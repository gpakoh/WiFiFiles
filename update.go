package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Update mechanism: the native InkView shell has no network access, so the
// embedded Go server performs the whole flow. The shell calls
// run_helper("--native-update-check") or run_helper("--native-update-install")
// and reads the result from /tmp/WiFiFiles/update_status.ini.
//
// Status values written to the file:
//
//	status=latest   — already on the newest release
//	status=found    — a newer release exists (check phase only)
//	status=updated  — the new app was installed
//	status=error    — something failed; message= holds the reason

const (
	updateGithubOwner    = "gpakoh"
	updateGithubRepo     = "WiFiFiles"
	updateEmbedMagic     = "WFSRV722"
	updateEmbedFooterLen = 16
	updateMinPayload     = 1024 * 1024
	updateMaxPayload     = 32 * 1024 * 1024
	updateMaxAppBytes    = 64 * 1024 * 1024
)

var (
	updateAPIBaseURL = "https://api.github.com"
	updateStatusVar  = "/tmp/WiFiFiles/update_status.ini"
	updateAppsDirVar = "/mnt/ext1/applications"
	updateHTTPClient = &http.Client{Timeout: 120 * time.Second}
)

type updateRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []updateAsset `json:"assets"`
}

type updateAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func nativeUpdateCheck(appDir string) {
	if err := updateCheck(appDir); err != nil {
		appendLog(unifiedLogPath, "update check failed: "+err.Error())
	}
}

func nativeUpdateInstall(appDir string) {
	if err := updateInstall(appDir); err != nil {
		appendLog(unifiedLogPath, "update install failed: "+err.Error())
	}
}

// updateCheck fetches the latest release and reports whether a newer version
// exists. It never downloads anything.
func updateCheck(appDir string) error {
	rel, err := fetchLatestRelease()
	if err != nil {
		writeUpdateStatus(appDir, "error", version, "", err.Error())
		return err
	}
	tag := versionFromTag(rel.TagName)
	latest := compareVersions(version, tag)
	if latest >= 0 {
		writeUpdateStatus(appDir, "latest", version, tag, "")
		return nil
	}
	writeUpdateStatus(appDir, "found", version, tag, "")
	return nil
}

// updateInstall verifies and installs the newest release when one exists.
func updateInstall(appDir string) error {
	rel, err := fetchLatestRelease()
	if err != nil {
		writeUpdateStatus(appDir, "error", version, "", err.Error())
		return err
	}
	tag := versionFromTag(rel.TagName)
	if compareVersions(version, tag) >= 0 {
		writeUpdateStatus(appDir, "latest", version, tag, "")
		return nil
	}
	target, err := resolveAppTarget()
	if err != nil {
		writeUpdateStatus(appDir, "error", version, tag, err.Error())
		return err
	}
	zipURL := findAssetURL(rel, "WiFiFiles_"+tag+".zip")
	if zipURL == "" {
		writeUpdateStatus(appDir, "error", version, tag, "В релизе не найден файл WiFiFiles_"+tag+".zip")
		return errors.New("zip asset not found")
	}
	zipPath := filepath.Join(appDir, "update.zip")
	if err := downloadToFile(zipURL, zipPath, updateMaxAppBytes); err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Ошибка загрузки: "+err.Error())
		return err
	}
	defer os.Remove(zipPath)
	if shaURL := findAssetURL(rel, "WiFiFiles_"+tag+".sha256"); shaURL != "" {
		shaPath := filepath.Join(appDir, "update.zip.sha256")
		if err := downloadToFile(shaURL, shaPath, 4096); err == nil {
			sum, err := sha256File(zipPath)
			if err == nil {
				data, _ := os.ReadFile(shaPath)
				expected, _ := parseSHA256(data)
				if expected != "" && !strings.EqualFold(expected, sum) {
					os.Remove(shaPath)
					writeUpdateStatus(appDir, "error", version, tag, "Контрольная сумма не совпадает")
					return errors.New("sha256 mismatch")
				}
			}
		}
		os.Remove(shaPath)
	}
	newApp := filepath.Join(appDir, "update.app")
	if err := extractAppFromZip(zipPath, newApp); err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Не удалось распаковать приложение: "+err.Error())
		return err
	}
	defer os.Remove(newApp)
	if err := verifyAppFile(newApp); err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Файл приложения повреждён: "+err.Error())
		return err
	}
	if err := installAppFile(newApp, target); err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Не удалось установить: "+err.Error())
		return err
	}
	writeUpdateStatus(appDir, "updated", version, tag, "")
	appendLog(unifiedLogPath, "updated to "+tag)
	return nil
}

func fetchLatestRelease() (updateRelease, error) {
	var rel updateRelease
	url := updateAPIBaseURL + "/repos/" + updateGithubOwner + "/" + updateGithubRepo + "/releases/latest"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("User-Agent", "WiFiFiles/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("github api: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return rel, err
	}
	return rel, nil
}

// versionFromTag strips a leading "v"/"V" from a git tag.
func versionFromTag(tag string) string {
	return strings.TrimLeft(tag, "vV")
}

// compareVersions returns 1 if a>b, 0 if equal, -1 if a<b. Numeric dotted
// segments are compared numerically; missing segments count as zero.
func compareVersions(a, b string) int {
	pa := strings.Split(versionFromTag(a), ".")
	pb := strings.Split(versionFromTag(b), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va, _ = strconv.Atoi(trimVersionSegment(pa[i]))
		}
		if i < len(pb) {
			vb, _ = strconv.Atoi(trimVersionSegment(pb[i]))
		}
		if va > vb {
			return 1
		}
		if va < vb {
			return -1
		}
	}
	return 0
}

func trimVersionSegment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

func findAssetURL(rel updateRelease, name string) string {
	for _, a := range rel.Assets {
		if a.Name == name && a.BrowserDownloadURL != "" {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

// downloadToFile streams url to path, aborting once maxBytes are reached.
func downloadToFile(url, path string, maxBytes int64) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "WiFiFiles/"+version)
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return errors.New("file too large")
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if n > maxBytes {
		return errors.New("file too large")
	}
	return nil
}

// parseSHA256 extracts the hex digest from a "hash  filename" checksum file.
func parseSHA256(data []byte) (string, error) {
	line := string(data)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		line = line[:i]
	}
	if len(line) != 64 {
		return "", errors.New("invalid sha256 line")
	}
	if _, err := hex.DecodeString(line); err != nil {
		return "", err
	}
	return line, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractAppFromZip writes the app/WiFiFiles.app entry of the release zip to dst.
func extractAppFromZip(zipPath, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	var entry *zip.File
	for _, f := range zr.File {
		if f.Name == "app/WiFiFiles.app" {
			entry = f
			break
		}
	}
	if entry == nil {
		return errors.New("app/WiFiFiles.app missing from archive")
	}
	rc, err := entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(rc, updateMaxAppBytes+1))
	if err != nil {
		return err
	}
	if n > updateMaxAppBytes {
		return errors.New("app too large")
	}
	return nil
}

// verifyAppFile checks ELF magic, the embedded-server footer (WFSRV722) and
// that the payload itself begins with an ELF header.
func verifyAppFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size < updateEmbedFooterLen+4 {
		return errors.New("file too small")
	}
	head := make([]byte, 4)
	if _, err := f.ReadAt(head, 0); err != nil {
		return err
	}
	if !isELFMagic(head) {
		return errors.New("not an ELF file")
	}
	footer := make([]byte, updateEmbedFooterLen)
	if _, err := f.ReadAt(footer, size-int64(updateEmbedFooterLen)); err != nil {
		return err
	}
	for i := 0; i < len(updateEmbedMagic); i++ {
		if footer[i] != updateEmbedMagic[i] {
			return errors.New("embedded server footer missing")
		}
	}
	payloadSize := binary.LittleEndian.Uint32(footer[8:12])
	payloadCheck := binary.LittleEndian.Uint32(footer[12:16])
	if payloadSize^0xA55AA55A != payloadCheck {
		return errors.New("embedded server footer corrupted")
	}
	if payloadSize < updateMinPayload || payloadSize > updateMaxPayload {
		return errors.New("embedded server size out of range")
	}
	payloadOff := size - int64(updateEmbedFooterLen) - int64(payloadSize)
	if payloadOff < 0 {
		return errors.New("embedded server offset invalid")
	}
	if _, err := f.ReadAt(head, payloadOff); err != nil {
		return err
	}
	if !isELFMagic(head) {
		return errors.New("embedded server is not an ELF file")
	}
	return nil
}

func isELFMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// resolveAppTarget locates the installed WiFiFiles.app. The server is normally
// launched by the native shell via run_helper, so the shell's path is available
// through /proc/<ppid>/exe. As a fallback the applications directory is scanned.
func resolveAppTarget() (string, error) {
	if path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getppid())); err == nil {
		if filepath.Base(path) == "WiFiFiles.app" && verifyAppFile(path) == nil {
			return path, nil
		}
	}
	entries, err := os.ReadDir(updateAppsDirVar)
	if err != nil {
		return "", errors.New("не найдено приложение WiFiFiles.app")
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() != "WiFiFiles.app" {
			continue
		}
		path := filepath.Join(updateAppsDirVar, e.Name())
		if verifyAppFile(path) == nil {
			return path, nil
		}
	}
	return "", errors.New("не найдено приложение WiFiFiles.app")
}

// installAppFile replaces target with the verified new app. The temporary file
// lives in the same directory so the final rename never crosses filesystems.
func installAppFile(newApp, target string) error {
	dir := filepath.Dir(target)
	tmp := filepath.Join(dir, ".WiFiFiles.app.new")
	src, err := os.Open(newApp)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := verifyAppFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(target, 0755)
}

func writeUpdateStatus(appDir, status, current, latest, message string) {
	lines := []string{
		"status=" + cleanINIValue(status),
		"current=" + cleanINIValue(current),
		"latest=" + cleanINIValue(latest),
		"message=" + cleanINIValue(message),
	}
	writeNativeINI(updateStatusVar, lines)
}

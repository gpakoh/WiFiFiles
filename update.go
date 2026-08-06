package main

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	updateHTTPClient = &http.Client{Timeout: 120 * time.Second, Transport: updateHTTPTransport()}
)

// updateRootsPEM bundles the root certificate that signs GitHub release-asset
// downloads (release-assets.githubusercontent.com, Let's Encrypt ISRG Root X1).
// The reader's system CA store predates this root, so the updater appends it
// to the system pool instead of relying on the store alone.
const updateRootsPEM = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`

// updateHTTPTransport returns the transport used by the updater: the system
// certificate pool extended with updateRootsPEM, so downloads succeed even on
// readers whose CA store is too old to trust GitHub's certificate chains.
func updateHTTPTransport() *http.Transport {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM([]byte(updateRootsPEM)); !ok {
		appendLog(unifiedLogPath, "update: failed to append bundled root certificate")
	}
	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
}

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
	shaURL := findAssetURL(rel, "WiFiFiles_"+tag+".sha256")
	if shaURL == "" {
		writeUpdateStatus(appDir, "error", version, tag, "В релизе не найден файл контрольной суммы")
		return errors.New("sha256 asset not found")
	}
	shaPath := filepath.Join(appDir, "update.zip.sha256")
	defer os.Remove(shaPath)
	if err := downloadToFile(shaURL, shaPath, 4096); err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Ошибка загрузки контрольной суммы: "+err.Error())
		return err
	}
	data, err := os.ReadFile(shaPath)
	if err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Не удалось прочитать контрольную сумму: "+err.Error())
		return err
	}
	expected, err := parseSHA256(data)
	if err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Неверный формат контрольной суммы")
		return err
	}
	sum, err := sha256File(zipPath)
	if err != nil {
		writeUpdateStatus(appDir, "error", version, tag, "Не удалось вычислить контрольную сумму: "+err.Error())
		return err
	}
	if !strings.EqualFold(expected, sum) {
		writeUpdateStatus(appDir, "error", version, tag, "Контрольная сумма не совпадает")
		return errors.New("sha256 mismatch")
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

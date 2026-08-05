package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPayloadLen = 1024*1024 + 32

func fakeAppBytes(t *testing.T, withELF bool) []byte {
	t.Helper()
	payload := make([]byte, testPayloadLen)
	copy(payload, "\x7fELF")
	if !withELF {
		copy(payload, "NOPE")
	}
	footer := make([]byte, updateEmbedFooterLen)
	copy(footer, updateEmbedMagic)
	binary.LittleEndian.PutUint32(footer[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(footer[12:16], uint32(len(payload))^0xA55AA55A)
	out := make([]byte, 0, 4+len(payload)+len(footer))
	out = append(out, 0x7f, 'E', 'L', 'F')
	out = append(out, payload...)
	out = append(out, footer...)
	return out
}

func writeFakeApp(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, fakeAppBytes(t, true), 0755); err != nil {
		t.Fatal(err)
	}
}

func makeReleaseZip(t *testing.T, appBytes []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("app/WiFiFiles.app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(appBytes); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func saveGlobals(t *testing.T) {
	t.Helper()
	api, status, apps := updateAPIBaseURL, updateStatusVar, updateAppsDirVar
	t.Cleanup(func() {
		updateAPIBaseURL, updateStatusVar, updateAppsDirVar = api, status, apps
	})
	updateStatusVar = filepath.Join(t.TempDir(), "update_status.ini")
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.7.25", "0.7.26", -1},
		{"0.7.26", "0.7.25", 1},
		{"0.7.25", "0.7.25", 0},
		{"v0.7.26", "0.7.26", 0},
		{"0.10.0", "0.9.9", 1},
		{"0.7.25", "0.7", 1},
		{"0.7", "0.7.25", -1},
		{"0.7.25", "0.7.25a", 0},
		{"1.0", "0.99.99", 1},
		{"", "", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionFromTag(t *testing.T) {
	for in, want := range map[string]string{"v0.7.26": "0.7.26", "V1.2.3": "1.2.3", "0.7.25": "0.7.25", "v0.7.25-beta": "0.7.25-beta"} {
		if got := versionFromTag(in); got != want {
			t.Errorf("versionFromTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSHA256(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	if got, err := parseSHA256([]byte(sum + "  WiFiFiles_0.7.26.zip\n")); err != nil || got != sum {
		t.Errorf("got %q err %v", got, err)
	}
	if got, err := parseSHA256([]byte(sum)); err != nil || got != sum {
		t.Errorf("plain: got %q err %v", got, err)
	}
	if _, err := parseSHA256([]byte("abcd")); err == nil {
		t.Error("short line should fail")
	}
	if _, err := parseSHA256([]byte(strings.Repeat("zz", 32))); err == nil {
		t.Error("non-hex should fail")
	}
}

func TestVerifyAppFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.app")
	writeFakeApp(t, good)
	if err := verifyAppFile(good); err != nil {
		t.Fatalf("valid app rejected: %v", err)
	}

	bad := filepath.Join(dir, "bad.app")
	if err := os.WriteFile(bad, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppFile(bad); err == nil {
		t.Error("non-ELF accepted")
	}

	noFooter := filepath.Join(dir, "nofooter.app")
	if err := os.WriteFile(noFooter, append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 64)...), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppFile(noFooter); err == nil {
		t.Error("missing footer accepted")
	}

	badPayload := fakeAppBytes(t, false)
	badPayloadPath := filepath.Join(dir, "badpayload.app")
	if err := os.WriteFile(badPayloadPath, badPayload, 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppFile(badPayloadPath); err == nil {
		t.Error("non-ELF payload accepted")
	}

	if err := verifyAppFile(filepath.Join(dir, "missing.app")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestVerifyAppFileCorruptFooter(t *testing.T) {
	dir := t.TempDir()
	app := fakeAppBytes(t, true)
	corrupt := append([]byte(nil), app...)
	// Corrupt the payload-size XOR check inside the footer.
	corrupt[len(corrupt)-1] ^= 0xFF
	p := filepath.Join(dir, "corrupt.app")
	if err := os.WriteFile(p, corrupt, 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppFile(p); err == nil {
		t.Error("corrupt footer accepted")
	}
}

func TestFindAssetURL(t *testing.T) {
	rel := updateRelease{Assets: []updateAsset{
		{Name: "WiFiFiles_0.7.26.zip", BrowserDownloadURL: "https://x/zip"},
		{Name: "WiFiFiles_0.7.26.sha256", BrowserDownloadURL: "https://x/sha"},
	}}
	if got := findAssetURL(rel, "WiFiFiles_0.7.26.zip"); got != "https://x/zip" {
		t.Errorf("got %q", got)
	}
	if got := findAssetURL(rel, "missing"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestFetchLatestRelease(t *testing.T) {
	saveGlobals(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/gpakoh/WiFiFiles/releases/latest" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing User-Agent")
		}
		fmt.Fprint(w, `{"tag_name":"v0.7.26","assets":[{"name":"WiFiFiles_0.7.26.zip","browser_download_url":"https://x/zip"}]}`)
	}))
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	rel, err := fetchLatestRelease()
	if err != nil {
		t.Fatal(err)
	}
	if rel.TagName != "v0.7.26" || len(rel.Assets) != 1 {
		t.Errorf("unexpected release: %+v", rel)
	}
}

func TestFetchLatestReleaseErrors(t *testing.T) {
	saveGlobals(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	if _, err := fetchLatestRelease(); err == nil {
		t.Error("500 should fail")
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer srv2.Close()
	updateAPIBaseURL = srv2.URL
	if _, err := fetchLatestRelease(); err == nil {
		t.Error("bad json should fail")
	}
}

func TestDownloadToFile(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("download-body")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write(payload)
		case "/err":
			w.WriteHeader(http.StatusNotFound)
		case "/huge":
			fmt.Fprint(w, strings.Repeat("x", 100))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dst := filepath.Join(dir, "out.bin")
	if err := downloadToFile(srv.URL+"/ok", dst, 100); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, payload) {
		t.Error("payload mismatch")
	}
	if err := downloadToFile(srv.URL+"/err", dst, 100); err == nil {
		t.Error("404 should fail")
	}
	if err := downloadToFile(srv.URL+"/huge", dst, 10); err == nil {
		t.Error("oversize should fail")
	}
}

func TestExtractAppFromZip(t *testing.T) {
	dir := t.TempDir()
	app := fakeAppBytes(t, true)
	zipPath := filepath.Join(dir, "rel.zip")
	if err := os.WriteFile(zipPath, makeReleaseZip(t, app), 0644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.app")
	if err := extractAppFromZip(zipPath, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, app) {
		t.Error("extracted app mismatch")
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	wf, _ := zw.Create("other.txt")
	wf.Write([]byte("x"))
	zw.Close()
	other := filepath.Join(dir, "other.zip")
	os.WriteFile(other, buf.Bytes(), 0644)
	if err := extractAppFromZip(other, dst); err == nil {
		t.Error("missing entry should fail")
	}
	corrupt := filepath.Join(dir, "corrupt.zip")
	os.WriteFile(corrupt, []byte("not a zip"), 0644)
	if err := extractAppFromZip(corrupt, dst); err == nil {
		t.Error("corrupt zip should fail")
	}
}

func TestResolveAppTarget(t *testing.T) {
	saveGlobals(t)
	apps := t.TempDir()
	updateAppsDirVar = apps
	if _, err := resolveAppTarget(); err == nil {
		t.Error("empty dir should fail")
	}
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))
	got, err := resolveAppTarget()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(apps, "WiFiFiles.app") {
		t.Errorf("got %q", got)
	}
	os.WriteFile(filepath.Join(apps, "WiFiFiles.app"), []byte("junk"), 0644)
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))
	if _, err := resolveAppTarget(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallAppFile(t *testing.T) {
	dir := t.TempDir()
	newApp := filepath.Join(dir, "new.app")
	target := filepath.Join(dir, "WiFiFiles.app")
	writeFakeApp(t, newApp)
	if err := installAppFile(newApp, target); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppFile(target); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm()&0111 == 0 {
		t.Error("target not executable")
	}
	os.Remove(newApp)
	if err := installAppFile(newApp, target); err == nil {
		t.Error("missing source should fail")
	}
	if err := installAppFile(newApp, filepath.Join(dir, "no", "such", "dir.app")); err == nil {
		t.Error("missing target dir should fail")
	}
}

func TestUpdateCheck(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/gpakoh/WiFiFiles/releases/latest" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"tag_name":"v9.9.9","assets":[]}`)
	}))
	defer srv.Close()
	updateAPIBaseURL = srv.URL

	if err := updateCheck(appDir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=found") || !strings.Contains(string(data), "latest=9.9.9") {
		t.Errorf("found state wrong: %s", data)
	}

	updateAPIBaseURL = srv.URL + "/nonexistent"
	if err := updateCheck(appDir); err == nil {
		t.Error("network error should fail")
	}
	data, _ = os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=error") {
		t.Errorf("error state wrong: %s", data)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.0.1","assets":[]}`)
	}))
	defer srv2.Close()
	updateAPIBaseURL = srv2.URL
	if err := updateCheck(appDir); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=latest") {
		t.Errorf("latest state wrong: %s", data)
	}
}

func setupUpdateServer(t *testing.T, zipBytes []byte, sha string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/gpakoh/WiFiFiles/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[{"name":"WiFiFiles_9.9.9.zip","browser_download_url":%q},{"name":"WiFiFiles_9.9.9.sha256","browser_download_url":%q}]}`,
				srv.URL+"/WiFiFiles_9.9.9.zip", srv.URL+"/WiFiFiles_9.9.9.sha256")
		case "/WiFiFiles_9.9.9.zip":
			w.Write(zipBytes)
		case "/WiFiFiles_9.9.9.sha256":
			if sha != "" {
				fmt.Fprint(w, sha)
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestUpdateInstall(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	apps := t.TempDir()
	updateAppsDirVar = apps
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))

	app := fakeAppBytes(t, true)
	zipBytes := makeReleaseZip(t, app)
	h := sha256.Sum256(zipBytes)
	sha := hex.EncodeToString(h[:]) + "  WiFiFiles_9.9.9.zip\n"
	srv := setupUpdateServer(t, zipBytes, sha)
	defer srv.Close()
	updateAPIBaseURL = srv.URL

	if err := updateInstall(appDir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=updated") {
		t.Errorf("updated state wrong: %s", data)
	}
	if err := verifyAppFile(filepath.Join(apps, "WiFiFiles.app")); err != nil {
		t.Fatal("target not replaced with valid app")
	}
}

func TestUpdateInstallShaMismatch(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	apps := t.TempDir()
	updateAppsDirVar = apps
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))

	zipBytes := makeReleaseZip(t, fakeAppBytes(t, true))
	sha := strings.Repeat("00", 32) + "  WiFiFiles_9.9.9.zip\n"
	srv := setupUpdateServer(t, zipBytes, sha)
	defer srv.Close()
	updateAPIBaseURL = srv.URL

	if err := updateInstall(appDir); err == nil {
		t.Fatal("sha mismatch should fail")
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=error") {
		t.Errorf("error state wrong: %s", data)
	}
}

func TestUpdateInstallVariants(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	apps := t.TempDir()
	updateAppsDirVar = apps
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))

	// Already latest.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.0.1","assets":[]}`)
	}))
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	if err := updateInstall(appDir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=latest") {
		t.Errorf("latest state wrong: %s", data)
	}

	// Newer but zip asset missing.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v9.9.9","assets":[]}`)
	}))
	defer srv2.Close()
	updateAPIBaseURL = srv2.URL
	if err := updateInstall(appDir); err == nil {
		t.Fatal("missing asset should fail")
	}
	data, _ = os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=error") {
		t.Errorf("error state wrong: %s", data)
	}

	// Corrupt zip download.
	updateAPIBaseURL = "http://127.0.0.1:1"
	if err := updateInstall(appDir); err == nil {
		t.Fatal("download failure should fail")
	}
}

func TestUpdateInstallCorruptZip(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	apps := t.TempDir()
	updateAppsDirVar = apps
	writeFakeApp(t, filepath.Join(apps, "WiFiFiles.app"))
	zipBytes := []byte("definitely not a zip")
	srv := setupUpdateServer(t, zipBytes, "")
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	if err := updateInstall(appDir); err == nil {
		t.Fatal("corrupt zip should fail")
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=error") {
		t.Errorf("error state wrong: %s", data)
	}
}

func TestUpdateInstallNoTarget(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	updateAppsDirVar = filepath.Join(t.TempDir(), "missing")
	zipBytes := makeReleaseZip(t, fakeAppBytes(t, true))
	srv := setupUpdateServer(t, zipBytes, "")
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	if err := updateInstall(appDir); err == nil {
		t.Fatal("missing target should fail")
	}
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=error") {
		t.Errorf("error state wrong: %s", data)
	}
}

func TestNativeUpdateWrappers(t *testing.T) {
	saveGlobals(t)
	appDir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.0.1","assets":[]}`)
	}))
	defer srv.Close()
	updateAPIBaseURL = srv.URL
	nativeUpdateCheck(appDir)
	nativeUpdateInstall(appDir)
	data, _ := os.ReadFile(updateStatusVar)
	if !strings.Contains(string(data), "status=latest") {
		t.Errorf("wrapper state wrong: %s", data)
	}
}

// updateTestISRGYR is the Let's Encrypt intermediate that signs *.github.io
// (release-assets.githubusercontent.com). It is issued directly by the
// embedded ISRG Root X1, so verifying it proves the bundled root is usable.
const updateTestISRGYR = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

func TestUpdateRootsPEM(t *testing.T) {
	block, _ := pem.Decode([]byte(updateRootsPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("updateRootsPEM: not a PEM certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("updateRootsPEM: %v", err)
	}
	if root.Subject.CommonName != "ISRG Root X1" {
		t.Errorf("unexpected root subject: %s", root.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(updateRootsPEM)) {
		t.Fatal("updateRootsPEM: failed to add to pool")
	}
	block, _ = pem.Decode([]byte(updateTestISRGYR))
	yr, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("test intermediate: %v", err)
	}
	if _, err := yr.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("bundled root does not verify the Let's Encrypt chain: %v", err)
	}
}

func TestUpdateHTTPTransport(t *testing.T) {
	tr := updateHTTPTransport()
	if tr == nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("updateHTTPTransport: missing TLS client config")
	}
	subjects := tr.TLSClientConfig.RootCAs.Subjects()
	if len(subjects) == 0 {
		t.Fatal("updateHTTPTransport: root pool is empty")
	}
	block, _ := pem.Decode([]byte(updateRootsPEM))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range subjects {
		if string(s) == string(root.RawSubject) {
			found = true
			break
		}
	}
	if !found {
		t.Error("updateHTTPTransport: bundled root missing from transport pool")
	}
}

func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	want := sha256.Sum256([]byte("hello update"))
	if err := os.WriteFile(p, []byte("hello update"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := sha256File(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("sha256File = %s, want %s", got, hex.EncodeToString(want[:]))
	}

	if _, err := sha256File(filepath.Join(dir, "missing.bin")); err == nil {
		t.Error("sha256File on missing file should fail")
	}
}

func TestDownloadToFileContentLength(t *testing.T) {
	payload := []byte("x")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.Write(payload)
	}))
	defer srv.Close()
	if err := downloadToFile(srv.URL, filepath.Join(t.TempDir(), "d"), 100); err == nil {
		t.Error("ContentLength larger than body should fail")
	}
}

func TestDownloadToFileOpenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "no", "such", "dir", "d")
	if err := downloadToFile(srv.URL, dst, 100); err == nil {
		t.Error("unwritable destination should fail")
	}
}



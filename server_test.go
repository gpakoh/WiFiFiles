package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	smbntlm "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	smbvfs "github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func utf16leTest(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		v := uint16(r)
		out = append(out, byte(v), byte(v>>8))
	}
	return out
}

func putSecBuf(dst []byte, off int, payload []byte, payloadOff uint32) {
	binary.LittleEndian.PutUint16(dst[off:off+2], uint16(len(payload)))
	binary.LittleEndian.PutUint16(dst[off+2:off+4], uint16(len(payload)))
	binary.LittleEndian.PutUint32(dst[off+4:off+8], payloadOff)
}

func buildNTLMAuthenticate(user, domain, password string, challenge [8]byte, targetInfo []byte) []byte {
	responseKey := smbntlm.NTOWFv2(password, user, domain)
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = append(blob, make([]byte, 8)...) // timestamp
	blob = append(blob, []byte{1, 2, 3, 4, 5, 6, 7, 8}...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0)
	mac := hmac.New(md5.New, responseKey)
	mac.Write(challenge[:])
	mac.Write(blob)
	ntResp := append(mac.Sum(nil), blob...)

	lmResp := make([]byte, 24)
	domainBytes := utf16leTest(domain)
	userBytes := utf16leTest(user)
	workstation := utf16leTest("TESTPC")
	payloadOff := uint32(88)
	msg := make([]byte, 88+len(lmResp)+len(ntResp)+len(domainBytes)+len(userBytes)+len(workstation))
	copy(msg[:8], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	binary.LittleEndian.PutUint32(msg[8:12], smbntlm.MsgAuthenticate)
	cursor := payloadOff
	putSecBuf(msg, 12, lmResp, cursor)
	copy(msg[cursor:], lmResp)
	cursor += uint32(len(lmResp))
	putSecBuf(msg, 20, ntResp, cursor)
	copy(msg[cursor:], ntResp)
	cursor += uint32(len(ntResp))
	putSecBuf(msg, 28, domainBytes, cursor)
	copy(msg[cursor:], domainBytes)
	cursor += uint32(len(domainBytes))
	putSecBuf(msg, 36, userBytes, cursor)
	copy(msg[cursor:], userBytes)
	cursor += uint32(len(userBytes))
	putSecBuf(msg, 44, workstation, cursor)
	copy(msg[cursor:], workstation)
	putSecBuf(msg, 52, nil, 0)
	flags := smbntlm.FlagNegotiateUnicode | smbntlm.FlagNegotiateNTLM | smbntlm.FlagNegotiateAlwaysSign | smbntlm.FlagNegotiateExtSecurity | smbntlm.FlagNegotiate128
	binary.LittleEndian.PutUint32(msg[60:64], flags)
	return msg
}

func TestNTHashKnownVector(t *testing.T) {
	got := hex.EncodeToString(smbntlm.NTHash("password"))
	const want = "8846f7eaee8fb117ad06bdd830b7586c"
	if got != want {
		t.Fatalf("NT hash = %s, want %s", got, want)
	}
}

func TestNTLMv2Authenticator(t *testing.T) {
	const user, domain, password = "pocketbook", "WORKGROUP", "650wifi"
	lookup := smbCredentialLookup{username: user, ntHash: smbntlm.NTHash(password)}
	authenticator := smbntlm.NewServer(lookup, "POCKETBOOK")()

	negotiate := make([]byte, 32)
	copy(negotiate[:8], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	binary.LittleEndian.PutUint32(negotiate[8:12], smbntlm.MsgNegotiate)
	binary.LittleEndian.PutUint32(negotiate[12:16], smbntlm.FlagNegotiateUnicode|smbntlm.FlagNegotiateNTLM|smbntlm.FlagNegotiateExtSecurity)
	first, err := authenticator.Accept(context.Background(), negotiate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := smbntlm.UnwrapSPNEGOToken(first.OutputToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 56 {
		t.Fatalf("short challenge: %d", len(raw))
	}
	var challenge [8]byte
	copy(challenge[:], raw[24:32])
	tiLen := int(binary.LittleEndian.Uint16(raw[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(raw[44:48]))
	targetInfo := append([]byte(nil), raw[tiOff:tiOff+tiLen]...)

	authMsg := buildNTLMAuthenticate(user, domain, password, challenge, targetInfo)
	result, err := authenticator.Accept(context.Background(), authMsg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Identity == nil || result.Identity.Username != user || result.Identity.Domain != domain {
		t.Fatalf("bad identity: %#v", result.Identity)
	}
	if len(result.SessionKey) != 16 {
		t.Fatalf("session key length = %d", len(result.SessionKey))
	}
}

func TestSafeSMBBackendHidesApplicationData(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Books", "applications", "system"} {
		if err := os.Mkdir(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "Books", "book.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "WiFiFiles.log"), []byte("secret diagnostics"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "WiFiFiles_preparation.log"), []byte("installer diagnostics"), 0644); err != nil {
		t.Fatal(err)
	}
	backend, err := newSafeSMBBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := backend.Open(context.Background(), smbvfs.OpenOptions{Path: "", Disposition: smbvfs.DispositionOpen})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	var names []string
	for info, enumErr := range h.Enumerate(context.Background(), "*") {
		if enumErr != nil {
			t.Fatal(enumErr)
		}
		names = append(names, info.Name)
	}
	for _, hidden := range []string{"applications", "system", "WiFiFiles.log", "WiFiFiles_preparation.log"} {
		for _, got := range names {
			if got == hidden {
				t.Fatalf("hidden folder %q was enumerated", hidden)
			}
		}
	}
	_, err = backend.Open(context.Background(), smbvfs.OpenOptions{Path: "applications/config.json", Disposition: smbvfs.DispositionOpen})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("protected open error = %v", err)
	}
	_, err = backend.Open(context.Background(), smbvfs.OpenOptions{Path: "WiFiFiles.log", Disposition: smbvfs.DispositionOpen})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("log open error = %v", err)
	}
	_, err = backend.Open(context.Background(), smbvfs.OpenOptions{Path: "WiFiFiles_preparation.log", Disposition: smbvfs.DispositionOpen})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("preparation log open error = %v", err)
	}
}

var _ auth.Authenticator

func TestSMBPortDefaultsTo4445(t *testing.T) {
	cfg := Config{}
	if got := smbListenPort(cfg); got != 4445 {
		t.Fatalf("smbListenPort() = %d, want 4445", got)
	}
	cfg.SMBPort = 5555
	if got := smbListenPort(cfg); got != 5555 {
		t.Fatalf("configured smbListenPort() = %d, want 5555", got)
	}
}

func TestNewConfigUsesDefaultCredentialsAndLanguageSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	a, err := newApp(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.configSnapshot()
	if cfg.SMBPort != 4445 {
		t.Fatalf("SMBPort = %d, want 4445", cfg.SMBPort)
	}
	if cfg.Language != "" {
		t.Fatalf("Language = %q, want empty first-launch selection", cfg.Language)
	}
	if !a.checkCredentials("pocketbook", "650wifi") {
		t.Fatal("default credentials do not authenticate")
	}
}

func TestNormalizeLanguage(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ru", "ru"}, {"EN", "en"}, {" fr ", "fr"}, {"de", "de"}, {"es", ""},
	} {
		if got := normalizeLanguage(tc.in); got != tc.want {
			t.Fatalf("normalizeLanguage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUploadDestinationCanChangeWithoutChangingCurrentFolder(t *testing.T) {
	root := t.TempDir()
	books := filepath.Join(root, "Books")
	other := filepath.Join(root, "Other")
	if err := os.MkdirAll(books, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(other, 0755); err != nil {
		t.Fatal(err)
	}
	app := &App{
		roots: map[string]string{"internal": root, "sd": filepath.Join(root, "missing-sd")},
		cfg:   Config{InternalEnabled: true},
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("target", "internal/Other"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("files", "book.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("book-data")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload?k="+encodeVirtualPath("internal/Books"), &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(other, "book.fb2"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "book-data" {
		t.Fatalf("uploaded content=%q", got)
	}
	if _, err := os.Stat(filepath.Join(books, "book.fb2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file unexpectedly uploaded to current folder: %v", err)
	}
}

func TestUploadDestinationsHideProtectedFoldersAndSelectCurrent(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Books", "Books/SciFi", "system", "applications", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(name)), 0755); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{
		roots: map[string]string{"internal": root, "sd": filepath.Join(root, "missing-sd")},
		cfg:   Config{InternalEnabled: true},
	}
	dests := app.uploadDestinations("internal/Books/SciFi")
	var selected bool
	for _, d := range dests {
		if d.Selected && d.Path == "internal/Books/SciFi" {
			selected = true
		}
		for _, forbidden := range []string{"internal/system", "internal/applications", "internal/.hidden"} {
			if d.Path == forbidden || strings.HasPrefix(d.Path, forbidden+"/") {
				t.Fatalf("protected destination exposed: %s", d.Path)
			}
		}
	}
	if !selected {
		t.Fatal("current folder was not selected")
	}
}

func TestUploadDoesNotOverwriteWithoutExplicitChoice(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "book.fb2"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	app := &App{
		roots: map[string]string{"internal": root, "sd": filepath.Join(root, "missing-sd")},
		cfg:   Config{InternalEnabled: true},
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("target", "internal")
	part, err := mw.CreateFormFile("files", "book.fb2")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("new"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(root, "book.fb2"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("file was overwritten: %q", got)
	}
}

func TestWebIndexTemplateRendersDestinationPicker(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	app, err := newApp(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Books", "SciFi"), 0755); err != nil {
		t.Fatal(err)
	}
	app.roots["internal"] = root
	app.roots["sd"] = filepath.Join(root, "missing-sd")
	app.cfgMu.Lock()
	app.cfg.InternalEnabled = true
	app.cfg.SDEnabled = false
	app.cfgMu.Unlock()
	rr := httptest.NewRecorder()
	app.renderIndex(rr, "internal/Books", "", "")
	body := rr.Body.String()
	for _, want := range []string{"name=\"target\"", "internal storage / Books / SciFi", "Заменять файлы", "upload-files"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page does not contain %q", want)
		}
	}
}

func TestBookFileAndLibraryScanTarget(t *testing.T) {
	cases := []struct {
		path   string
		want   string
		accept bool
	}{
		{"/mnt/ext1/Books/Novel.EPUB", "/mnt/ext1/Books", true},
		{"/mnt/ext1/Books/archive.fb2.zip", "/mnt/ext1/Books", true},
		{"/mnt/ext2/Library/manual.pdf", "/mnt/ext2/Library", true},
		{"/mnt/ext1/system/config/book.epub", "", false},
		{"/mnt/ext1/applications/book.fb2", "", false},
		{"/tmp/book.epub", "", false},
		{"/mnt/ext1/Books/cover.jpg", "", false},
	}
	for _, tc := range cases {
		got, ok := libraryScanTarget(tc.path)
		if ok != tc.accept || got != tc.want {
			t.Errorf("libraryScanTarget(%q) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.accept)
		}
	}
}

func TestCollapseLibraryTargets(t *testing.T) {
	got := collapseLibraryTargets([]string{
		"/mnt/ext1/Books/Fiction",
		"/mnt/ext2/Books",
		"/mnt/ext1/Books",
		"/mnt/ext1/Books/Fiction/Classics",
	})
	want := []string{"/mnt/ext1/Books", "/mnt/ext2/Books"}
	if len(got) != len(want) {
		t.Fatalf("collapseLibraryTargets() = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collapseLibraryTargets() = %#v; want %#v", got, want)
		}
	}
}

func TestDefaultPasswordIsRecognized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	app, err := newApp(path)
	if err != nil {
		t.Fatal(err)
	}
	if !usesDefaultPassword(app.configSnapshot()) {
		t.Fatal("new configuration must require changing the factory password")
	}
}

func TestUploadLeavesNoPartFiles(t *testing.T) {
	root := t.TempDir()
	hdrBody := &bytes.Buffer{}
	mw := multipart.NewWriter(hdrBody)
	part, err := mw.CreateFormFile("files", "atomic.epub")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("complete-book"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", hdrBody)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	hdr := req.MultipartForm.File["files"][0]
	if err := saveUpload(root, hdr, false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "atomic.epub" {
		t.Fatalf("unexpected files after atomic upload: %#v", entries)
	}
}

func TestSystemStoragePathsAreProtectedAndHidden(t *testing.T) {
	protected := []string{
		"internal/system/config",
		"internal/System Volume Information/indexer.db",
		"internal/.adobe-digital-editions/activation.xml",
		"internal/.adobe-hidden-files/item",
		"sd/LOST.DIR/123",
		"sd/System Volume Information/WPSettings.dat",
		"sd/.adobe-digital-editions/device.xml",
	}
	for _, value := range protected {
		if !isProtectedVirtual(value) {
			t.Errorf("isProtectedVirtual(%q) = false", value)
		}
	}
	visible := []string{
		"internal/Books/System Volume Information/book.epub",
		"sd/Books/LOST.DIR/book.epub",
	}
	for _, value := range visible {
		if isProtectedVirtual(value) {
			t.Errorf("nested user path unexpectedly protected: %q", value)
		}
	}
	for _, tc := range []struct{ parent, name string }{
		{"internal", "System Volume Information"},
		{"internal", ".adobe-digital-editions"},
		{"sd", "LOST.DIR"},
		{"sd", ".adobe-hidden-files"},
	} {
		if !isHiddenSystemPath(tc.parent, tc.name) {
			t.Errorf("isHiddenSystemPath(%q, %q) = false", tc.parent, tc.name)
		}
	}
	if isHiddenSystemPath("internal/Books", "System Volume Information") {
		t.Fatal("nested user folder must remain visible")
	}
}

func TestSettingsClearDefaultTarget(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	app, err := newApp(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	app.cfgMu.Lock()
	app.cfg.DefaultTarget = "internal/Books"
	app.cfgMu.Unlock()
	if err := app.saveConfig(); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	app.handleSettings(rr, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if !strings.Contains(rr.Body.String(), "internal/Books") {
		t.Fatalf("settings page does not show default target:\n%s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("action=clear_default_target"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.handleSettings(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("clear default target status=%d body=%s", rr.Code, rr.Body.String())
	}
	app2, err := newApp(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if app2.cfg.DefaultTarget != "" {
		t.Fatalf("default target not cleared: %q", app2.cfg.DefaultTarget)
	}
}

func TestLoadOrCreateConfigVariants(t *testing.T) {
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "missing.json")
	app, err := newApp(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(cfgPath)
	if err := app.loadOrCreateConfig(); err != nil {
		t.Fatalf("fresh config: %v", err)
	}
	app.cfgMu.RLock()
	if app.cfg.InternalEnabled != true || app.cfg.Username == "" || app.cfg.HTTPPort != 8080 {
		t.Fatalf("defaults wrong: %+v", app.cfg)
	}
	app.cfgMu.RUnlock()

	v1 := Config{
		ConfigVersion: 1,
		Username:      "pocketbook",
		PasswordHash:  "hash",
		Port:          99,
		InternalEnabled: true,
		SDEnabled:     true,
	}
	data, _ := json.Marshal(v1)
	cfgPath2 := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(cfgPath2, data, 0600); err != nil {
		t.Fatal(err)
	}
	app2, err := newApp(cfgPath2)
	if err != nil {
		t.Fatal(err)
	}
	if err := app2.loadOrCreateConfig(); err != nil {
		t.Fatalf("v1 migration: %v", err)
	}
	app2.cfgMu.RLock()
	if app2.cfg.ConfigVersion != 7 || app2.cfg.HTTPPort != 8080 || !app2.cfg.HTTPEnabled {
		t.Fatalf("v1 migration wrong: %+v", app2.cfg)
	}
	app2.cfgMu.RUnlock()

	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("{{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	app3, err := newApp(garbage)
	if err != nil {
		t.Fatal(err)
	}
	if err := app3.loadOrCreateConfig(); err != nil {
		t.Fatalf("garbage config: %v", err)
	}
}

func TestReadLivePIDVariants(t *testing.T) {
	dir := t.TempDir()

	if pid, ok := readLivePID(dir); ok {
		t.Fatalf("missing pid file: pid=%d", pid)
	}

	pidFile := filepath.Join(dir, "wififiles.pid")
	if err := os.WriteFile(pidFile, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readLivePID(dir); ok {
		t.Fatal("pid 0 accepted")
	}
	if _, err := os.Stat(pidFile); err == nil {
		t.Fatal("stale pid file not removed")
	}

	if err := os.WriteFile(pidFile, []byte("not-a-pid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readLivePID(dir); ok {
		t.Fatal("garbage pid accepted")
	}

	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	pid, ok := readLivePID(dir)
	if !ok || pid != os.Getpid() {
		t.Fatalf("live pid = %d/%v", pid, ok)
	}
}

func TestWriteManagerStatusVariants(t *testing.T) {
	app := newTestWebApp(t)
	sm := &ServiceManager{app: app}
	for _, cfg := range []Config{
		{Username: "pb", HTTPEnabled: true, HTTPPort: 8080, FTPEnabled: true, FTPPort: 2121, SMBEnabled: true, InternalEnabled: true, SDEnabled: true},
		{Username: "pb", SMBEnabled: true, InternalEnabled: false, SDEnabled: true},
		{Username: "pb", HTTPEnabled: true, HTTPPort: 9999},
		{Username: "pb"},
	} {
		app.cfg = cfg
		writeManagerStatus(sm)
	}
}

func TestStopHTTPLockedWithLiveServer(t *testing.T) {
	app := newTestWebApp(t)
	sm := &ServiceManager{app: app}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go func() { _ = srv.Serve(ln) }()
	sm.httpSrv = srv
	sm.httpLn = ln
	sm.httpPort = 8080

	backup, berr := os.ReadFile(mobileTokenPath)
	t.Cleanup(func() {
		if berr == nil {
			_ = os.WriteFile(mobileTokenPath, backup, 0600)
		} else {
			_ = os.Remove(mobileTokenPath)
		}
	})
	_ = os.WriteFile(mobileTokenPath, []byte("[]"), 0600)

	sm.stopHTTPLocked()
	if sm.httpSrv != nil || sm.httpLn != nil || sm.httpPort != 0 {
		t.Fatalf("http not cleared: %+v", sm)
	}
	if _, err := os.Stat(mobileTokenPath); !os.IsNotExist(err) {
		t.Fatal("mobile token path not removed")
	}
}

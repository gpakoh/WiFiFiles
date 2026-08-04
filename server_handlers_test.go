package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBool01AndParseNativeBool(t *testing.T) {
	if bool01(true) != 1 || bool01(false) != 0 {
		t.Fatal("bool01 broken")
	}
	for _, v := range []string{"1", "true", "on", "TRUE", "On"} {
		if !parseNativeBool(v) {
			t.Errorf("parseNativeBool(%q) = false", v)
		}
	}
	for _, v := range []string{"0", "false", "off", "yes", ""} {
		if parseNativeBool(v) {
			t.Errorf("parseNativeBool(%q) = true", v)
		}
	}
}

func TestParseNativeApply(t *testing.T) {
	vals := parseNativeApply([]byte("username=pocketbook\r\nhttp_port=8080\r\n\r\nempty=\n"))
	if vals["username"] != "pocketbook" || vals["http_port"] != "8080" || vals["empty"] != "" {
		t.Fatalf("parseNativeApply = %#v", vals)
	}
	if len(vals) != 3 {
		t.Fatalf("parseNativeApply size = %d", len(vals))
	}
}

func TestWriteNativeINI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.ini")
	writeNativeINI(path, []string{"a=1", "b=2"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "a=1\nb=2\n" {
		t.Fatalf("writeNativeINI content = %q", data)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0666 {
		t.Fatalf("writeNativeINI mode = %v err=%v", st.Mode().Perm(), err)
	}
}

func TestProcessAliveAndIsWiFiFiles(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("processAlive(self) = false")
	}
	if processAlive(99999999) {
		t.Fatal("processAlive(fake) = true")
	}
	if processIsWiFiFiles(99999999) {
		t.Fatal("processIsWiFiFiles(fake) = true")
	}
}

func TestConfiguredPortDefaults(t *testing.T) {
	if got := configuredPort("/tmp"); got != 8080 {
		t.Fatalf("configuredPort = %d, want 8080", got)
	}
}

func TestDefaultRootSelection(t *testing.T) {
	app := newTestAuthApp(t)
	if app.defaultRoot() != "internal" {
		t.Fatalf("defaultRoot = %q", app.defaultRoot())
	}
	app.cfgMu.Lock()
	app.cfg.InternalEnabled = false
	app.cfg.SDEnabled = true
	app.cfgMu.Unlock()
	if app.defaultRoot() != "sd" {
		t.Fatalf("defaultRoot(sd) = %q", app.defaultRoot())
	}
	app.cfgMu.Lock()
	app.cfg.SDEnabled = false
	app.cfgMu.Unlock()
	if app.defaultRoot() != "internal" {
		t.Fatalf("defaultRoot(empty) = %q", app.defaultRoot())
	}
}

func newTestWebApp(t *testing.T) *App {
	t.Helper()
	app, err := newApp(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	app.cfgMu.Lock()
	app.cfg.InternalEnabled = true
	app.cfg.SDEnabled = false
	app.cfgMu.Unlock()
	return app
}

func TestHandleLoginFlow(t *testing.T) {
	app := newTestWebApp(t)
	h := app.routes()

	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d", rec.Code)
	}

	bad := httptest.NewRequest("POST", "/login", strings.NewReader("username=pocketbook&password=wrong"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", rec.Code)
	}

	good := httptest.NewRequest("POST", "/login", strings.NewReader("username=pocketbook&password=650wifi"))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, good)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("good login = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	var session string
	for _, c := range cookies {
		if c.Name == "pbwf_session" && c.Value != "" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie set")
	}
	if !app.validSession(session) {
		t.Fatal("session not recorded")
	}
}

func TestHandleIndexAndLogout(t *testing.T) {
	app := newTestWebApp(t)
	h := app.routes()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("unauth / = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}

	token := "handlers-test-token"
	app.sessMu.Lock()
	app.sessions[token] = time.Now().Add(time.Hour)
	app.sessMu.Unlock()

	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "pbwf_session", Value: token})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed / = %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "pbwf_session", Value: token})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	if app.validSession(token) {
		t.Fatal("session survives logout")
	}
}

func TestHandleMkdirAndDelete(t *testing.T) {
	app := newTestWebApp(t)
	h := app.routes()
	token := "handlers-mkdir-token"
	app.sessMu.Lock()
	app.sessions[token] = time.Now().Add(time.Hour)
	app.sessMu.Unlock()
	cookie := &http.Cookie{Name: "pbwf_session", Value: token}

	req := httptest.NewRequest("POST", "/mkdir", strings.NewReader("p=internal&name=newdir"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("mkdir missing parent = %d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/delete", strings.NewReader("p=internal"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete volume root = %d, want 400", rec.Code)
	}

	req = httptest.NewRequest("POST", "/delete", strings.NewReader("p=sd/Books"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete missing sd = %d, want 400", rec.Code)
	}
}

func TestHandleInfo(t *testing.T) {
	app := newTestAuthApp(t)
	req := httptest.NewRequest("GET", "/info", nil)
	rec := httptest.NewRecorder()
	app.handleInfo(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "WiFiFiles") {
		t.Fatalf("handleInfo = %d body=%q", rec.Code, rec.Body.String())
	}
}

func newTestServiceManager(t *testing.T) *ServiceManager {
	t.Helper()
	return &ServiceManager{app: newTestWebApp(t), appDir: t.TempDir()}
}

func TestHandleServices(t *testing.T) {
	sm := newTestServiceManager(t)
	h := sm.handleServices

	req := httptest.NewRequest("GET", "/services", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /services = %d", rec.Code)
	}

	bad := httptest.NewRequest("POST", "/services", strings.NewReader("http_port=80&ftp_port=2121&smb_port=4445"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h(rec, bad)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "ports") {
		t.Fatalf("bad ports = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}

	noStorage := httptest.NewRequest("POST", "/services", strings.NewReader("http_port=8081&ftp_port=2121&smb_port=4445"))
	noStorage.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h(rec, noStorage)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "least+one") {
		t.Fatalf("no storage = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}

	okForm := "http_port=8081&ftp_port=2122&smb_port=4446&internal=on&http_enabled=off&ftp_enabled=off&smb_enabled=off&logging_enabled=off"
	req = httptest.NewRequest("POST", "/services", strings.NewReader(okForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("good services = %d", rec.Code)
	}
	cfg := sm.app.configSnapshot()
	if cfg.HTTPPort != 8081 || cfg.FTPPort != 2122 || cfg.SMBPort != 4446 {
		t.Fatalf("ports not saved: %+v", cfg)
	}
}

func TestHandleCredentials(t *testing.T) {
	sm := newTestServiceManager(t)
	h := sm.handleCredentials

	bad := httptest.NewRequest("POST", "/credentials", strings.NewReader("username=ab&password=x"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, bad)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bad credentials = %d", rec.Code)
	}

	ok := httptest.NewRequest("POST", "/credentials", strings.NewReader("username=owner&password=supersecret"))
	ok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h(rec, ok)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("good credentials = %d", rec.Code)
	}
	cfg := sm.app.configSnapshot()
	if cfg.Username != "owner" {
		t.Fatalf("username = %q", cfg.Username)
	}
	if cfg.PasswordHash == "" || cfg.SMBNTHash == "" || cfg.DAVDigestHA1 == "" {
		t.Fatalf("hashes not saved: %+v", cfg)
	}
	if usesDefaultPassword(cfg) {
		t.Fatal("default password still recognized after change")
	}
}

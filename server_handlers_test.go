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

func TestHandleWebRenderBranches(t *testing.T) {
	app := newTestWebApp(t)
	internal := t.TempDir()
	sd := t.TempDir()
	app.roots["internal"] = internal
	app.roots["sd"] = sd
	h := app.routes()
	token := "handlers-render-token"
	app.sessMu.Lock()
	app.sessions[token] = time.Now().Add(time.Hour)
	app.sessMu.Unlock()
	cookie := &http.Cookie{Name: "pbwf_session", Value: token}
	get := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// handleLogin: method not allowed
	req := httptest.NewRequest("PUT", "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /login = %d", rec.Code)
	}

	// handleIndex: bad path -> renderIndex falls back to defaultRoot
	rec = get("/?k=" + encodeVirtualPath("nope/x"))
	if rec.Code != http.StatusOK {
		t.Fatalf("bad path index = %d body=%s", rec.Code, rec.Body.String())
	}

	// renderIndex: sort dirs-first, hidden file skipped
	for _, f := range []string{"book.fb2", "wififiles.log"} {
		if err := os.WriteFile(filepath.Join(internal, f), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"zeta", "Alpha"} {
		if err := os.MkdirAll(filepath.Join(internal, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	rec = get("/?p=internal")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "book.fb2") || strings.Contains(rec.Body.String(), "wififiles.log") {
		t.Fatalf("index list = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "zeta") || !strings.Contains(rec.Body.String(), "Alpha") {
		t.Fatalf("index dirs missing")
	}

	// renderIndex: sd root listed when sd enabled and exists
	app.cfgMu.Lock()
	app.cfg.SDEnabled = true
	app.cfgMu.Unlock()
	rec = get("/?p=internal")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Карта SD") {
		t.Fatalf("sd root = %d body=%s", rec.Code, rec.Body.String())
	}

	// renderIndex: ReadDir err
	app.roots["internal"] = filepath.Join(t.TempDir(), "missing")
	rec = get("/?p=internal")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "failed to read folder") {
		t.Fatalf("readdir err = %d body=%s", rec.Code, rec.Body.String())
	}

	// handleMkdir: invalid name
	app.roots["internal"] = internal
	req = httptest.NewRequest("POST", "/mkdir", strings.NewReader("p=internal&name=."))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("mkdir dot = %d", rec.Code)
	}

	// handleMkdir: existing dir -> redirect error
	if err := os.MkdirAll(filepath.Join(internal, "dup"), 0755); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/mkdir", strings.NewReader("p=internal&name=dup"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "failed+to+create") {
		t.Fatalf("mkdir dup = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}

	// enabledRoot: unknown volume default branch
	if app.enabledRoot("nope") {
		t.Fatal("enabledRoot(nope) = true")
	}
	if !app.enabledRoot("internal") {
		t.Fatal("enabledRoot(internal) = false")
	}

	// handleDelete: protected path is rejected by resolvePath -> 400
	req = httptest.NewRequest("POST", "/delete", strings.NewReader("p=internal/wififiles.log"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete protected = %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/delete", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /delete = %d", rec.Code)
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

func TestHandleControlAndControlData(t *testing.T) {
	sm := newTestServiceManager(t)
	req := httptest.NewRequest("GET", "/?msg=hi", nil)
	data := sm.controlData(req)
	if data.Version == "" || data.Username == "" {
		t.Fatalf("controlData incomplete: %+v", data)
	}
	if data.Message != "hi" {
		t.Fatalf("controlData message = %q", data.Message)
	}
	if data.HTTPPort == 0 {
		t.Fatalf("controlData http port = 0")
	}

	rec := httptest.NewRecorder()
	sm.handleControl(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleControl = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	sm.handleControl(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("handleControl /nope = %d", rec.Code)
	}
}

func TestHandleSettingsMethodsAndActions(t *testing.T) {
	app := newTestWebApp(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/settings", nil)
	app.handleSettings(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d, want 405", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/settings", nil)
	req.ParseForm()
	app.handleSettings(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("short creds = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/settings", nil)
	req.ParseForm()
	req.Form.Set("username", "newuser")
	req.Form.Set("password", "newpass123")
	app.handleSettings(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("valid creds = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location = %q", loc)
	}

	app.cfgMu.Lock()
	app.cfg.DefaultTarget = "internal/Books"
	app.cfgMu.Unlock()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/settings", nil)
	req.ParseForm()
	req.Form.Set("action", "clear_default_target")
	app.handleSettings(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("clear default = %d, want 303", rr.Code)
	}
	app.cfgMu.RLock()
	if app.cfg.DefaultTarget != "" {
		t.Fatal("default target not cleared")
	}
	app.cfgMu.RUnlock()

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/settings?msg=hello", nil)
	app.handleSettings(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET settings = %d", rr.Code)
	}
}

func TestHandleMkdirAndDeleteNegatives(t *testing.T) {
	app := newTestWebApp(t)
	app.roots["internal"] = t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mkdir", nil)
	app.handleMkdir(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mkdir GET = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/mkdir?p=internal/system/x", nil)
	req.ParseForm()
	app.handleMkdir(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mkdir protected = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/mkdir?p=internal", nil)
	req.ParseForm()
	req.Form.Set("name", "..")
	app.handleMkdir(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("mkdir invalid name = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/mkdir?p=internal", nil)
	req.ParseForm()
	req.Form.Set("name", "exists")
	app.handleMkdir(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("mkdir created = %d", rr.Code)
	}
	req = httptest.NewRequest("POST", "/mkdir?p=internal", nil)
	req.ParseForm()
	req.Form.Set("name", "exists")
	app.handleMkdir(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("mkdir dup = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/delete?p=internal", nil)
	req.ParseForm()
	app.handleDelete(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete root = %d, want 400 (resolvePath rejects root)", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/delete?p=internal/system/x", nil)
	req.ParseForm()
	app.handleDelete(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete protected = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/delete?p=internal/nope", nil)
	req.ParseForm()
	app.handleDelete(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("delete missing = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/delete?p=internal/exists", nil)
	req.ParseForm()
	app.handleDelete(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("delete ok = %d", rr.Code)
	}
}

func TestStopLockedNilServers(t *testing.T) {
	sm := newTestServiceManager(t)

	sm.stopHTTPLocked()
	if sm.httpSrv != nil {
		t.Fatal("httpSrv not nil after stop")
	}

	sm.stopFTPLocked()
	if sm.ftpSrv != nil {
		t.Fatal("ftpSrv not nil after stop")
	}

	sm.smbPort = 4445
	sm.smbKey = "abc"
	sm.stopSMBLocked()
	if sm.smbPort != 0 || sm.smbKey != "" {
		t.Fatalf("smb state not reset: %d %q", sm.smbPort, sm.smbKey)
	}
}

func TestWriteNativeStateStoppedFallback(t *testing.T) {
	dir := t.TempDir()
	writeNativeStateStopped(dir, "shutting down")
	data, err := os.ReadFile(filepath.Join(dir, "native_state.ini"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "running=0") {
		t.Fatalf("state missing running=0: %q", text)
	}
	if !strings.Contains(text, "version="+version) {
		t.Fatalf("state missing version: %q", text)
	}
	if !strings.Contains(text, "message=") {
		t.Fatalf("state missing message line: %q", text)
	}
}

func TestControlAuthBranches(t *testing.T) {
	app := newTestWebApp(t)
	sm := &ServiceManager{app: app}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("inner"))
	})
	h := sm.controlAuth(inner)

	if ips := localIPv4s(); len(ips) > 0 {
		req := httptest.NewRequest("POST", "http://pb/control", nil)
		req.RemoteAddr = ips[0] + ":1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || rr.Body.String() != "inner" {
			t.Fatalf("own address = %d %q", rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest("POST", "http://pb/control", nil)
	req.RemoteAddr = "10.99.99.99:1234"
	req.SetBasicAuth("pocketbook", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad creds = %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}

	req = httptest.NewRequest("POST", "http://pb/control", nil)
	req.RemoteAddr = "10.99.99.99:1234"
	req.SetBasicAuth("pocketbook", "650wifi")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "inner" {
		t.Fatalf("good creds = %d %q", rr.Code, rr.Body.String())
	}
}

func TestMobileTargetLabelVariants(t *testing.T) {
	if got := mobileTargetLabel("en", "internal/Books"); got != "Reader storage / Books" {
		t.Fatalf("en internal = %q", got)
	}
	if got := mobileTargetLabel("ru", "sd/Books"); got != "Карта SD / Books" {
		t.Fatalf("ru sd = %q", got)
	}
	if got := mobileTargetLabel("de", "/sd/Books"); got != "SD-Karte / Books" {
		t.Fatalf("de sd trim = %q", got)
	}
	if got := mobileTargetLabel("fr", "internal"); got != "Mémoire du lecteur" {
		t.Fatalf("fr internal = %q", got)
	}
	if got := mobileTargetLabel("en", "/"); got != "" {
		t.Fatalf("root = %q", got)
	}
	if got := mobileTargetLabel("xx", "internal/Books"); got != "Память ридера / Books" {
		t.Fatalf("default lang = %q", got)
	}
}

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAuthApp(t *testing.T) *App {
	t.Helper()
	salt := "00112233445566778899aabbccddeeff"
	return &App{
		cfg: Config{
			ConfigVersion:   5,
			Username:        "pocketbook",
			PasswordSalt:    salt,
			PasswordHash:    passwordHash(salt, "650wifi"),
			InternalEnabled: true,
			SDEnabled:       true,
		},
		sessions: make(map[string]time.Time),
	}
}

func TestSessionPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "sessions.json")

	first := newTestAuthApp(t)
	first.sessionPath = sessionPath
	first.sessions["tok-a"] = time.Now().Add(time.Hour)
	first.sessions["tok-expired"] = time.Now().Add(-time.Minute)
	first.saveSessions()

	second := newTestAuthApp(t)
	second.sessionPath = sessionPath
	second.loadSessions()
	if !second.validSession("tok-a") {
		t.Fatal("persisted session should survive restart")
	}
	if second.validSession("tok-expired") {
		t.Fatal("expired session must not be restored")
	}
	if len(second.sessions) != 1 {
		t.Fatalf("expected 1 restored session, got %d", len(second.sessions))
	}
}

func TestSessionFilePermissions(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "sessions.json")
	app := newTestAuthApp(t)
	app.sessionPath = sessionPath
	app.sessions["tok"] = time.Now().Add(time.Hour)
	app.saveSessions()
	st, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("session file mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestNewAppSessionPathUsesConfigDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	a, err := newApp(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(path), "sessions.json")
	if a.sessionPath != want {
		t.Fatalf("sessionPath = %q, want %q", a.sessionPath, want)
	}
}

func TestResetSessionsAndValidSession(t *testing.T) {
	app := newTestAuthApp(t)

	if app.validSession("") {
		t.Fatal("empty token must be invalid")
	}
	if app.validSession("unknown-token") {
		t.Fatal("unknown token must be invalid")
	}

	app.sessions["fresh"] = time.Now().Add(time.Hour)
	if !app.validSession("fresh") {
		t.Fatal("fresh token must be valid")
	}
	extended, ok := app.sessions["fresh"]
	if !ok || !extended.After(time.Now().Add(11*time.Hour)) {
		t.Fatalf("validSession should extend expiry, got %v", extended)
	}

	app.sessions["expired"] = time.Now().Add(-time.Minute)
	if app.validSession("expired") {
		t.Fatal("expired token must be invalid")
	}
	if _, still := app.sessions["expired"]; still {
		t.Fatal("expired token should be pruned")
	}

	app.resetSessions()
	if len(app.sessions) != 0 {
		t.Fatalf("resetSessions left %d entries", len(app.sessions))
	}
}

func TestAuthMiddlewareRedirectsWithoutSession(t *testing.T) {
	app := newTestAuthApp(t)
	handler := app.auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	noCookie := httptest.NewRequest("GET", "http://pb/settings", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, noCookie)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/login" {
		t.Fatalf("no cookie: code=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}

	badCookie := httptest.NewRequest("GET", "http://pb/settings", nil)
	badCookie.AddCookie(&http.Cookie{Name: "pbwf_session", Value: "bogus"})
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, badCookie)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("bad cookie: code=%d", rr.Code)
	}

	app.sessions["good"] = time.Now().Add(time.Hour)
	goodCookie := httptest.NewRequest("GET", "http://pb/settings", nil)
	goodCookie.AddCookie(&http.Cookie{Name: "pbwf_session", Value: "good"})
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, goodCookie)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("good cookie: code=%d", rr.Code)
	}
}

func TestControlAuthBasicAuth(t *testing.T) {
	app := newTestAuthApp(t)
	sm := &ServiceManager{app: app}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := sm.controlAuth(inner)

	req := httptest.NewRequest("GET", "http://pb/control", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials should be 401, got %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), `Basic realm=`) {
		t.Fatalf("missing WWW-Authenticate: %q", rr.Header().Get("WWW-Authenticate"))
	}

	bad := httptest.NewRequest("GET", "http://pb/control", nil)
	bad.RemoteAddr = "203.0.113.9:1234"
	bad.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("pocketbook:wrong")))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bad)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad password should be 401, got %d", rr.Code)
	}

	good := httptest.NewRequest("GET", "http://pb/control", nil)
	good.RemoteAddr = "203.0.113.9:1234"
	good.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("pocketbook:650wifi")))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, good)
	if rr.Code != http.StatusOK {
		t.Fatalf("good credentials should pass, got %d", rr.Code)
	}
}

func TestRemoteAddressHelpers(t *testing.T) {
	hostPort := httptest.NewRequest("GET", "http://pb/", nil)
	hostPort.RemoteAddr = "192.168.1.50:4444"
	if got := remoteIP(hostPort); got != "192.168.1.50" {
		t.Fatalf("remoteIP(host:port) = %q", got)
	}
	plain := httptest.NewRequest("GET", "http://pb/", nil)
	plain.RemoteAddr = "192.168.1.50"
	if got := remoteIP(plain); got != "192.168.1.50" {
		t.Fatalf("remoteIP(plain) = %q", got)
	}

	req := httptest.NewRequest("GET", "http://pb:8080/settings", nil)
	if got := requestHost(req); got != "pb" {
		t.Fatalf("requestHost(host:port) = %q", got)
	}
	req = httptest.NewRequest("GET", "http://pb/settings", nil)
	if got := requestHost(req); got != "pb" {
		t.Fatalf("requestHost(plain) = %q", got)
	}

	owns := localIPv4s()
	if len(owns) == 0 {
		t.Fatal("localIPv4s returned nothing on the test host")
	}
	if !isOwnAddress(owns[0]) {
		t.Fatalf("isOwnAddress(%q) should be true", owns[0])
	}
	if isOwnAddress("203.0.113.77") {
		t.Fatal("isOwnAddress of a non-local address should be false")
	}
}

func TestTestListenPort(t *testing.T) {
	ok, _ := testListenPort(0)
	if !ok {
		t.Fatal("port 0 should be available")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy, reason := testListenPort(ln.Addr().(*net.TCPAddr).Port)
	if busy {
		t.Fatalf("occupied port reported available: %s", reason)
	}
}

func TestSaveSessionsNoopWithoutPath(t *testing.T) {
	app := newTestAuthApp(t)
	app.sessions["tok"] = time.Now().Add(time.Hour)
	app.saveSessionsLocked()
	if len(app.sessions) != 1 {
		t.Fatalf("session map changed: %d", len(app.sessions))
	}
}

func TestSaveSessionsFiltersExpired(t *testing.T) {
	dir := t.TempDir()
	app := newTestAuthApp(t)
	app.sessionPath = filepath.Join(dir, "sessions.json")
	app.sessions["live"] = time.Now().Add(time.Hour)
	app.sessions["expired"] = time.Now().Add(-time.Minute)
	app.saveSessionsLocked()

	data, err := os.ReadFile(app.sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]int64
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["expired"]; ok {
		t.Fatal("expired session persisted")
	}
	if _, ok := stored["live"]; !ok {
		t.Fatal("live session missing from persisted file")
	}
}

func TestSaveSessionsMkdirFailure(t *testing.T) {
	app := newTestAuthApp(t)
	parent := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(parent, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	app.sessionPath = filepath.Join(parent, "sub", "sessions.json")
	app.sessions["tok"] = time.Now().Add(time.Hour)
	app.saveSessionsLocked()
	if !app.lastSessionSave.IsZero() {
		t.Fatal("failed save should not record lastSessionSave")
	}
	if _, err := os.Stat(app.sessionPath); err == nil {
		t.Fatal("session file written despite MkdirAll failure")
	}
}

func TestSaveSessionsWriteFileFailure(t *testing.T) {
	app := newTestAuthApp(t)
	dir := t.TempDir()
	app.sessionPath = filepath.Join(dir, "sessions.json")
	if err := os.Mkdir(app.sessionPath+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	app.sessions["tok"] = time.Now().Add(time.Hour)
	app.saveSessionsLocked()
	if !app.lastSessionSave.IsZero() {
		t.Fatal("failed WriteFile should not record lastSessionSave")
	}
}

func TestSaveSessionsRenameFailure(t *testing.T) {
	app := newTestAuthApp(t)
	dir := t.TempDir()
	app.sessionPath = filepath.Join(dir, "sessions.json")
	if err := os.Mkdir(app.sessionPath, 0700); err != nil {
		t.Fatal(err)
	}
	app.sessions["tok"] = time.Now().Add(time.Hour)
	app.saveSessionsLocked()
	if !app.lastSessionSave.IsZero() {
		t.Fatal("failed Rename should not record lastSessionSave")
	}
	if _, err := os.Stat(app.sessionPath + ".tmp"); err == nil {
		t.Fatal("tmp file not removed after failed Rename")
	}
}

func TestRandomHex(t *testing.T) {
	for _, n := range []int{0, 4, 16} {
		got, err := randomHex(n)
		if err != nil {
			t.Fatalf("randomHex(%d): %v", n, err)
		}
		if len(got) != 2*n {
			t.Fatalf("randomHex(%d) length = %d, want %d", n, len(got), 2*n)
		}
		if _, err := hex.DecodeString(got); err != nil {
			t.Fatalf("randomHex(%d) not hex: %v", n, err)
		}
	}
}

func TestLoadSessionsMissingFile(t *testing.T) {
	app := newTestAuthApp(t)
	app.sessionPath = filepath.Join(t.TempDir(), "nope", "sessions.json")
	app.loadSessions()
	if len(app.sessions) != 0 {
		t.Fatalf("sessions loaded from missing file: %d", len(app.sessions))
	}
}

func TestLoadSessionsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	app := newTestAuthApp(t)
	app.sessionPath = path
	app.loadSessions()
	if len(app.sessions) != 0 {
		t.Fatalf("sessions loaded from corrupt file: %d", len(app.sessions))
	}
}

func TestLoadSessionsRestoresLiveOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	data, _ := json.Marshal(map[string]int64{
		"live":    time.Now().Add(time.Hour).Unix(),
		"expired": time.Now().Add(-time.Minute).Unix(),
	})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	app := newTestAuthApp(t)
	app.sessionPath = path
	app.loadSessions()
	if _, ok := app.sessions["live"]; !ok {
		t.Fatal("live session not restored")
	}
	if _, ok := app.sessions["expired"]; ok {
		t.Fatal("expired session restored")
	}
}

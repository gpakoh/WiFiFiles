package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const sessionPersistInterval = 30 * time.Second

func (a *App) loadSessions() {
	if a.sessionPath == "" {
		return
	}
	data, err := os.ReadFile(a.sessionPath)
	if err != nil {
		return
	}
	var stored map[string]int64
	if err := json.Unmarshal(data, &stored); err != nil {
		return
	}
	now := time.Now()
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	for tok, exp := range stored {
		if exp > now.Unix() {
			a.sessions[tok] = time.Unix(exp, 0)
		}
	}
}

func (a *App) saveSessions() {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	a.saveSessionsLocked()
}

func (a *App) saveSessionsLocked() {
	if a.sessionPath == "" {
		return
	}
	now := time.Now()
	data := make(map[string]int64, len(a.sessions))
	for tok, exp := range a.sessions {
		if exp.After(now) {
			data[tok] = exp.Unix()
		}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(a.sessionPath), 0700); err != nil {
		return
	}
	tmp := a.sessionPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, a.sessionPath); err != nil {
		_ = os.Remove(tmp)
		return
	}
	a.lastSessionSave = now
}

func (a *App) resetSessions() {
	a.sessMu.Lock()
	a.sessions = make(map[string]time.Time)
	a.sessMu.Unlock()
	a.saveSessions()
}

func (a *App) checkCredentials(username, password string) bool {
	cfg := a.configSnapshot()
	wantUser := []byte(cfg.Username)
	gotUser := []byte(username)
	userOK := len(wantUser) == len(gotUser) && subtle.ConstantTimeCompare(wantUser, gotUser) == 1
	gotHash := []byte(passwordHash(cfg.PasswordSalt, password))
	wantHash := []byte(cfg.PasswordHash)
	passOK := len(wantHash) == len(gotHash) && subtle.ConstantTimeCompare(wantHash, gotHash) == 1
	return userOK && passOK
}

func passwordHash(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

func usesDefaultPassword(cfg Config) bool {
	return passwordHash(cfg.PasswordSalt, "650wifi") == cfg.PasswordHash
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("pbwf_session")
		if err != nil || !a.validSession(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (a *App) validSession(token string) bool {
	if token == "" {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	expiry, ok := a.sessions[token]
	if !ok || time.Now().After(expiry) {
		delete(a.sessions, token)
		return false
	}
	a.sessions[token] = time.Now().Add(12 * time.Hour)
	if time.Since(a.lastSessionSave) >= sessionPersistInterval {
		a.saveSessionsLocked()
	}
	return true
}

func (sm *ServiceManager) controlAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOwnAddress(remoteIP(r)) {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || !sm.app.checkCredentials(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="WiFiFiles control"`)
			http.Error(w, "WiFiFiles login required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

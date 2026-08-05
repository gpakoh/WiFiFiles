package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	activityClientWindow = 5 * time.Minute
	activityRecentMax    = 12
	activitySyncEvery    = 2 * time.Second
)

type activityState struct {
	mu       sync.Mutex
	syncMu   sync.Mutex
	path     string
	now      func() time.Time
	clients  map[string]time.Time
	uploaded int64
	deleted  int64
	recent   []string
	lastSync time.Time
}

var activity activityState

func (a *activityState) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *activityState) setPath(p string) {
	a.mu.Lock()
	a.path = p
	a.lastSync = time.Time{}
	a.mu.Unlock()
}

func (a *activityState) noteClient(ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	if a.clients == nil {
		a.clients = make(map[string]time.Time)
	}
	a.clients[ip] = a.clock()
	a.mu.Unlock()
}

func (a *activityState) addUpload() {
	a.mu.Lock()
	a.uploaded++
	a.mu.Unlock()
	a.syncNow()
}

func (a *activityState) addDelete() {
	a.mu.Lock()
	a.deleted++
	a.mu.Unlock()
	a.syncNow()
}

func (a *activityState) addEvent(text string) {
	if text == "" {
		return
	}
	a.mu.Lock()
	a.recent = append(a.recent, text)
	if len(a.recent) > activityRecentMax {
		a.recent = a.recent[len(a.recent)-activityRecentMax:]
	}
	a.mu.Unlock()
	a.syncNow()
}

func (a *activityState) activeConnectionsLocked() int {
	cutoff := a.clock().Add(-activityClientWindow)
	n := 0
	for ip, seen := range a.clients {
		if seen.Before(cutoff) {
			delete(a.clients, ip)
			continue
		}
		n++
	}
	return n
}

func (a *activityState) syncNow() {
	a.mu.Lock()
	if a.path == "" || a.clock().Sub(a.lastSync) < activitySyncEvery {
		a.mu.Unlock()
		return
	}
	a.lastSync = a.clock()
	path := a.path
	conns := a.activeConnectionsLocked()
	uploaded := a.uploaded
	deleted := a.deleted
	recent := strings.Join(a.recent, "\x01")
	a.mu.Unlock()
	a.writeToFile(path, conns, uploaded, deleted, recent)
}

func (a *activityState) writeToFile(path string, conns int, uploaded, deleted int64, recent string) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	lines = setINILine(lines, "active_connections", strconv.Itoa(conns))
	lines = setINILine(lines, "uploaded_total", strconv.FormatInt(uploaded, 10))
	lines = setINILine(lines, "deleted_total", strconv.FormatInt(deleted, 10))
	lines = setINILine(lines, "recent_log", cleanINIValue(recent))
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0666)
	_ = os.Chmod(path, 0666)
}

func (a *activityState) snapshot() (conns int, uploaded, deleted int64, recent string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	conns = a.activeConnectionsLocked()
	uploaded = a.uploaded
	deleted = a.deleted
	recent = strings.Join(a.recent, "\x01")
	return
}

func tr(lang, ru, en, fr, de string) string {
	switch lang {
	case "ru":
		return ru
	case "fr":
		return fr
	case "de":
		return de
	default:
		return en
	}
}

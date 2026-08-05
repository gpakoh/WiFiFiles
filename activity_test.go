package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActivityNoteClientWindow(t *testing.T) {
	var a activityState
	tm := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return tm }

	a.noteClient("192.168.1.10")
	a.noteClient("192.168.1.11")
	if got := a.snapshotCount(); got != 2 {
		t.Fatalf("expected 2 active clients, got %d", got)
	}

	tm = tm.Add(activityClientWindow + time.Minute)
	if got := a.snapshotCount(); got != 0 {
		t.Fatalf("expected 0 active clients after window, got %d", got)
	}
}

func TestActivitySnapshotCounters(t *testing.T) {
	var a activityState
	tm := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return tm }

	a.noteClient("10.0.0.5")
	a.addUpload()
	a.addUpload()
	a.addDelete()

	conns, uploaded, deleted, _ := a.snapshot()
	if conns != 1 || uploaded != 2 || deleted != 1 {
		t.Fatalf("unexpected snapshot: conns=%d uploaded=%d deleted=%d", conns, uploaded, deleted)
	}
}

func TestActivityRecentRollover(t *testing.T) {
	var a activityState
	tm := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return tm }

	for i := 0; i < activityRecentMax+5; i++ {
		a.addEvent("event")
	}
	_, _, _, recent := a.snapshot()
	if n := strings.Count(recent, "\x01") + 1; n != activityRecentMax {
		t.Fatalf("expected %d recent events, got %d", activityRecentMax, n)
	}
}

func TestActivitySyncToStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "native_state.ini")
	_ = os.WriteFile(path, []byte("running=1\nip=192.168.1.5\n"), 0644)

	var a activityState
	tm := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time {
		tm = tm.Add(3 * time.Second)
		return tm
	}
	a.setPath(path)

	a.addUpload()
	a.addDelete()
	a.addEvent("Загружено: book.fb2")
	time.Sleep(150 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"active_connections=0", "uploaded_total=1", "deleted_total=1", "recent_log=", "running=1", "ip=192.168.1.5"} {
		if !strings.Contains(text, want) {
			t.Fatalf("state file missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "recent_log=") || !strings.Contains(text, "book.fb2") {
		t.Fatalf("recent_log not written:\n%s", text)
	}
	if !strings.Contains(text, "Загружено: book.fb2") {
		t.Fatalf("recent_log event text mismatch:\n%s", text)
	}
}

func TestActivitySyncThrottle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "native_state.ini")
	_ = os.WriteFile(path, []byte("running=1\n"), 0644)

	var a activityState
	tm := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return tm }
	a.setPath(path)

	a.addUpload()
	a.addUpload()
	time.Sleep(150 * time.Millisecond)

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "uploaded_total=1") {
		t.Fatalf("expected throttled sync to keep first value, got:\n%s", string(data))
	}
}

func (a *activityState) snapshotCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activeConnectionsLocked()
}

func TestActivityTrLanguages(t *testing.T) {
	cases := []struct {
		lang, want string
	}{
		{"ru", "подключение"},
		{"fr", "connexion"},
		{"de", "Verbindung"},
		{"en", "connection"},
		{"xx", "connection"},
		{"", "connection"},
	}
	for _, c := range cases {
		if got := tr(c.lang, "подключение", "connection", "connexion", "Verbindung"); got != c.want {
			t.Errorf("tr(%q) = %q, want %q", c.lang, got, c.want)
		}
	}
}


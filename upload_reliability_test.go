package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUploadIdleDeadlineAndSlowProgress(t *testing.T) {
	for _, steady := range []bool{false, true} {
		t.Run(fmt.Sprint(steady), func(t *testing.T) {
			srv := httptest.NewServer(activityTracking(securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w, trace := beginHTTPUpload(w, r, "test")
				defer trace.finish()
				r.Body.(*uploadBody).idle = 150 * time.Millisecond
				_, err := io.Copy(io.Discard, r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusRequestTimeout)
					return
				}
				w.WriteHeader(http.StatusCreated)
			}))))
			defer srv.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = fmt.Fprint(conn, "PUT / HTTP/1.1\r\nHost: reader\r\nContent-Length: 8\r\n\r\na")
			if steady {
				// Total transfer time exceeds the idle allowance, but every read progresses.
				for i := 0; i < 7; i++ {
					time.Sleep(40 * time.Millisecond)
					_, _ = conn.Write([]byte("b"))
				}
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			want := http.StatusRequestTimeout
			if steady {
				want = http.StatusCreated
			}
			if response.StatusCode != want {
				t.Fatalf("status=%d want=%d", response.StatusCode, want)
			}
		})
	}
}

func TestStopHTTPClosesActiveUpload(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		_, _ = io.Copy(io.Discard, r.Body)
		close(finished)
	}))
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: reader\r\nContent-Length: 20\r\n\r\nx")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request not started")
	}
	sm := &ServiceManager{httpSrv: srv.Config, httpLn: srv.Listener, appDir: t.TempDir()}
	sm.stopHTTPLocked()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("active request survived HTTP stop")
	}
}

func TestMobileSameSizeDifferentContentIsPreserved(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint(raw), func(t *testing.T) {
			app, token, dir := prepareMobileTest(t, "safe")
			original := filepath.Join(dir, "book.epub")
			if err := os.WriteFile(original, []byte("same"), 0644); err != nil {
				t.Fatal(err)
			}
			var rr *httptest.ResponseRecorder
			var result MobileUploadResult
			if raw {
				rr, result = mobileRawUploadRequest(t, app, token, "collision", "book.epub", []byte("diff"))
			} else {
				rr, result = mobileUploadRequest(t, app, token, "collision", "book.epub", "diff")
			}
			if rr.Code != http.StatusOK || result.Status != "renamed" {
				t.Fatalf("status=%d result=%+v", rr.Code, result)
			}
			old, _ := os.ReadFile(original)
			newData, err := os.ReadFile(filepath.Join(dir, result.StoredAs))
			if err != nil || string(old) != "same" || string(newData) != "diff" {
				t.Fatalf("old=%q new=%q err=%v", old, newData, err)
			}
		})
	}
}

func TestSameUploadContentAcrossBuffers(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "old"), filepath.Join(dir, "new")
	content := strings.Repeat("a", 65536)
	for _, test := range []struct {
		text  string
		equal bool
	}{{content, true}, {content[:len(content)-1] + "b", false}, {"short", false}, {"", false}} {
		if err := os.WriteFile(a, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, []byte(test.text), 0644); err != nil {
			t.Fatal(err)
		}
		same, err := sameUploadContent(a, b, int64(len(test.text)))
		if err != nil || same != test.equal {
			t.Fatalf("equal=%v err=%v want=%v", same, err, test.equal)
		}
	}
}

type interruptedUploadReader struct{}

func (interruptedUploadReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestDAVInterruptedUploadCleanupAndRetry(t *testing.T) {
	dav, dir := newTestDAV(t)
	path := filepath.Join(dir, "book.epub")
	if err := os.WriteFile(path, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	body := io.MultiReader(strings.NewReader("partial"), interruptedUploadReader{})
	r := httptest.NewRequest(http.MethodPut, "/dav/internal/book.epub", body)
	rr := httptest.NewRecorder()
	dav.handlePut(rr, r)
	if rr.Code < 400 {
		t.Fatalf("interrupted upload succeeded: %d", rr.Code)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "original" {
		t.Fatalf("existing file changed: %q", data)
	}
	partials, err := filepath.Glob(filepath.Join(dir, ".wififiles-upload-*"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partials=%v error=%v", partials, err)
	}
	rr = httptest.NewRecorder()
	dav.handlePut(rr, httptest.NewRequest(http.MethodPut, "/dav/internal/book.epub", strings.NewReader("complete")))
	data, _ = os.ReadFile(path)
	if rr.Code != http.StatusNoContent || string(data) != "complete" {
		t.Fatalf("retry status=%d data=%q", rr.Code, data)
	}
}

func TestDAVUnknownLengthUploadKeepsDiskReserve(t *testing.T) {
	dav, dir := newTestDAV(t)
	old := diskSpaceAvailable
	diskSpaceAvailable = func(string) (uint64, error) { return uploadSafetyReserve - 1, nil }
	t.Cleanup(func() { diskSpaceAvailable = old })
	r := httptest.NewRequest(http.MethodPut, "/dav/internal/book.epub", io.NopCloser(strings.NewReader("book")))
	r.ContentLength = -1
	rr := httptest.NewRecorder()
	dav.handlePut(rr, r)
	if rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected files=%v error=%v", entries, err)
	}
}

func TestLibraryRefreshSerializesScansAndKeepsPendingTargets(t *testing.T) {
	ensureStorageMounts(t)
	dir := "/mnt/ext1/system/bin"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	// Each real child process gets a lock directory. Concurrent starts leave
	// an overlap marker; the release file makes completion deterministic.
	script := fmt.Sprintf("#!/bin/sh\nif ! mkdir '%s/lock' 2>/dev/null; then touch '%s/overlap'; exit 1; fi\necho start >> '%s/starts'\nwhile [ ! -f '%s/release' ]; do sleep 0.02; done\nrmdir '%s/lock'\n", state, state, state, state, state)
	if err := os.WriteFile(filepath.Join(dir, "scanner.app"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	app := &App{libraryTargets: map[string]struct{}{"/mnt/ext1/Books": {}}}
	defer func() {
		_ = os.WriteFile(filepath.Join(state, "release"), nil, 0600)
		app.libraryMu.Lock()
		if app.libraryTimer != nil {
			app.libraryTimer.Stop()
		}
		app.libraryMu.Unlock()
	}()
	wait := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !check() {
			if time.Now().After(deadline) {
				t.Fatal("scanner did not reach expected state")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	app.flushLibraryRefresh()
	wait(func() bool { _, err := os.Stat(filepath.Join(state, "lock")); return err == nil })
	app.libraryMu.Lock()
	app.libraryTargets["/mnt/ext2/Books"] = struct{}{}
	app.libraryMu.Unlock()
	app.flushLibraryRefresh()
	app.libraryMu.Lock()
	pending := len(app.libraryTargets)
	app.libraryMu.Unlock()
	if pending != 1 {
		t.Fatal("pending target was discarded")
	}
	if err := os.WriteFile(filepath.Join(state, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { app.libraryMu.Lock(); defer app.libraryMu.Unlock(); return !app.libraryRunning })
	app.libraryMu.Lock()
	if app.libraryTimer != nil {
		app.libraryTimer.Stop()
	}
	app.libraryMu.Unlock()
	app.flushLibraryRefresh()
	wait(func() bool { app.libraryMu.Lock(); defer app.libraryMu.Unlock(); return !app.libraryRunning })
	starts, err := os.ReadFile(filepath.Join(state, "starts"))
	if err != nil || strings.Count(string(starts), "start") != 2 {
		t.Fatalf("starts=%q err=%v", starts, err)
	}
	if _, err := os.Stat(filepath.Join(state, "overlap")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("scanner processes overlapped")
	}
}

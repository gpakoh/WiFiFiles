package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPathHelpersVariants(t *testing.T) {
	app := newTestAuthApp(t)
	app.roots = map[string]string{"internal": t.TempDir(), "sd": t.TempDir()}

	app.cfg.InternalEnabled = false
	if _, _, err := app.resolvePath("internal/Books/a.txt", true); err == nil || !strings.Contains(err.Error(), "storage disabled") {
		t.Fatalf("resolvePath disabled storage err=%v", err)
	}
	app.cfg.InternalEnabled = true

	cases := []struct {
		v     string
		allow bool
		want  string
	}{
		{"internal/Books/a.txt", true, "internal/Books/a.txt"},
		{"", true, "internal"},
		{"", false, ""},
		{"internal", false, ""},
		{"internal/Books", true, "internal/Books"},
		{"sd/Books/x.txt", true, "sd/Books/x.txt"},
		{"nope/x", true, ""},
		{"internal/../../etc", true, ""},
	}
	for _, tc := range cases {
		_, clean, err := app.resolvePath(tc.v, tc.allow)
		if tc.want == "" {
			if err == nil {
				t.Fatalf("resolvePath(%q,%v) want err", tc.v, tc.allow)
			}
			continue
		}
		if err != nil || clean != tc.want {
			t.Fatalf("resolvePath(%q,%v) = %q,%v want %q", tc.v, tc.allow, clean, err, tc.want)
		}
	}

	if _, _, err := app.resolvePath("internal/system/x", true); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("resolvePath protected err=%v", err)
	}
	app.roots["sd"] = filepath.Join(t.TempDir(), "missing")
	if _, _, err := app.resolvePath("sd/Books/x.txt", true); err == nil || !strings.Contains(err.Error(), "memory card") {
		t.Fatalf("resolvePath sd missing err=%v", err)
	}

	prot := []struct {
		v    string
		want bool
	}{
		{"internal", false},
		{"internal/Books", false},
		{"internal/system", true},
		{"internal/system/x", true},
		{"internal/wififiles.log", true},
		{"sd/lost.dir", true},
		{"sd/Books", false},
		{"nope/x", false},
	}
	for _, tc := range prot {
		if got := isProtectedVirtual(tc.v); got != tc.want {
			t.Fatalf("isProtectedVirtual(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}

	hidden := []struct {
		parent, name string
		want         bool
	}{
		{"internal", "wififiles.log", true},
		{"internal", "books", false},
		{"sd", "lost.dir", true},
		{"sd", "books", false},
		{"unknown", "x", false},
		{"internal/Books", "x", false},
	}
	for _, tc := range hidden {
		if got := isHiddenSystemPath(tc.parent, tc.name); got != tc.want {
			t.Fatalf("isHiddenSystemPath(%q,%q) = %v, want %v", tc.parent, tc.name, got, tc.want)
		}
	}

	parents := []struct {
		v    string
		want string
	}{
		{"internal", ""},
		{"sd", ""},
		{"", ""},
		{".", ""},
		{"internal/Books", "internal"},
		{"internal/Books/a.txt", "internal/Books"},
		{"/internal/Books", "internal"},
	}
	for _, tc := range parents {
		if got := parentVirtual(tc.v); got != tc.want {
			t.Fatalf("parentVirtual(%q) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestEncodeAndRequestVirtualPath(t *testing.T) {
	original := "internal/Books/книга.pdf"
	enc := encodeVirtualPath(original)
	if enc == original {
		t.Fatal("encodeVirtualPath should not be a plaintext passthrough")
	}

	req := httptest.NewRequest("GET", "http://pb/?k="+enc, nil)
	if got := requestVirtualPath(req); got != original {
		t.Fatalf("requestVirtualPath(k) = %q, want %q", got, original)
	}

	req = httptest.NewRequest("GET", "http://pb/?p="+original, nil)
	if got := requestVirtualPath(req); got != original {
		t.Fatalf("requestVirtualPath(p) = %q, want %q", got, original)
	}

	req = httptest.NewRequest("GET", "http://pb/?k=%21%21%21", nil)
	if got := requestVirtualPath(req); got != "" {
		t.Fatalf("requestVirtualPath(bad k) = %q, want empty fallback", got)
	}
}

func TestRequestVirtualPathFallbackAndUnescape(t *testing.T) {
	req := httptest.NewRequest("GET", "http://pb/?k=!!bad!!&p=internal/Books", nil)
	if got := requestVirtualPath(req); got != "internal/Books" {
		t.Fatalf("fallback k->p = %q", got)
	}

	req = httptest.NewRequest("GET", "http://pb/?p=internal%252FBooks", nil)
	if got := requestVirtualPath(req); got != "internal/Books" {
		t.Fatalf("double unescape = %q", got)
	}

	req = httptest.NewRequest("GET", "http://pb/?p=%25252e", nil)
	if got := requestVirtualPath(req); got != "." {
		t.Fatalf("triple unescape = %q", got)
	}

	req = httptest.NewRequest("GET", "http://pb/?p=%25252e%25252e", nil)
	if got := requestVirtualPath(req); got != ".." {
		t.Fatalf("triple unescape pair = %q", got)
	}
}

func TestRedirectMsg(t *testing.T) {
	req := httptest.NewRequest("GET", "http://pb/?p=x", nil)
	rr := httptest.NewRecorder()
	redirectMsg(rr, req, "internal/Books", "saved")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc == "" || !containsAll(loc, "msg=saved", "/?k=") {
		t.Fatalf("location = %q", loc)
	}
}

func TestHandleDownload(t *testing.T) {
	app := newTestAuthApp(t)
	root := t.TempDir()
	internal := filepath.Join(root, "internal")
	if err := os.MkdirAll(internal, 0755); err != nil {
		t.Fatal(err)
	}
	app.roots = map[string]string{"internal": internal}
	content := []byte("download me")
	if err := os.WriteFile(filepath.Join(internal, "file.txt"), content, 0644); err != nil {
		t.Fatal(err)
	}

	ok := httptest.NewRequest("GET", "http://pb/download?p=internal/file.txt", nil)
	rr := httptest.NewRecorder()
	app.handleDownload(rr, ok)
	if rr.Code != http.StatusOK {
		t.Fatalf("download ok: code=%d", rr.Code)
	}
	if !containsAll(rr.Header().Get("Content-Disposition"), "attachment; filename*=UTF-8''file.txt") {
		t.Fatalf("Content-Disposition = %q", rr.Header().Get("Content-Disposition"))
	}
	if rr.Body.String() != string(content) {
		t.Fatalf("body = %q", rr.Body.String())
	}

	missing := httptest.NewRequest("GET", "http://pb/download?p=internal/nope.txt", nil)
	rr = httptest.NewRecorder()
	app.handleDownload(rr, missing)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("download missing: code=%d", rr.Code)
	}

	dir := httptest.NewRequest("GET", "http://pb/download?p=internal", nil)
	rr = httptest.NewRecorder()
	app.handleDownload(rr, dir)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("download of volume root should be 400: code=%d", rr.Code)
	}

	subdir := httptest.NewRequest("GET", "http://pb/download?p=internal/Books", nil)
	rr = httptest.NewRecorder()
	app.handleDownload(rr, subdir)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("download of a dir should be 404: code=%d", rr.Code)
	}

	protected := httptest.NewRequest("GET", "http://pb/download?p=internal/system/x", nil)
	rr = httptest.NewRecorder()
	app.handleDownload(rr, protected)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("download of protected path should be 400: code=%d", rr.Code)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func TestCommitTempAutoRenameStatError(t *testing.T) {
	dir := t.TempDir()
	longName := strings.Repeat("a", 300) + ".txt"
	if _, err := commitTempAutoRename(dir, longName, filepath.Join(dir, "src")); err == nil {
		t.Fatal("Stat on too-long name should fail")
	}
}

func TestCommitTempAutoRenameRenameError(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "missing-src.part")
	if _, err := commitTempAutoRename(dir, "book.fb2", src); err == nil {
		t.Fatal("Rename of missing temp should fail")
	}
}

func TestResolvePathRejectsSymlink(t *testing.T) {
	app := newTestAuthApp(t)
	root := t.TempDir()
	app.roots = map[string]string{"internal": root}
	app.cfg.InternalEnabled = true
	if err := os.MkdirAll(filepath.Join(root, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "Books", "escape")); err != nil {
		t.Skip("symlinks not supported")
	}
	if _, _, err := app.resolvePath("internal/Books/escape/etc/passwd", true); err == nil {
		t.Fatal("symlink escape accepted")
	}
	if _, _, err := app.resolvePath("internal/Books/escape", true); err == nil {
		t.Fatal("symlink itself accepted")
	}
	if _, _, err := app.resolvePath("internal/Books/new.txt", true); err != nil {
		t.Fatalf("missing leaf must stay allowed: %v", err)
	}
}

func TestCommitTempAutoRenameConcurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	results := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		tm := filepath.Join(dir, fmt.Sprintf(".src-%d", i))
		if err := os.WriteFile(tm, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(tmp string) {
			defer wg.Done()
			name, err := commitTempAutoRename(dir, "book.txt", tmp)
			if err != nil {
				results <- "ERR: " + err.Error()
				return
			}
			results <- name
		}(tm)
	}
	wg.Wait()
	close(results)
	seen := make(map[string]bool)
	for r := range results {
		if strings.HasPrefix(r, "ERR: ") {
			t.Fatal(r)
		}
		if seen[r] {
			t.Fatalf("duplicate result %q — a file was clobbered", r)
		}
		seen[r] = true
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "book") {
			got++
		}
	}
	if got != n {
		t.Fatalf("committed files = %d, want %d", got, n)
	}
}

func TestCommitTempAutoRenameTooMany(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10000; i++ {
		name := "doc.txt"
		if i > 0 {
			name = fmt.Sprintf("doc (%d).txt", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join(dir, "src.part")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := commitTempAutoRename(dir, "doc.txt", src); err == nil {
		t.Fatal("10k colliding names should fail")
	}
}

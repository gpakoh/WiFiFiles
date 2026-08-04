package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

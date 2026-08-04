package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
)

func TestWriteMultipartTempIgnoresUnsupportedChmod(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("files", "book.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "pdf-data"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	hdr := req.MultipartForm.File["files"][0]

	old := chmodFile
	chmodFile = func(path string, mode os.FileMode) error {
		return &os.PathError{Op: "chmod", Path: path, Err: syscall.EPERM}
	}
	t.Cleanup(func() { chmodFile = old })

	dir := t.TempDir()
	tmpPath, err := writeMultipartTemp(dir, hdr)
	if err != nil {
		t.Fatalf("chmod EPERM aborted upload: %v", err)
	}
	defer os.Remove(tmpPath)
	got, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pdf-data" {
		t.Fatalf("got %q", got)
	}
}

func TestHandleUploadNegativeBranches(t *testing.T) {
	app := newTestWebApp(t)
	app.roots["internal"] = t.TempDir()
	app.roots["sd"] = t.TempDir()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/upload", nil)
	app.handleUpload(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/upload", nil)
	app.handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no multipart = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/upload", nil)
	app.handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no multipart = %d", rr.Code)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("files", "book.fb2")
	part.Write([]byte("data"))
	mw.Close()
	req = httptest.NewRequest("POST", "/upload?p=internal/system/x", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("protected target = %d, want 400", rr.Code)
	}

	body.Reset()
	mw = multipart.NewWriter(&body)
	part, _ = mw.CreateFormFile("files", "..")
	part.Write([]byte("data"))
	mw.Close()
	req = httptest.NewRequest("POST", "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("traversal name = %d, want 400", rr.Code)
	}
}

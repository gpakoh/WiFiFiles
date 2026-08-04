package main

import (
	"bytes"
	"io"
	"mime/multipart"
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

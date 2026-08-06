package main

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

func multipartUploadBody(t *testing.T, fields map[string]string, files []string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range files {
		part, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, "content-"+name); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, mw.FormDataContentType()
}

func uploadLocationMsg(rr *httptest.ResponseRecorder) string {
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	msg, _ := url.QueryUnescape(u.Query().Get("msg"))
	return msg
}

func TestHandleUploadSuccessAndDuplicates(t *testing.T) {
	app := newTestWebApp(t)
	internal := t.TempDir()
	app.roots["internal"] = internal
	app.roots["sd"] = t.TempDir()

	post := func(body *bytes.Buffer, ct, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", url, body)
		req.Header.Set("Content-Type", ct)
		rr := httptest.NewRecorder()
		app.handleUpload(rr, req)
		return rr
	}

	body, ct := multipartUploadBody(t, map[string]string{"target": "internal"}, []string{"book.fb2"})
	rr := post(body, ct, "/upload")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("success = %d body=%s", rr.Code, rr.Body.String())
	}
	if msg := uploadLocationMsg(rr); !strings.Contains(msg, "Загрузка завершена") {
		t.Fatalf("success msg = %q", msg)
	}
	if data, err := os.ReadFile(filepath.Join(internal, "book.fb2")); err != nil || string(data) != "content-book.fb2" {
		t.Fatalf("uploaded file: %q %v", data, err)
	}

	body, ct = multipartUploadBody(t, map[string]string{"target": "internal"}, []string{"a.fb2", "a.fb2"})
	rr = post(body, ct, "/upload")
	if rr.Code != http.StatusSeeOther || !strings.Contains(uploadLocationMsg(rr), "несколько раз") {
		t.Fatalf("dup = %d msg=%q", rr.Code, uploadLocationMsg(rr))
	}

	body, ct = multipartUploadBody(t, map[string]string{"target": "internal"}, []string{"book.fb2"})
	rr = post(body, ct, "/upload")
	if rr.Code != http.StatusSeeOther || !strings.Contains(uploadLocationMsg(rr), "уже существует") {
		t.Fatalf("exists = %d msg=%q", rr.Code, uploadLocationMsg(rr))
	}

	body, ct = multipartUploadBody(t, map[string]string{"target": "internal", "overwrite": "1"}, []string{"book.fb2"})
	rr = post(body, ct, "/upload")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("overwrite = %d body=%s", rr.Code, rr.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(internal, "book.fb2")); err != nil || string(data) != "content-book.fb2" {
		t.Fatalf("overwritten file: %q %v", data, err)
	}
}

func TestHandleUploadMoreBranches(t *testing.T) {
	app := newTestWebApp(t)
	internal := t.TempDir()
	app.roots["internal"] = internal
	app.roots["sd"] = t.TempDir()

	post := func(body *bytes.Buffer, ct, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", url, body)
		req.Header.Set("Content-Type", ct)
		rr := httptest.NewRecorder()
		app.handleUpload(rr, req)
		return rr
	}

	body, ct := multipartUploadBody(t, map[string]string{"other": "x"}, nil)
	rr := post(body, ct, "/upload")
	if rr.Code != http.StatusSeeOther || !strings.Contains(uploadLocationMsg(rr), "Файл не выбран") {
		t.Fatalf("no files = %d msg=%q", rr.Code, uploadLocationMsg(rr))
	}

	body, ct = multipartUploadBody(t, map[string]string{"target": "internal"}, []string{"big.fb2"})
	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", ct)
	req.ContentLength = 1 << 60
	rr = httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusSeeOther || uploadLocationMsg(rr) == "" {
		t.Fatalf("space exceeded = %d msg=%q", rr.Code, uploadLocationMsg(rr))
	}

	dirName := "conflict.fb2"
	if err := os.MkdirAll(filepath.Join(internal, dirName), 0755); err != nil {
		t.Fatal(err)
	}
	body, ct = multipartUploadBody(t, map[string]string{"target": "internal", "overwrite": "1"}, []string{dirName})
	rr = post(body, ct, "/upload")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("rename onto dir = %d body=%s", rr.Code, rr.Body.String())
	}

	body = &bytes.Buffer{}
	body.WriteString("--X\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a.fb2\"\r\n\r\ndata")
	req = httptest.NewRequest("POST", "/upload?p=internal", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	rr = httptest.NewRecorder()
	app.handleUpload(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("truncated body = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSaveUploadVariants(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("files", "book.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "data"); err != nil {
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
	dir := t.TempDir()

	hdr.Filename = ".."
	if err := saveUpload(dir, hdr, false); err == nil {
		t.Fatal("dotdot name accepted")
	}

	hdr.Filename = "ok.fb2"
	if err := saveUpload(dir, hdr, true); err != nil {
		t.Fatalf("saveUpload ok: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "conflict.fb2"), 0755); err != nil {
		t.Fatal(err)
	}
	hdr.Filename = "conflict.fb2"
	if err := saveUpload(dir, hdr, true); err == nil {
		t.Fatal("rename onto dir should fail")
	}
}

func TestEnsureRequestUploadSpaceVariants(t *testing.T) {
	dir := t.TempDir()
	if err := ensureRequestUploadSpace(dir, 1024); err != nil {
		t.Fatalf("enough space = %v", err)
	}
	if err := ensureRequestUploadSpace(dir, -1); err != nil {
		t.Fatalf("non-positive = %v", err)
	}
	if err := ensureRequestUploadSpace(filepath.Join(dir, "missing"), 100); err == nil {
		t.Fatal("missing dir accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteStreamTempVariants(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := writeStreamTemp(filepath.Join(dir, "missing"), strings.NewReader("x")); err == nil {
		t.Fatal("missing parent accepted")
	}
	if _, _, err := writeStreamTemp(dir, failingReader{}); err == nil {
		t.Fatal("failing reader accepted")
	}
	tmp, n, err := writeStreamTemp(dir, strings.NewReader("hello"))
	if err != nil || n != 5 {
		t.Fatalf("stream = %q %d %v", tmp, n, err)
	}
	defer os.Remove(tmp)
	data, _ := os.ReadFile(tmp)
	if string(data) != "hello" {
		t.Fatalf("stream content = %q", data)
	}
}

func TestCommitTempAutoRenameVariants(t *testing.T) {
	dir := t.TempDir()
	tmp, _, err := writeStreamTemp(dir, strings.NewReader("a"))
	if err != nil {
		t.Fatal(err)
	}
	name, err := commitTempAutoRename(dir, "book.txt", tmp)
	if err != nil || name != "book.txt" {
		t.Fatalf("rename = %q %v", name, err)
	}

	tmp2, _, _ := writeStreamTemp(dir, strings.NewReader("b"))
	name, err = commitTempAutoRename(dir, "book.txt", tmp2)
	if err != nil || name != "book (1).txt" {
		t.Fatalf("conflict rename = %q %v", name, err)
	}

	other := t.TempDir()
	tmp3, _, _ := writeStreamTemp(other, strings.NewReader("c"))
	name, err = commitTempAutoRename(dir, "new.txt", tmp3)
	if err != nil || name != "new.txt" {
		t.Fatalf("cross-dir rename = %q %v", name, err)
	}
}

func TestWriteMultipartTempOpenError(t *testing.T) {
	hdr := &multipart.FileHeader{Filename: "x.txt"}
	if _, err := writeMultipartTemp(t.TempDir(), hdr); err == nil {
		t.Fatal("open without parsed tmpfile accepted")
	}
}

func TestWriteStreamTempSpaceCheckError(t *testing.T) {
	old := diskSpaceAvailable
	diskSpaceAvailable = func(string) (uint64, error) { return 0, errors.New("statfs failed") }
	defer func() { diskSpaceAvailable = old }()
	dir := t.TempDir()
	_, _, err := writeStreamTemp(dir, strings.NewReader(strings.Repeat("a", 10<<20)))
	if err == nil || !strings.Contains(err.Error(), "failed to check disk space") {
		t.Fatalf("err = %v", err)
	}
}

func TestWriteStreamTempAbortsWhenDiskFull(t *testing.T) {
	old := diskSpaceAvailable
	diskSpaceAvailable = func(string) (uint64, error) { return uploadSafetyReserve, nil }
	defer func() { diskSpaceAvailable = old }()
	dir := t.TempDir()
	_, written, err := writeStreamTemp(dir, strings.NewReader(strings.Repeat("a", 10<<20)))
	if err == nil {
		t.Fatal("upload past free space accepted")
	}
	if !strings.Contains(err.Error(), "insufficient disk space") {
		t.Fatalf("err = %v", err)
	}
	if written == 0 {
		t.Fatal("expected partial write progress")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func prepareMobileTest(t *testing.T, mode string) (*App, string, string) {
	t.Helper()
	t.Cleanup(func() {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
	})
	if err := os.MkdirAll(filepath.Dir(mobileTokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	internal := filepath.Join(root, "internal")
	sd := filepath.Join(root, "sd")
	books := filepath.Join(internal, "Books")
	if err := os.MkdirAll(books, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sd, 0755); err != nil {
		t.Fatal(err)
	}
	app, err := newApp(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	app.roots["internal"] = internal
	app.roots["sd"] = sd
	token := "0123456789abcdef"
	record := MobileTokenRecord{Token: token, Target: "internal/Books", Mode: mode, Expires: time.Now().Add(time.Minute).Unix()}
	data, _ := json.Marshal([]MobileTokenRecord{record})
	if err := os.WriteFile(mobileTokenPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	return app, token, books
}

func mobileUploadRequest(t *testing.T, app *App, token, uploadID, name, contents string) (*httptest.ResponseRecorder, MobileUploadResult) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("upload_id", uploadID); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, contents); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	var result MobileUploadResult
	if rr.Code >= 200 && rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid upload response: %v body=%s", err, rr.Body.String())
		}
	}
	return rr, result
}

func mobileRawUploadRequest(t *testing.T, app *App, token, uploadID, name string, contents []byte) (*httptest.ResponseRecorder, MobileUploadResult) {
	t.Helper()
	u := "/m/" + token + "/upload?upload_id=" + url.QueryEscape(uploadID) + "&name=" + url.QueryEscape(name)
	req := httptest.NewRequest(http.MethodPost, u, bytes.NewReader(contents))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	var result MobileUploadResult
	if rr.Code >= 200 && rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("invalid raw upload response: %v body=%s", err, rr.Body.String())
		}
	}
	return rr, result
}

func TestMobilePageDoesNotRequireMainLoginAndIsPhoneNeutral(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Передача с телефона по QR-коду", "current-progress", "overall-progress", "Свободное место", "Безопасный режим", "badge-safe"} {
		if !strings.Contains(body, want) {
			t.Fatalf("mobile page does not contain %q", want)
		}
	}
	if strings.Contains(body, "name=\"password\"") {
		t.Fatal("mobile page unexpectedly requested the main password")
	}
	if strings.Contains(strings.ToLower(body), "iphone") || strings.Contains(strings.ToLower(body), "apple") {
		t.Fatal("mobile page is tied to a specific phone brand")
	}
	if !strings.Contains(body, "application/octet-stream") || !strings.Contains(body, "x.send(item.file)") {
		t.Fatal("mobile page does not use direct raw file streaming")
	}
	if strings.Contains(body, "new FormData()") {
		t.Fatal("mobile queue unexpectedly uses multipart FormData")
	}
}

func TestMobilePageShowsDefaultBadgeWhenTargetIsDefault(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	app.cfgMu.Lock()
	app.cfg.DefaultTarget = "internal/Books"
	app.cfgMu.Unlock()
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token, nil))
	body := rr.Body.String()
	if !strings.Contains(body, `class="badge badge-default"`) || !strings.Contains(body, "По умолчанию") {
		t.Fatalf("default badge missing:\n%s", body)
	}
}

func TestMobilePageOmitsDefaultBadgeForOtherTargets(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token, nil))
	if strings.Contains(rr.Body.String(), `class="badge badge-default"`) {
		t.Fatal("default badge shown although target is not the default")
	}
}

func TestSafeModeListsFilesButDoesNotExposeEditActions(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	if err := os.WriteFile(filepath.Join(books, "existing.epub"), []byte("book"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token, nil))
	body := rr.Body.String()
	if !strings.Contains(body, "existing.epub") {
		t.Fatal("safe mode does not show folder contents")
	}
	for _, forbidden := range []string{"/download?", "/delete", "/rename"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("safe mode exposed %q", forbidden)
		}
	}

	download := httptest.NewRecorder()
	app.routes().ServeHTTP(download, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download?name=existing.epub", nil))
	if download.Code != http.StatusForbidden {
		t.Fatalf("safe download status=%d", download.Code)
	}
}

func TestEditModeCanDownloadRenameAndDeleteOnlySelectedFolder(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	outside := filepath.Join(filepath.Dir(books), "outside.epub")
	if err := os.WriteFile(filepath.Join(books, "inside.epub"), []byte("inside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/m/"+token, nil))
	for _, want := range []string{"Режим редактирования", "badge-edit", "/download?", "/rename", "/delete", "/download-all", "/delete-all", "Скачать всё", "Удалить всё"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("edit page missing %q", want)
		}
	}
	if strings.Count(page.Body.String(), "class=\"file-row\"") != 1 {
		t.Fatalf("file row appears unexpected number of times: %d", strings.Count(page.Body.String(), "class=\"file-row\""))
	}

	dl := httptest.NewRecorder()
	app.routes().ServeHTTP(dl, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download?name=inside.epub", nil))
	if dl.Code != http.StatusOK || dl.Body.String() != "inside" {
		t.Fatalf("download status=%d body=%q", dl.Code, dl.Body.String())
	}
	blocked := httptest.NewRecorder()
	app.routes().ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download?name=../outside.epub", nil))
	if blocked.Code != http.StatusBadRequest {
		t.Fatalf("path escape status=%d", blocked.Code)
	}

	renameForm := url.Values{"old": {"inside.epub"}, "new": {"renamed.epub"}}
	renameReq := httptest.NewRequest(http.MethodPost, "/m/"+token+"/rename", strings.NewReader(renameForm.Encode()))
	renameReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	renameRR := httptest.NewRecorder()
	app.routes().ServeHTTP(renameRR, renameReq)
	if renameRR.Code != http.StatusSeeOther {
		t.Fatalf("rename status=%d body=%s", renameRR.Code, renameRR.Body.String())
	}
	if _, err := os.Stat(filepath.Join(books, "renamed.epub")); err != nil {
		t.Fatal(err)
	}

	deleteForm := url.Values{"name": {"renamed.epub"}}
	deleteReq := httptest.NewRequest(http.MethodPost, "/m/"+token+"/delete", strings.NewReader(deleteForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRR := httptest.NewRecorder()
	app.routes().ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusSeeOther {
		t.Fatalf("delete status=%d body=%s", deleteRR.Code, deleteRR.Body.String())
	}
	if _, err := os.Stat(filepath.Join(books, "renamed.epub")); !errorsIsNotExist(err) {
		t.Fatalf("file still exists: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
		t.Fatalf("outside file changed: %q %v", data, err)
	}
}

func TestRenameToSameNameIsNoOp(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	path := filepath.Join(books, "same.epub")
	if err := os.WriteFile(path, []byte("same"), 0644); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"old": {"same.epub"}, "new": {"same.epub"}}
	req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), url.QueryEscape("Имя не изменено")) {
		t.Fatalf("status=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "same" {
		t.Fatalf("file changed: %q %v", data, err)
	}
}

func TestDownloadAllCreatesArchiveFromSelectedFolderOnly(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	if err := os.WriteFile(filepath.Join(books, "one.epub"), []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "два.pdf"), []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(books, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "nested", "hidden.epub"), []byte("hidden"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download-all", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("status=%d type=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, file := range zr.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		got[file.Name] = string(data)
	}
	if len(got) != 2 || got["one.epub"] != "one" || got["два.pdf"] != "two" {
		t.Fatalf("archive contents=%v", got)
	}
}

func TestDeleteAllRemovesFilesButKeepsSubfolders(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	if err := os.WriteFile(filepath.Join(books, "one.epub"), []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "two.pdf"), []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(books, "nested")
	if err := os.Mkdir(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "keep.epub"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/m/"+token+"/delete-all", nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(books, "one.epub")); !os.IsNotExist(err) {
		t.Fatalf("one.epub still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(books, "two.pdf")); !os.IsNotExist(err) {
		t.Fatalf("two.pdf still exists: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(nested, "keep.epub")); err != nil || string(data) != "keep" {
		t.Fatalf("nested file changed: %q %v", data, err)
	}
}

func TestSafeModeBlocksBulkEditActions(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	if err := os.WriteFile(filepath.Join(books, "book.epub"), []byte("book"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/m/" + token + "/download-all"},
		{http.MethodPost, "/m/" + token + "/delete-all"},
	} {
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, rr.Code)
		}
	}
}

func errorsIsNotExist(err error) bool { return err != nil && os.IsNotExist(err) }

func TestRawMobileUploadWritesRussianNamedBook(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	name := "Искусство программирования. Том 2.pdf"
	payload := []byte("large-pdf-body")
	rr, result := mobileRawUploadRequest(t, app, token, "raw-russian-1", name, payload)
	if rr.Code != http.StatusOK || result.Status != "uploaded" || result.StoredAs != name {
		t.Fatalf("status=%d result=%+v body=%s", rr.Code, result, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(books, name))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("raw file=%q err=%v", got, err)
	}
}

func TestRawMobileUploadRetryIsIdempotent(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	payload := []byte("raw-data")
	firstRR, first := mobileRawUploadRequest(t, app, token, "raw-stable-id", "book.epub", payload)
	secondRR, second := mobileRawUploadRequest(t, app, token, "raw-stable-id", "book.epub", payload)
	if firstRR.Code != http.StatusOK || secondRR.Code != http.StatusOK || first != second {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	matches, err := filepath.Glob(filepath.Join(books, "book*.epub"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("raw retry created duplicates: %v err=%v", matches, err)
	}
}

func TestRawMobileLargeUploadDoesNotUseSystemTemp(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	missingTemp := filepath.Join(t.TempDir(), "missing-tmp")
	t.Setenv("TMPDIR", missingTemp)
	payload := bytes.Repeat([]byte("0123456789abcdef"), (6<<20)/16)
	rr, result := mobileRawUploadRequest(t, app, token, "raw-large-1", "large.pdf", payload)
	if rr.Code != http.StatusOK || result.Status != "uploaded" {
		t.Fatalf("status=%d result=%+v body=%s", rr.Code, result, rr.Body.String())
	}
	st, err := os.Stat(filepath.Join(books, "large.pdf"))
	if err != nil || st.Size() != int64(len(payload)) {
		t.Fatalf("size=%v err=%v", st, err)
	}
	if _, err := os.Stat(missingTemp); !errorsIsNotExist(err) {
		t.Fatalf("system temp unexpectedly used: %v", err)
	}
}

func TestQueueUploadSkipsSameNameAndSizeAndRenamesDifferentContent(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	if err := os.WriteFile(filepath.Join(books, "book.epub"), []byte("same"), 0644); err != nil {
		t.Fatal(err)
	}
	rr, result := mobileUploadRequest(t, app, token, "batch-1", "book.epub", "same")
	if rr.Code != http.StatusOK || result.Status != "skipped" || result.StoredAs != "book.epub" {
		t.Fatalf("skip response status=%d result=%+v body=%s", rr.Code, result, rr.Body.String())
	}
	rr, result = mobileUploadRequest(t, app, token, "batch-2", "book.epub", "different-size")
	if rr.Code != http.StatusOK || result.Status != "renamed" || result.StoredAs != "book (1).epub" {
		t.Fatalf("rename response status=%d result=%+v body=%s", rr.Code, result, rr.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(books, "book (1).epub")); err != nil || string(data) != "different-size" {
		t.Fatalf("renamed data=%q err=%v", data, err)
	}
}

func TestRetryWithSameUploadIDIsIdempotent(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	firstRR, first := mobileUploadRequest(t, app, token, "stable-id", "book.epub", "new-data")
	secondRR, second := mobileUploadRequest(t, app, token, "stable-id", "book.epub", "new-data")
	if firstRR.Code != http.StatusOK || secondRR.Code != http.StatusOK || first != second {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	matches, err := filepath.Glob(filepath.Join(books, "book*.epub"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("idempotent retry created duplicates: %v err=%v", matches, err)
	}
}

func TestRetryReceiptSurvivesManagerRestart(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	firstRR, first := mobileUploadRequest(t, app, token, "persistent-id", "restart.epub", "book-data")
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", firstRR.Code, firstRR.Body.String())
	}
	root := filepath.Dir(filepath.Dir(books))
	restarted, err := newApp(filepath.Join(root, "config-restarted.json"))
	if err != nil {
		t.Fatal(err)
	}
	restarted.roots["internal"] = filepath.Join(root, "internal")
	restarted.roots["sd"] = filepath.Join(root, "sd")
	secondRR, second := mobileUploadRequest(t, restarted, token, "persistent-id", "restart.epub", "book-data")
	if secondRR.Code != http.StatusOK || first != second {
		t.Fatalf("first=%+v second=%+v status=%d", first, second, secondRR.Code)
	}
	matches, err := filepath.Glob(filepath.Join(books, "restart*.epub"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("restart retry created duplicates: %v err=%v", matches, err)
	}
}

func TestMobileUploadRejectsNonBookFiles(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	rr, _ := mobileUploadRequest(t, app, token, "bad-file", "program.exe", "data")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "только файлы книг") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileLargeUploadDoesNotUseSystemTemp(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	missingTemp := filepath.Join(t.TempDir(), "missing-tmp")
	t.Setenv("TMPDIR", missingTemp)

	payload := bytes.Repeat([]byte("0123456789abcdef"), (6<<20)/16)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "large-book.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-WiFiFiles-Upload-ID", "large-upload-1")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	st, err := os.Stat(filepath.Join(books, "large-book.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != int64(len(payload)) {
		t.Fatalf("size=%d want=%d", st.Size(), len(payload))
	}
	if _, err := os.Stat(missingTemp); !errorsIsNotExist(err) {
		t.Fatalf("system temp unexpectedly used: %v", err)
	}
}

func writeMobileTokensForTest(t *testing.T, records ...MobileTokenRecord) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(mobileTokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(records)
	if err := os.WriteFile(mobileTokenPath, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMobileTokenQueueKeepsMultipleValidTokens(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
	})
	first := MobileTokenRecord{Token: "aaaaaaaaaaaaaaaa", Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(time.Minute).Unix()}
	second := MobileTokenRecord{Token: "bbbbbbbbbbbbbbbb", Target: "internal/Books", Mode: "edit", Expires: time.Now().Add(time.Minute).Unix()}
	writeMobileTokensForTest(t, first, second)
	r1, err := loadMobileToken(first.Token)
	if err != nil || r1.Mode != "safe" {
		t.Fatalf("first token err=%v record=%+v", err, r1)
	}
	r2, err := loadMobileToken(second.Token)
	if err != nil || r2.Mode != "edit" {
		t.Fatalf("second token err=%v record=%+v", err, r2)
	}
	records, err := readMobileTokens()
	if err != nil || len(records) != 2 {
		t.Fatalf("queue after loads: %d records err=%v", len(records), err)
	}
}

func TestMobileTokenQueueAddKeepsExistingAndPrunesExpired(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
	})
	old := MobileTokenRecord{Token: "cccccccccccccccc", Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(-time.Minute).Unix()}
	writeMobileTokensForTest(t, old)
	if _, err := loadMobileToken("cccccccccccccccc"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token err=%v", err)
	}
	if err := addMobileToken(MobileTokenRecord{Token: "dddddddddddddddd", Target: "sd/Books", Mode: "edit", Expires: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	records, err := readMobileTokens()
	if err != nil || len(records) != 1 || records[0].Token != "dddddddddddddddd" {
		t.Fatalf("queue after add: %+v err=%v", records, err)
	}
	if _, err := loadMobileToken("dddddddddddddddd"); err != nil {
		t.Fatalf("new token err=%v", err)
	}
}

func TestMobileTokenQueuePrunesExcessTokens(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
	})
	records := make([]MobileTokenRecord, 0, maxMobileTokens+2)
	for i := 0; i < maxMobileTokens+2; i++ {
		records = append(records, MobileTokenRecord{Token: fmt.Sprintf("%016d", i), Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(time.Hour).Unix()})
	}
	writeMobileTokensForTest(t, records...)
	queue, err := readMobileTokens()
	if err != nil || len(queue) != maxMobileTokens {
		t.Fatalf("queue size=%d err=%v want=%d", len(queue), err, maxMobileTokens)
	}
}

func TestMobileTokenQueueExpiredTokenDoesNotKillLiveReceipts(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
	})
	live := MobileTokenRecord{Token: "eeeeeeeeeeeeeeee", Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(time.Minute).Unix()}
	dead := MobileTokenRecord{Token: "ffffffffffffffff", Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(-time.Minute).Unix()}
	writeMobileTokensForTest(t, live, dead)
	if err := os.MkdirAll(filepath.Dir(mobileTokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMobileToken(dead.Token); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := loadMobileToken(live.Token); err != nil {
		t.Fatalf("live token dropped after expiry of another: %v", err)
	}
	records, err := readMobileTokens()
	if err != nil || len(records) != 1 || records[0].Token != live.Token {
		t.Fatalf("queue=%+v err=%v", records, err)
	}
}

func TestMobileUploadEnforcesPerTokenFileLimit(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	for i := 0; i < maxMobileFilesPerToken; i++ {
		rr, result := mobileUploadRequest(t, app, token, fmt.Sprintf("id-%03d", i), fmt.Sprintf("book%03d.epub", i), "contents")
		if rr.Code != http.StatusOK || result.Status != "uploaded" {
			t.Fatalf("upload %d: status=%d result=%+v", i, rr.Code, result)
		}
	}
	rr, result := mobileUploadRequest(t, app, token, "over-limit", "over.epub", "contents")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status=%d result=%+v", rr.Code, result)
	}
	if !strings.Contains(rr.Body.String(), "лимит") {
		t.Fatalf("over-limit body missing limit message: %s", rr.Body.String())
	}
	entries, err := os.ReadDir(books)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxMobileFilesPerToken {
		t.Fatalf("files on disk=%d want=%d", len(entries), maxMobileFilesPerToken)
	}
}

func TestMobileUploadRecordsRecentTargets(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	rr, result := mobileUploadRequest(t, app, token, "id-1", "book1.epub", "contents")
	if rr.Code != http.StatusOK || result.Status != "uploaded" {
		t.Fatalf("upload: status=%d result=%+v", rr.Code, result)
	}
	app.cfgMu.RLock()
	recent := append([]string(nil), app.cfg.RecentTargets...)
	app.cfgMu.RUnlock()
	if len(recent) != 1 || recent[0] != "internal/Books" {
		t.Fatalf("recent targets=%v want=[internal/Books]", recent)
	}
	rr, result = mobileUploadRequest(t, app, token, "id-2", "book2.epub", "contents")
	if rr.Code != http.StatusOK || result.Status != "uploaded" {
		t.Fatalf("second upload: status=%d result=%+v", rr.Code, result)
	}
	app.cfgMu.RLock()
	recent = append([]string(nil), app.cfg.RecentTargets...)
	app.cfgMu.RUnlock()
	if len(recent) != 1 || recent[0] != "internal/Books" {
		t.Fatalf("recent after dedup=%v want=[internal/Books]", recent)
	}
}

func TestRememberTargetDedupAndCap(t *testing.T) {
	app, err := newApp(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	app.rememberTarget("internal/Books")
	app.rememberTarget("sd/Books")
	app.rememberTarget("internal/Books")
	app.rememberTarget("internal/New")
	app.rememberTarget("sd/Other")
	app.rememberTarget("internal/Last")
	app.cfgMu.RLock()
	recent := append([]string(nil), app.cfg.RecentTargets...)
	app.cfgMu.RUnlock()
	want := []string{"internal/Last", "sd/Other", "internal/New", "internal/Books"}
	if len(recent) != len(want) {
		t.Fatalf("recent=%v want=%v", recent, want)
	}
	for i := range want {
		if recent[i] != want[i] {
			t.Fatalf("recent=%v want=%v", recent, want)
		}
	}
}

func TestSyncStateTargets(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "native_state.ini")
	original := "ip=192.168.1.5\nrunning=1\ndefault_target=internal/Books\nrecent1=internal/Books\nrecent2=sd/Books\n"
	if err := os.WriteFile(statePath, []byte(original), 0666); err != nil {
		t.Fatal(err)
	}
	syncStateTargets(dir, "sd/New", []string{"sd/New", "internal/Books"})
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	wantContains := []string{"ip=192.168.1.5", "default_target=sd/New", "recent1=sd/New", "recent2=internal/Books"}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Fatalf("state missing %q in:\n%s", w, got)
		}
	}
	if strings.Contains(got, "default_target=internal/Books") {
		t.Fatalf("state still has old default_target:\n%s", got)
	}
}

func TestSyncStateTargetsAppendsMissing(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "native_state.ini")
	if err := os.WriteFile(statePath, []byte("running=0\n"), 0666); err != nil {
		t.Fatal(err)
	}
	syncStateTargets(dir, "internal/Books", []string{"internal/Books"})
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "default_target=internal/Books") {
		t.Fatalf("state missing appended default_target:\n%s", got)
	}
	if !strings.Contains(got, "recent1=internal/Books") {
		t.Fatalf("state missing appended recent1:\n%s", got)
	}
}

func TestRefreshDynamicStateReplacesAndKeepsOtherKeys(t *testing.T) {
	original := "version=0.7.23\nrunning=1\nip=192.168.1.5\nfree_internal=12.3 GiB\nfree_sd=1.0 GiB\ndefault_target=internal/Books\n"
	got := string(refreshDynamicState([]byte(original), "10.0.0.2", "9.8 GiB", "512.0 MiB"))
	wantContains := []string{"version=0.7.23", "running=1", "ip=10.0.0.2", "free_internal=9.8 GiB", "free_sd=512.0 MiB", "default_target=internal/Books"}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Fatalf("state missing %q in:\n%s", w, got)
		}
	}
	for _, old := range []string{"ip=192.168.1.5", "free_internal=12.3 GiB", "free_sd=1.0 GiB"} {
		if strings.Contains(got, old) {
			t.Fatalf("state still has old value %q:\n%s", old, got)
		}
	}
}

func TestRefreshDynamicStateAppendsMissing(t *testing.T) {
	got := string(refreshDynamicState([]byte("running=1\nip=\n"), "10.0.0.2", "—", "—"))
	wantContains := []string{"running=1", "ip=10.0.0.2", "free_internal=—", "free_sd=—"}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Fatalf("state missing %q in:\n%s", w, got)
		}
	}
}

func TestFlushMobilePending(t *testing.T) {
	a := newTestAuthApp(t)
	a.mobilePending = make(map[string]map[string]struct{})
	a.mobileTimers = make(map[string]*time.Timer)
	if got := a.flushMobilePending("nope"); got != 0 {
		t.Fatalf("flush empty = %d, want 0", got)
	}
	a.mobileMu.Lock()
	a.mobilePending["tok"] = map[string]struct{}{"/mnt/ext1/Books/a.epub": {}, "/mnt/ext1/Books/b.fb2": {}}
	a.mobileMu.Unlock()
	if got := a.flushMobilePending("tok"); got != 2 {
		t.Fatalf("flush = %d, want 2", got)
	}
	a.mobileMu.Lock()
	defer a.mobileMu.Unlock()
	if len(a.mobilePending) != 0 {
		t.Fatalf("pending not cleared: %v", a.mobilePending)
	}
}

func TestMobileTextLocalization(t *testing.T) {
	if got := mobileText("ru", "рус", "eng", "frr", "dee"); got != "рус" {
		t.Fatalf("ru = %q", got)
	}
	if got := mobileText("EN", "рус", "eng", "frr", "dee"); got != "eng" {
		t.Fatalf("EN = %q", got)
	}
	if got := mobileText("fr", "рус", "eng", "frr", "dee"); got != "frr" {
		t.Fatalf("fr = %q", got)
	}
	if got := mobileText("de", "рус", "eng", "frr", "dee"); got != "dee" {
		t.Fatalf("de = %q", got)
	}
	if got := mobileText("xx", "рус", "eng", "frr", "dee"); got != "рус" {
		t.Fatalf("unknown = %q", got)
	}
}

func TestMobileTargetLabel(t *testing.T) {
	if got := mobileTargetLabel("ru", "/mnt/ext1/Books"); got == "" {
		t.Fatal("target label empty")
	}
}

func TestSafeUploadName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"book.fb2", "book.fb2"},
		{"../evil.fb2", "evil.fb2"},
		{"a\\b\\c.fb2", "c.fb2"},
		{"/abs/path.epub", "path.epub"},
	}
	for _, c := range cases {
		got, err := safeUploadName(c.in)
		if err != nil || got != c.want {
			t.Errorf("safeUploadName(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", ".", "..", "\x00evil.fb2"} {
		if _, err := safeUploadName(bad); err == nil {
			t.Errorf("safeUploadName(%q) accepted", bad)
		}
	}
}

func TestSaveUploadOverwriteSemantics(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "dup.fb2")
	if err := os.WriteFile(existing, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	hdr := newMultipartFileHeader(t, "dup.fb2", "new")
	if err := saveUpload(dir, hdr, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-overwrite = %v, want ErrExist", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "old" {
		t.Fatalf("file clobbered without overwrite: %q", data)
	}
	if err := saveUpload(dir, hdr, true); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "new" {
		t.Fatalf("overwrite content = %q", data)
	}
}

func newMultipartFileHeader(t *testing.T, name, content string) *multipart.FileHeader {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("files", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
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
	return req.MultipartForm.File["files"][0]
}

func TestRemoveMobileReceipts(t *testing.T) {
	if err := os.MkdirAll(filepath.Dir(mobileReceiptPath), 0700); err != nil {
		t.Fatal(err)
	}
	var backup []byte
	if data, err := os.ReadFile(mobileReceiptPath); err == nil {
		backup = data
	}
	t.Cleanup(func() {
		if backup == nil {
			_ = os.Remove(mobileReceiptPath)
		} else {
			_ = os.WriteFile(mobileReceiptPath, backup, 0600)
		}
	})

	store := mobileReceiptStore{Receipts: map[string]map[string]MobileUploadResult{
		"tok1": {"a.fb2": {}},
		"tok2": {"b.fb2": {}},
	}}
	data, _ := json.Marshal(store)
	if err := os.WriteFile(mobileReceiptPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	removeMobileReceipts("tok1")
	got, err := os.ReadFile(mobileReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var after mobileReceiptStore
	if err := json.Unmarshal(got, &after); err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Receipts["tok1"]; ok {
		t.Fatal("tok1 receipt survived")
	}
	if _, ok := after.Receipts["tok2"]; !ok {
		t.Fatal("tok2 receipt lost")
	}

	removeMobileReceipts("tok2")
	after = mobileReceiptStore{}
	if data, err := os.ReadFile(mobileReceiptPath); err == nil {
		_ = json.Unmarshal(data, &after)
	}
	if len(after.Receipts) != 0 {
		t.Fatalf("receipts not empty: %v", after.Receipts)
	}

	removeMobileReceipts("")
	removeMobileReceipts("nope")
	if err := os.WriteFile(mobileReceiptPath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	removeMobileReceipts("tok3")
}

func TestHandleMobileNegativePaths(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")

	req := httptest.NewRequest("GET", "/other/path", nil)
	rec := httptest.NewRecorder()
	app.handleMobile(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-m path = %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/m/nonexistent", nil)
	rec = httptest.NewRecorder()
	app.handleMobile(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("bad token = %d, want 410", rec.Code)
	}

	app.mobileMu.Lock()
	app.mobilePending = make(map[string]map[string]struct{})
	app.mobileTimers = make(map[string]*time.Timer)
	app.mobileMu.Unlock()
	if err := writeMobileTokens([]MobileTokenRecord{{Token: token, Target: "internal/system/x", Mode: "safe", Expires: time.Now().Add(time.Minute).Unix()}}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/m/"+token, nil)
	rec = httptest.NewRecorder()
	app.handleMobile(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("protected target = %d, want 400", rec.Code)
	}

	if err := writeMobileTokens([]MobileTokenRecord{{Token: token, Target: "internal/Books", Mode: "safe", Expires: time.Now().Add(time.Minute).Unix()}}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/m/"+token+"/fragment?x=1", nil)
	rec = httptest.NewRecorder()
	app.handleMobile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fragment = %d", rec.Code)
	}
	if rec.Header().Get("X-WiFiFiles-Free-Space") == "" {
		t.Fatal("fragment missing free-space header")
	}
}

func TestReadMultipartText(t *testing.T) {
	if got, err := readMultipartText(strings.NewReader("hello"), 10); err != nil || got != "hello" {
		t.Fatalf("short = (%q, %v)", got, err)
	}
	if _, err := readMultipartText(strings.NewReader("hello world"), 5); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestRawMobileUploadNegativeBranches(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")

	rr, _ := mobileRawUploadRequest(t, app, token, "", "book.fb2", []byte("data"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty upload id = %d", rr.Code)
	}

	rr, _ = mobileRawUploadRequest(t, app, token, strings.Repeat("x", 241), "book.fb2", []byte("data"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("long upload id = %d", rr.Code)
	}

	rr, _ = mobileRawUploadRequest(t, app, token, "raw-neg-1", "notes.md", []byte("data"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("non-book name = %d", rr.Code)
	}

	rr, _ = mobileRawUploadRequest(t, app, token, "raw-neg-2", "book.fb2", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d", rr.Code)
	}

	payload := []byte("same-content")
	firstRR, first := mobileRawUploadRequest(t, app, token, "raw-neg-3", "same.fb2", payload)
	secondRR, second := mobileRawUploadRequest(t, app, token, "raw-neg-4", "same.fb2", payload)
	if firstRR.Code != http.StatusOK || secondRR.Code != http.StatusOK {
		t.Fatalf("dup codes %d/%d", firstRR.Code, secondRR.Code)
	}
	if second.Status != "skipped" {
		t.Fatalf("duplicate result = %+v", second)
	}
	_ = first

	if err := os.WriteFile(filepath.Join(books, "noext"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	rr, _ = mobileRawUploadRequest(t, app, token, "raw-neg-5", "../..", []byte("data"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("traversal name = %d", rr.Code)
	}
}

func TestAddMobileTokenKeepsLiveAndCaps(t *testing.T) {
	if err := os.MkdirAll(filepath.Dir(mobileTokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	var backup []byte
	if data, err := os.ReadFile(mobileTokenPath); err == nil {
		backup = data
	}
	t.Cleanup(func() {
		if backup == nil {
			_ = os.Remove(mobileTokenPath)
		} else {
			_ = os.WriteFile(mobileTokenPath, backup, 0600)
		}
	})
	_ = os.Remove(mobileTokenPath + ".tmp")

	now := time.Now()
	if err := addMobileToken(MobileTokenRecord{Token: "tok-a", Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := addMobileToken(MobileTokenRecord{Token: "tok-a", Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	records, err := readMobileTokens()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range records {
		if r.Token == "tok-a" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dedupe failed, tok-a count = %d", count)
	}

	for i := 0; i < maxMobileTokens+5; i++ {
		tok := fmt.Sprintf("tok-%d", i)
		if err := addMobileToken(MobileTokenRecord{Token: tok, Expires: now.Add(time.Hour).Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	records, err = readMobileTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) > maxMobileTokens {
		t.Fatalf("token file over cap: %d > %d", len(records), maxMobileTokens)
	}

	if err := addMobileToken(MobileTokenRecord{Token: "expired", Expires: now.Add(-time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := addMobileToken(MobileTokenRecord{Token: "trigger-cleanup", Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	records, _ = readMobileTokens()
	for _, r := range records {
		if r.Token == "expired" {
			t.Fatal("expired token retained")
		}
	}
}

func TestHandleMobileListAction(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	if err := os.WriteFile(filepath.Join(books, "one.epub"), []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/list", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		Entries   []mobileFolderEntry `json:"entries"`
		FreeSpace string              `json:"free_space"`
		Mode      string              `json:"mode"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("list json: %v body=%s", err, rr.Body.String())
	}
	if payload.Mode != "safe" || len(payload.Entries) != 1 || payload.Entries[0].Name != "one.epub" || payload.FreeSpace == "" {
		t.Fatalf("list payload=%+v", payload)
	}
}

func TestHandleMobileFragmentFailsOnMissingTarget(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")
	if err := writeMobileTokens([]MobileTokenRecord{{Token: token, Target: "internal/Missing", Mode: "safe", Expires: time.Now().Add(time.Minute).Unix()}}); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/fragment", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("fragment missing dir = %d", rr.Code)
	}
}

func TestHandleMobileDeleteAndRenameNegatives(t *testing.T) {
	app, token, books := prepareMobileTest(t, "safe")
	if err := os.WriteFile(filepath.Join(books, "a.epub"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "b.epub"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, req)
		return rr
	}

	rr := post("/m/"+token+"/delete", url.Values{"name": {"a.epub"}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("safe delete = %d", rr.Code)
	}
	rr = post("/m/"+token+"/rename", url.Values{"old": {"a.epub"}, "new": {"b.epub"}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("safe rename = %d", rr.Code)
	}

	if err := writeMobileTokens([]MobileTokenRecord{{Token: token, Target: "internal/Books", Mode: "edit", Expires: time.Now().Add(time.Minute).Unix()}}); err != nil {
		t.Fatal(err)
	}

	rr = post("/m/"+token+"/delete", url.Values{"name": {"../escape"}})
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "err") {
		t.Fatalf("delete bad name = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = post("/m/"+token+"/delete", url.Values{"name": {"missing.epub"}})
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "err") {
		t.Fatalf("delete missing = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = post("/m/"+token+"/rename", url.Values{"old": {"missing.epub"}, "new": {"new.epub"}})
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "err") {
		t.Fatalf("rename missing old = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = post("/m/"+token+"/rename", url.Values{"old": {"a.epub"}, "new": {"b.epub"}})
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "err") {
		t.Fatalf("rename onto existing = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	if data, err := os.ReadFile(filepath.Join(books, "a.epub")); err != nil || string(data) != "a" {
		t.Fatalf("a.epub damaged: %q %v", data, err)
	}
}

func TestMobileDownloadAllEmptyAndMissing(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download-all", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("download-all empty = %d body=%s", rr.Code, rr.Body.String())
	}

	if err := os.RemoveAll(books); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download-all", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("download-all missing dir = %d", rr.Code)
	}

	if err := os.MkdirAll(books, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "book.fb2"), []byte("zip me"), 0644); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download-all", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("download-all zip = %d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "book.fb2" {
		t.Fatalf("zip parse err=%v files=%d", err, len(zr.File))
	}
}

func TestMobileEditActionsForbiddenInSafeMode(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "safe")

	for _, action := range []string{"delete", "delete-all", "rename"} {
		req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/"+action, nil)
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s = %d body=%s", action, rr.Code, rr.Body.String())
		}
	}
	for _, action := range []string{"download", "download-all"} {
		req := httptest.NewRequest(http.MethodGet, "/m/"+token+"/"+action, nil)
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s = %d body=%s", action, rr.Code, rr.Body.String())
		}
	}
}

func TestMobileRenameBranches(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")

	post := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, nil)
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, req)
		return rr
	}
	loc := func(rr *httptest.ResponseRecorder) string {
		u, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatalf("bad location %q: %v", rr.Header().Get("Location"), err)
		}
		return u.Query().Get("msg") + u.Query().Get("err")
	}

	rr := post("/m/" + token + "/rename?old=a.fb2&new=a.fb2")
	if rr.Code != http.StatusSeeOther || !strings.Contains(loc(rr), "не изменено") {
		t.Fatalf("rename same = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = post("/m/" + token + "/rename?old=missing.fb2&new=x.fb2")
	if rr.Code != http.StatusSeeOther || !strings.Contains(loc(rr), "не найден") {
		t.Fatalf("rename missing = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	if err := os.WriteFile(filepath.Join(books, "a.fb2"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "b.fb2"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	rr = post("/m/" + token + "/rename?old=a.fb2&new=b.fb2")
	if rr.Code != http.StatusSeeOther || !strings.Contains(loc(rr), "уже существует") {
		t.Fatalf("rename conflict = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = post("/m/" + token + "/rename?old=a.fb2&new=c.fb2")
	if rr.Code != http.StatusSeeOther || !strings.Contains(loc(rr), "Переименовано") {
		t.Fatalf("rename ok = %d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(books, "c.fb2")); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
}

func TestMobileUploadMultipartNegativeBranches(t *testing.T) {

	app, token, _ := prepareMobileTest(t, "safe")

	post := func(body io.Reader, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, req)
		return rr
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "book.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	rr := post(&body, mw.FormDataContentType())
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "идентификатор") {
		t.Fatalf("multipart without upload_id = %d body=%s", rr.Code, rr.Body.String())
	}

	body.Reset()
	mw = multipart.NewWriter(&body)
	if err := mw.WriteField("upload_id", "two-files"); err != nil {
		t.Fatal(err)
	}
	first, err := mw.CreateFormFile("file", "one.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	second, err := mw.CreateFormFile("file", "two.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	rr = post(&body, mw.FormDataContentType())
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "по одному файлу") {
		t.Fatalf("two files = %d body=%s", rr.Code, rr.Body.String())
	}

	body.Reset()
	mw = multipart.NewWriter(&body)
	if err := mw.WriteField("upload_id", strings.Repeat("x", 241)); err != nil {
		t.Fatal(err)
	}
	part, err = mw.CreateFormFile("file", "book.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	rr = post(&body, mw.FormDataContentType())
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversize multipart upload_id = %d body=%s", rr.Code, rr.Body.String())
	}

	body.Reset()
	mw = multipart.NewWriter(&body)
	if err := mw.WriteField("upload_id", "no-file"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	rr = post(&body, mw.FormDataContentType())
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Файл не выбран") {
		t.Fatalf("no file part = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = post(bytes.NewReader([]byte("raw")), "application/octet-stream")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("non-multipart without name = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReadMobileTokensVariants(t *testing.T) {
	backup, backupErr := os.ReadFile(mobileTokenPath)
	t.Cleanup(func() {
		if backupErr == nil {
			_ = os.WriteFile(mobileTokenPath, backup, 0600)
		} else {
			_ = os.Remove(mobileTokenPath)
		}
	})

	if _, err := readMobileTokens(); err == nil {
		t.Fatal("missing token file accepted")
	}

	if err := os.WriteFile(mobileTokenPath, []byte(`{"token":"single-token","expires":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readMobileTokens()
	if err != nil || len(got) != 1 || got[0].Token != "single-token" {
		t.Fatalf("single object = %+v err=%v", got, err)
	}

	recs := make([]MobileTokenRecord, 0, maxMobileTokens+5)
	for i := 0; i < maxMobileTokens+5; i++ {
		recs = append(recs, MobileTokenRecord{Token: fmt.Sprintf("tok-%d", i)})
	}
	data, _ := json.Marshal(recs)
	if err := os.WriteFile(mobileTokenPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = readMobileTokens()
	if err != nil || len(got) != maxMobileTokens {
		t.Fatalf("capped = %d err=%v", len(got), err)
	}
	if got[0].Token != "tok-5" || got[len(got)-1].Token != fmt.Sprintf("tok-%d", maxMobileTokens+4) {
		t.Fatalf("capped window = %s..%s", got[0].Token, got[len(got)-1].Token)
	}

	if err := os.WriteFile(mobileTokenPath, []byte("{bad json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMobileTokens(); err == nil {
		t.Fatal("garbage token file accepted")
	}
}

func TestStrictMobileNameVariants(t *testing.T) {
	for _, name := range []string{"book.fb2", "книга.pdf", "a b.txt", "a-b_c.txt"} {
		if got, err := strictMobileName(name); err != nil || got != name {
			t.Fatalf("valid %q = %q %v", name, got, err)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", "..\\x", "x\x00y", "  ", "dir/name"} {
		if _, err := strictMobileName(name); err == nil {
			t.Fatalf("invalid %q accepted", name)
		}
	}
}

func TestMobileEntriesVariants(t *testing.T) {
	app := newTestAuthApp(t)
	dir := t.TempDir()
	if _, err := app.mobileEntries(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
	if err := os.MkdirAll(filepath.Join(dir, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z.txt"), []byte("123"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "z.txt"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	entries, err := app.mobileEntries(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Name != "Books" || !entries[0].IsDir {
		t.Fatalf("dir first = %+v", entries[0])
	}
	if entries[1].Name != "z.txt" || entries[1].Size == "" || entries[1].ModTime == "" {
		t.Fatalf("file = %+v", entries[1])
	}
}

func TestMobileReceiptDiskFallback(t *testing.T) {
	app := newTestAuthApp(t)
	backup, berr := os.ReadFile(mobileReceiptPath)
	t.Cleanup(func() {
		if berr == nil {
			_ = os.WriteFile(mobileReceiptPath, backup, 0600)
		} else {
			_ = os.Remove(mobileReceiptPath)
		}
	})
	app.mobileReceipts = make(map[string]map[string]MobileUploadResult)

	if app.mobileUploadCount("tok") != 0 {
		t.Fatal("count without file != 0")
	}

	store := mobileReceiptStore{Receipts: map[string]map[string]MobileUploadResult{
		"tok": {"up1": {Status: "uploaded"}},
	}}
	data, _ := json.Marshal(store)
	if err := os.WriteFile(mobileReceiptPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if got := app.mobileUploadCount("tok"); got != 1 {
		t.Fatalf("count = %d", got)
	}
	if got, ok := app.getMobileReceipt("tok", "up1"); !ok || got.Status != "uploaded" {
		t.Fatalf("receipt = %+v %v", got, ok)
	}
	if _, ok := app.getMobileReceipt("tok", "nope"); ok {
		t.Fatal("missing upload id accepted")
	}

	app.saveMobileReceipt("tok", "up2", MobileUploadResult{Status: "uploaded"})
	if got := app.mobileUploadCount("tok"); got != 2 {
		t.Fatalf("saved count = %d", got)
	}

	if err := os.WriteFile(mobileReceiptPath, []byte("{bad"), 0600); err != nil {
		t.Fatal(err)
	}
	app.mobileReceipts = nil
	app.mobileReceipts = make(map[string]map[string]MobileUploadResult)
	if app.mobileUploadCount("tok2") != 0 {
		t.Fatal("count with garbage != 0")
	}
	if _, ok := app.getMobileReceipt("tok2", "x"); ok {
		t.Fatal("receipt with garbage ok")
	}
}

func TestMobileVisibleAndDeleteAll(t *testing.T) {
	app := newTestAuthApp(t)
	dir := t.TempDir()
	for _, name := range []string{"b.txt", "a.txt", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "a.txt"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	files, err := mobileVisibleFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].name != "a.txt" || files[1].name != "b.txt" {
		t.Fatalf("visible = %+v", files)
	}

	deleted, err := app.deleteAllMobileFiles(dir)
	if err != nil || deleted != 2 {
		t.Fatalf("deleted = %d %v", deleted, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("a.txt remains")
	}
	if _, err := os.Stat(filepath.Join(dir, ".hidden")); err != nil {
		t.Fatal(".hidden should remain")
	}
}

func TestDeleteAllMobileFilesMissingDir(t *testing.T) {
	app := newTestAuthApp(t)
	deleted, err := app.deleteAllMobileFiles(filepath.Join(t.TempDir(), "nope"))
	if err == nil || deleted != 0 {
		t.Fatalf("missing dir: deleted=%d err=%v", deleted, err)
	}
}

func TestHandleMobileDownloadVariants(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	book := filepath.Join(books, "inside.epub")
	if err := os.WriteFile(book, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(book, filepath.Join(books, "link.epub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(books, "adir"), 0755); err != nil {
		t.Fatal(err)
	}

	get := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/download"+query, nil))
		return rr
	}

	if rr := get("?name=../outside.epub"); rr.Code != http.StatusBadRequest {
		t.Fatalf("traversal name = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := get("?name=nope.epub"); rr.Code != http.StatusNotFound {
		t.Fatalf("missing name = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := get("?name=adir"); rr.Code != http.StatusNotFound {
		t.Fatalf("dir name = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := get("?name=link.epub"); rr.Code != http.StatusNotFound {
		t.Fatalf("symlink name = %d body=%s", rr.Code, rr.Body.String())
	}

	rr := get("?name=inside.epub")
	if rr.Code != http.StatusOK || rr.Body.String() != "content" {
		t.Fatalf("ok = %d body=%q", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "inside.epub") {
		t.Fatalf("content-disposition = %q", cd)
	}
}

func TestMobileFinishFlushAndMethodNotAllowed(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	if err := os.WriteFile(filepath.Join(books, "b.epub"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/m/"+token+"/finish", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("finish = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/m/"+token+"/badaction", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("badaction = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileRawUploadSuccessWithHeader(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")

	u := "/m/" + token + "/upload?name=" + url.QueryEscape("raw.fb2")
	req := httptest.NewRequest(http.MethodPost, u, strings.NewReader("rawdata"))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-WiFiFiles-Upload-ID", "hdr-id-1")
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	var result MobileUploadResult
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &result) != nil || result.Status != "uploaded" {
		t.Fatalf("raw upload = %d body=%s", rr.Code, rr.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(books, "raw.fb2")); err != nil || string(data) != "rawdata" {
		t.Fatalf("raw file: %q %v", data, err)
	}

	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, u+"&upload_id=hdr-id-1", strings.NewReader("rawdata")))
	if rr.Code != http.StatusOK {
		t.Fatalf("raw receipt retry = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/m/"+token+"/finish", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"indexed":1`) {
		t.Fatalf("finish after upload = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileUploadRenamedAndOversizeQueryID(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")
	dup := filepath.Join(books, "dup.fb2")
	if err := os.WriteFile(dup, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	rr, result := mobileUploadRequest(t, app, token, "r-1", "dup.fb2", "new-content")
	if rr.Code != http.StatusOK || result.Status != "renamed" {
		t.Fatalf("rename upload = %d %+v body=%s", rr.Code, result, rr.Body.String())
	}
	if result.StoredAs == "dup.fb2" {
		t.Fatalf("rename kept original name: %+v", result)
	}

	rr, _ = mobileUploadRequest(t, app, token, strings.Repeat("x", 241), "ok.fb2", "data")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversize query upload_id = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileRawUploadSpaceExceeded(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "edit")

	u := "/m/" + token + "/upload?upload_id=s-1&name=" + url.QueryEscape("big.fb2")
	req := httptest.NewRequest(http.MethodPost, u, strings.NewReader("data"))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = 1 << 60
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 507 {
		t.Fatalf("space exceeded = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileUploadOneUnknownFieldAndMultipartID(t *testing.T) {
	app, token, books := prepareMobileTest(t, "edit")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("other", "x"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("upload_id", "multi-id"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "m.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("m")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("multipart with unknown field = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(books, "m.fb2")); err != nil {
		t.Fatalf("multipart file missing: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload?upload_id=multi-id", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("multipart receipt retry = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileUploadOneMoreBranches(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "edit")

	rr, _ := mobileUploadRequest(t, app, token, "", "ok.fb2", "data")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty multipart upload_id = %d body=%s", rr.Code, rr.Body.String())
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("upload_id", "ignored-in-field"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "hdr.fb2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "data"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload?upload_id="+strings.Repeat("x", 241), &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize query upload_id multipart = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload?name=ignored", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-WiFiFiles-Upload-ID", "hdr-id")
	rec = httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("header + multipart upload_id = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.ContentLength = 1 << 60
	rec = httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	if rec.Code != 507 {
		t.Fatalf("multipart space exceeded = %d body=%s", rec.Code, rec.Body.String())
	}

	truncated := "--X\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\ns-9\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cut.fb2\"\r\nContent-Type: application/octet-stream\r\n\r\npartial"
	req = httptest.NewRequest(http.MethodPost, "/m/"+token+"/upload", strings.NewReader(truncated))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	rec = httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("truncated multipart = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMobileUploadLimitReached(t *testing.T) {
	app, token, _ := prepareMobileTest(t, "edit")
	app.mobileMu.Lock()
	results := make(map[string]MobileUploadResult)
	for i := 0; i < maxMobileFilesPerToken; i++ {
		results[fmt.Sprintf("id-%d", i)] = MobileUploadResult{Status: "uploaded"}
	}
	app.mobileReceipts[token] = results
	app.mobileMu.Unlock()

	rr, _ := mobileRawUploadRequest(t, app, token, "limit-raw", "one.fb2", []byte("x"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("raw over limit = %d body=%s", rr.Code, rr.Body.String())
	}

	rr, _ = mobileUploadRequest(t, app, token, "limit-mp", "two.fb2", "data")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("multipart over limit = %d body=%s", rr.Code, rr.Body.String())
	}
}

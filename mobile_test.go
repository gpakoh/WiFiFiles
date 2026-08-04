package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
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
	for _, want := range []string{"Передача с телефона по QR-коду", "current-progress", "overall-progress", "Свободное место", "Безопасный режим"} {
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
	for _, want := range []string{"Режим редактирования", "/download?", "/rename", "/delete", "/download-all", "/delete-all", "Скачать всё", "Удалить всё"} {
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

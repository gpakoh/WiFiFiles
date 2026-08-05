package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestDAV(t *testing.T) (*DAVServer, string) {
	t.Helper()
	root := t.TempDir()
	internal := filepath.Join(root, "internal")
	sd := filepath.Join(root, "sd")
	if err := os.MkdirAll(internal, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sd, 0755); err != nil {
		t.Fatal(err)
	}
	salt := "00112233445566778899aabbccddeeff"
	app := &App{
		cfg: Config{
			ConfigVersion:   5,
			Username:        "pocketbook",
			PasswordSalt:    salt,
			PasswordHash:    passwordHash(salt, "650wifi"),
			DAVDigestHA1:    digestHA1("pocketbook", "650wifi"),
			HTTPEnabled:     true,
			HTTPPort:        8080,
			InternalEnabled: true,
			SDEnabled:       true,
		},
		sessions: make(map[string]time.Time),
		roots:    map[string]string{"internal": internal, "sd": sd},
	}
	return newDAVServer(app), internal
}

func davRequest(t *testing.T, handler http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("pocketbook:650wifi")))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestWebDAVFileLifecycle(t *testing.T) {
	dav, internal := newTestDAV(t)

	rr := davRequest(t, dav, "PROPFIND", "http://pb/dav/", "", map[string]string{"Depth": "1"})
	if rr.Code != 207 || !strings.Contains(rr.Body.String(), "INTERNAL") {
		t.Fatalf("root propfind: %d %s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "MKCOL", "http://pb/dav/internal/Books", "", nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("mkcol: %d %s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/Books/test.txt", "hello", nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, http.MethodGet, "http://pb/dav/internal/Books/test.txt", "", nil)
	data, _ := io.ReadAll(rr.Result().Body)
	if rr.Code != http.StatusOK || string(data) != "hello" {
		t.Fatalf("get: %d %q", rr.Code, data)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/test.txt", "", map[string]string{"Destination": "http://pb/dav/internal/Books/renamed.txt"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("move: %d %s", rr.Code, rr.Body.String())
	}

	if _, err := os.Stat(filepath.Join(internal, "Books", "renamed.txt")); err != nil {
		t.Fatal(err)
	}

	rr = davRequest(t, dav, http.MethodDelete, "http://pb/dav/internal/Books", "", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(internal, "Books")); !os.IsNotExist(err) {
		t.Fatalf("directory still exists: %v", err)
	}
}

func TestWebDAVProtectsSystemDirectory(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "system"), 0755); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/system/secret.txt", "x", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVRequiresAuthentication(t *testing.T) {
	dav, _ := newTestDAV(t)
	req := httptest.NewRequest("PROPFIND", "http://pb/dav/", nil)
	req.Header.Set("Depth", "0")
	rr := httptest.NewRecorder()
	dav.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Digest ") {
		t.Fatalf("missing digest challenge: %#v", rr.Header())
	}
}

func TestWebDAVDigestAuthentication(t *testing.T) {
	dav, _ := newTestDAV(t)
	first := httptest.NewRequest("PROPFIND", "http://pb/dav/", nil)
	first.Header.Set("Depth", "0")
	firstRR := httptest.NewRecorder()
	dav.ServeHTTP(firstRR, first)
	if firstRR.Code != http.StatusUnauthorized {
		t.Fatalf("challenge: %d", firstRR.Code)
	}
	var challenge string
	for _, value := range firstRR.Header().Values("WWW-Authenticate") {
		if strings.HasPrefix(value, "Digest ") {
			challenge = value
			break
		}
	}
	values := parseDigestHeader(challenge)
	nonce := values["nonce"]
	if nonce == "" {
		t.Fatalf("nonce missing in %q", challenge)
	}

	method, uri := "PROPFIND", "/dav/"
	nc, cnonce := "00000001", "abcdef0123456789"
	ha1 := digestHA1("pocketbook", "650wifi")
	ha2 := md5Hex(method + ":" + uri)
	response := md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	authorization := `Digest username="pocketbook", realm="WiFiFiles", nonce="` + nonce + `", uri="` + uri + `", algorithm=MD5, response="` + response + `", qop=auth, nc=` + nc + `, cnonce="` + cnonce + `"`

	req := httptest.NewRequest(method, "http://pb"+uri, nil)
	req.Header.Set("Depth", "0")
	req.Header.Set("Authorization", authorization)
	rr := httptest.NewRecorder()
	dav.ServeHTTP(rr, req)
	if rr.Code != 207 {
		t.Fatalf("digest request: %d %s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVLockUnlock(t *testing.T) {
	dav, _ := newTestDAV(t)
	body := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>test</D:href></D:owner></D:lockinfo>`
	rr := davRequest(t, dav, "LOCK", "http://pb/dav/internal/locked.txt", body, map[string]string{"Timeout": "Second-600"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("lock: %d %s", rr.Code, rr.Body.String())
	}
	token := rr.Header().Get("Lock-Token")
	if token == "" {
		t.Fatal("lock token missing")
	}
	rr = davRequest(t, dav, "UNLOCK", "http://pb/dav/internal/locked.txt", "", map[string]string{"Lock-Token": token})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("unlock: %d %s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVWindowsProbeWithoutAuth(t *testing.T) {
	dav, _ := newTestDAV(t)
	for _, target := range []string{"http://pb/dav", "http://pb/dav/"} {
		req := httptest.NewRequest(http.MethodOptions, target, nil)
		req.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.26100")
		rr := httptest.NewRecorder()
		dav.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("OPTIONS %s: got %d, body=%q", target, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("DAV") == "" || rr.Header().Get("MS-Author-Via") != "DAV" {
			t.Fatalf("OPTIONS %s: missing DAV headers: %#v", target, rr.Header())
		}
	}
}

func TestWebDAVNoRedirectAtDavWithoutSlash(t *testing.T) {
	dav, _ := newTestDAV(t)
	req := httptest.NewRequest("PROPFIND", "http://pb/dav", nil)
	req.Header.Set("Depth", "0")
	rr := httptest.NewRecorder()
	dav.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401; location=%q body=%q", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	if rr.Header().Get("Location") != "" {
		t.Fatalf("unexpected redirect location %q", rr.Header().Get("Location"))
	}
	if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Digest ") {
		t.Fatalf("digest challenge missing: %#v", rr.Header())
	}
	if strings.Contains(strings.ToLower(rr.Header().Get("WWW-Authenticate")), "basic") {
		t.Fatalf("basic challenge must not be advertised over HTTP")
	}
}

func TestWebDAVBrowserProvidesFullEditingUI(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "Books", "Series"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "book.pdf"), []byte("pdf"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, http.MethodGet, "http://pb/dav/internal/Books/", "", map[string]string{
		"Accept":     "text/html,application/xhtml+xml",
		"User-Agent": "Mozilla/5.0",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("browser get: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Полный доступ", "Загрузить файлы", "Создать папку", "Переименовать", "Переместить", "Копировать", "Удалить", "Свободно:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("browser UI missing %q in %s", want, body)
		}
	}
	if !strings.Contains(body, "book.pdf") || !strings.Contains(body, "Series") {
		t.Fatalf("browser UI does not list files: %s", body)
	}
}

func TestWebDAVPutIfNoneMatchPreventsOverwrite(t *testing.T) {
	dav, internal := newTestDAV(t)
	path := filepath.Join(internal, "existing.txt")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/existing.txt", "new", map[string]string{"If-None-Match": "*"})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("got %d, body=%q", rr.Code, rr.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("existing file was overwritten: %q", data)
	}
}

func TestWebDAVPropfindDepthInfinity(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "Books", "Nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "Nested", "deep.epub"), []byte("book"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/", "", map[string]string{"Depth": "infinity"})
	if rr.Code != 207 {
		t.Fatalf("propfind infinity: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Nested") || !strings.Contains(body, "deep.epub") {
		t.Fatalf("nested resources missing: %s", body)
	}
}

func TestWebDAVCopyAndSafeOverwrite(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "source.txt"), []byte("source"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "target.txt"), []byte("target"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "COPY", "http://pb/dav/internal/Books/source.txt", "", map[string]string{
		"Destination": "http://pb/dav/internal/Books/target.txt",
		"Overwrite":   "F",
	})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("copy without overwrite: %d %s", rr.Code, rr.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(internal, "Books", "target.txt"))
	if err != nil || string(data) != "target" {
		t.Fatalf("target changed after rejected copy: %q %v", data, err)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books/source.txt", "", map[string]string{
		"Destination": "http://pb/dav/internal/Books/target.txt",
		"Overwrite":   "T",
	})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("copy overwrite: %d %s", rr.Code, rr.Body.String())
	}
	data, err = os.ReadFile(filepath.Join(internal, "Books", "target.txt"))
	if err != nil || string(data) != "source" {
		t.Fatalf("target not replaced: %q %v", data, err)
	}
}

func TestWebDAVMoveToSamePathIsNoop(t *testing.T) {
	dav, internal := newTestDAV(t)
	path := filepath.Join(internal, "same.txt")
	if err := os.WriteFile(path, []byte("same"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, "MOVE", "http://pb/dav/internal/same.txt", "", map[string]string{
		"Destination": "http://pb/dav/internal/same.txt",
		"Overwrite":   "T",
	})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("same-path move: %d %s", rr.Code, rr.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "same" {
		t.Fatalf("same-path move damaged file: %q %v", data, err)
	}
}

func TestWebDAVDigestAcceptsWindowsTrailingSlashNormalization(t *testing.T) {
	dav, _ := newTestDAV(t)
	first := httptest.NewRequest("PROPFIND", "http://pb/dav/internal", nil)
	first.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19044")
	first.Header.Set("Depth", "0")
	firstRR := httptest.NewRecorder()
	dav.ServeHTTP(firstRR, first)
	if firstRR.Code != http.StatusUnauthorized {
		t.Fatalf("challenge: %d %q", firstRR.Code, firstRR.Body.String())
	}
	challenge := parseDigestHeader(firstRR.Header().Get("WWW-Authenticate"))
	nonce := challenge["nonce"]
	if nonce == "" {
		t.Fatalf("nonce missing")
	}
	method, digestURI := "PROPFIND", "/dav/internal"
	nc, cnonce := "00000001", "windows-slash"
	ha1 := digestHA1("pocketbook", "650wifi")
	ha2 := md5Hex(method + ":" + digestURI)
	response := md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	authorization := `Digest username="pocketbook", realm="WiFiFiles", nonce="` + nonce + `", uri="` + digestURI + `", algorithm=MD5, response="` + response + `", qop=auth, nc=` + nc + `, cnonce="` + cnonce + `"`

	req := httptest.NewRequest(method, "http://pb/dav/internal/", nil)
	req.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19044")
	req.Header.Set("Depth", "0")
	req.Header.Set("Authorization", authorization)
	rr := httptest.NewRecorder()
	dav.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("authenticated slash-normalized request: %d %q", rr.Code, rr.Body.String())
	}
}

func TestWebDAVWindowsRootRequiresAuthentication(t *testing.T) {
	dav, _ := newTestDAV(t)
	for _, tc := range []struct {
		target string
		depth  string
	}{
		{"http://pb/dav", "0"},
		{"http://pb/dav", "1"},
		{"http://pb/dav/", "0"},
		{"http://pb/dav/", "1"},
	} {
		req := httptest.NewRequest("PROPFIND", tc.target, nil)
		req.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19044")
		req.Header.Set("Depth", tc.depth)
		rr := httptest.NewRecorder()
		dav.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("PROPFIND %s depth=%q: got %d body=%q", tc.target, tc.depth, rr.Code, rr.Body.String())
		}
		if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Digest ") {
			t.Fatalf("PROPFIND %s: missing Digest challenge: %#v", tc.target, rr.Header())
		}
		if rr.Header().Get("Content-Length") != "0" || rr.Body.Len() != 0 {
			t.Fatalf("PROPFIND %s: 401 must have empty body, length=%q body=%q", tc.target, rr.Header().Get("Content-Length"), rr.Body.String())
		}
	}
}

func TestWebDAVWindowsVolumeRequiresAuthenticationAtEveryDepth(t *testing.T) {
	dav, _ := newTestDAV(t)
	for _, target := range []string{"http://pb/dav/internal", "http://pb/dav/internal/", "http://pb/dav/sd", "http://pb/dav/sd/"} {
		for _, depth := range []string{"0", "1", ""} {
			req := httptest.NewRequest("PROPFIND", target, nil)
			req.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19044")
			if depth != "" {
				req.Header.Set("Depth", depth)
			}
			rr := httptest.NewRecorder()
			dav.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("PROPFIND %s depth=%q: got %d body=%q", target, depth, rr.Code, rr.Body.String())
			}
			if !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Digest ") {
				t.Fatalf("PROPFIND %s depth=%q: missing Digest challenge", target, depth)
			}
		}
	}
}

func TestWebDAVWindowsShellMetadataReturnsNotFoundWithoutAuth(t *testing.T) {
	dav, _ := newTestDAV(t)
	for _, target := range []string{
		"http://pb/dav/desktop.ini",
		"http://pb/dav/internal/folder.jpg",
		"http://pb/dav/internal/Thumbs.db",
		"http://pb/dav/sd/autorun.inf",
	} {
		req := httptest.NewRequest("PROPFIND", target, nil)
		req.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19044")
		req.Header.Set("Depth", "0")
		rr := httptest.NewRecorder()
		dav.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d body=%q", target, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s: shell metadata must not trigger authentication", target)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("%s: 404 body must be empty, got %q", target, rr.Body.String())
		}
	}
}

func TestWebDAVWindowsAuthenticatedRootAndVolumeListing(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.WriteFile(filepath.Join(internal, "book.epub"), []byte("book"), 0644); err != nil {
		t.Fatal(err)
	}
	ua := "Microsoft-WebDAV-MiniRedir/10.0.19044"

	challengeReq := httptest.NewRequest("PROPFIND", "http://pb/dav", nil)
	challengeReq.Header.Set("User-Agent", ua)
	challengeReq.Header.Set("Depth", "1")
	challengeRR := httptest.NewRecorder()
	dav.ServeHTTP(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusUnauthorized {
		t.Fatalf("root challenge: %d %q", challengeRR.Code, challengeRR.Body.String())
	}
	challenge := parseDigestHeader(challengeRR.Header().Get("WWW-Authenticate"))
	nonce := challenge["nonce"]
	if nonce == "" {
		t.Fatalf("nonce missing: %q", challengeRR.Header().Get("WWW-Authenticate"))
	}

	makeAuth := func(method, uri string) string {
		nc, cnonce := "00000001", "windowsclient"
		ha1 := digestHA1("pocketbook", "650wifi")
		ha2 := md5Hex(method + ":" + uri)
		response := md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
		return `Digest username="pocketbook", realm="WiFiFiles", nonce="` + nonce + `", uri="` + uri + `", algorithm=MD5, response="` + response + `", qop=auth, nc=` + nc + `, cnonce="` + cnonce + `"`
	}

	root := httptest.NewRequest("PROPFIND", "http://pb/dav", nil)
	root.Header.Set("User-Agent", ua)
	root.Header.Set("Depth", "1")
	root.Header.Set("Authorization", makeAuth("PROPFIND", "/dav"))
	rootRR := httptest.NewRecorder()
	dav.ServeHTTP(rootRR, root)
	if rootRR.Code != http.StatusMultiStatus {
		t.Fatalf("authenticated root: %d %q", rootRR.Code, rootRR.Body.String())
	}
	if !strings.Contains(rootRR.Body.String(), "INTERNAL") || !strings.Contains(rootRR.Body.String(), "SDCARD") {
		t.Fatalf("authenticated root missing volumes: %s", rootRR.Body.String())
	}
	if strings.Contains(rootRR.Body.String(), "book.epub") {
		t.Fatalf("root must not recursively leak volume contents: %s", rootRR.Body.String())
	}

	listing := httptest.NewRequest("PROPFIND", "http://pb/dav/internal", nil)
	listing.Header.Set("User-Agent", ua)
	listing.Header.Set("Depth", "1")
	listing.Header.Set("Authorization", makeAuth("PROPFIND", "/dav/internal"))
	listingRR := httptest.NewRecorder()
	dav.ServeHTTP(listingRR, listing)
	if listingRR.Code != http.StatusMultiStatus {
		t.Fatalf("authenticated volume: %d %q", listingRR.Code, listingRR.Body.String())
	}
	if !strings.Contains(listingRR.Body.String(), "book.epub") {
		t.Fatalf("authenticated volume missing file: %s", listingRR.Body.String())
	}
}

func TestWebDAVHidesAndProtectsSystemStorageDirectories(t *testing.T) {
	dav, internal := newTestDAV(t)
	for _, name := range []string{"System Volume Information", ".adobe-digital-editions", ".adobe-hidden-files"} {
		if err := os.MkdirAll(filepath.Join(internal, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	resource, err := dav.stat("/internal")
	if err != nil {
		t.Fatal(err)
	}
	children, err := dav.children(resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		name := strings.ToLower(child.Info.Name())
		if name == "system volume information" || name == ".adobe-digital-editions" || name == ".adobe-hidden-files" {
			t.Fatalf("protected directory leaked into WebDAV listing: %q", child.Info.Name())
		}
	}
	if _, _, err := dav.resolve("/internal/System Volume Information/file", false, true); err == nil {
		t.Fatal("protected WebDAV path unexpectedly resolved")
	}
}

func TestWebDAVProppatchReturnsMultistatus(t *testing.T) {
	dav, _ := newTestDAV(t)
	body := `<?xml version="1.0" encoding="utf-8"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:displayname>newname</D:displayname></D:prop></D:set></D:propertyupdate>`
	rr := davRequest(t, dav, "PROPPATCH", "http://pb/dav/internal/", body, map[string]string{"Depth": "0"})
	if rr.Code != 207 {
		t.Fatalf("PROPPATCH code = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "<D:multistatus") || !strings.Contains(rr.Body.String(), "HTTP/1.1 200 OK") {
		t.Fatalf("PROPPATCH body: %s", rr.Body.String())
	}

	missing := davRequest(t, dav, "PROPPATCH", "http://pb/dav/internal/Books/nope", body, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("PROPPATCH missing should be 404, got %d", missing.Code)
	}
}

func TestWebDAVMoveSameFileHardlink(t *testing.T) {
	dav, internal := newTestDAV(t)
	books := filepath.Join(internal, "Books")
	if err := os.MkdirAll(books, 0755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(books, "one.txt")
	dst := filepath.Join(books, "two.txt")
	if err := os.WriteFile(src, []byte("hardlinked"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, dst); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/one.txt", "",
		map[string]string{"Destination": "http://pb/dav/internal/Books/two.txt", "Overwrite": "T"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("MOVE hardlink code = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("destination missing after MOVE: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source should be gone, stat err=%v", err)
	}
}

func TestDAVRootInfoImplementsFileInfo(t *testing.T) {
	var info os.FileInfo = davRootInfo{}
	if info.Name() != "WiFiFiles" {
		t.Fatalf("Name = %q", info.Name())
	}
	if info.Size() != 0 {
		t.Fatalf("Size = %d", info.Size())
	}
	if info.Mode() != os.ModeDir|0755 {
		t.Fatalf("Mode = %v", info.Mode())
	}
	if !info.IsDir() {
		t.Fatal("IsDir = false")
	}
	if !info.ModTime().Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("ModTime = %v", info.ModTime())
	}
	if info.Sys() != nil {
		t.Fatalf("Sys = %v", info.Sys())
	}
}

func TestIsDAVRootRequest(t *testing.T) {
	for _, path := range []string{"/dav", "/dav/"} {
		req := httptest.NewRequest("GET", path, nil)
		if !isDAVRootRequest(req) {
			t.Errorf("isDAVRootRequest(%q) = false", path)
		}
	}
	for _, path := range []string{"/dav/internal", "/dav/", "/", "/other"} {
		req := httptest.NewRequest("GET", path, nil)
		if path == "/dav/" {
			continue
		}
		if isDAVRootRequest(req) {
			t.Errorf("isDAVRootRequest(%q) = true", path)
		}
	}
}

func TestWindowsDAVVolume(t *testing.T) {
	cases := []struct {
		in   string
		vol  string
		want bool
	}{
		{"/dav/internal", "/internal", true},
		{"/dav/sd", "/sd", true},
		{"/dav/internal/", "/internal", true},
		{"/dav/internal/Books", "", false},
		{"/dav/sd/Books/novel.epub", "", false},
		{"/dav/", "", false},
		{"dav/sd", "/sd", true},
	}
	for _, c := range cases {
		vol, ok := windowsDAVVolume(c.in)
		if vol != c.vol || ok != c.want {
			t.Errorf("windowsDAVVolume(%q) = (%q, %v), want (%q, %v)", c.in, vol, ok, c.vol, c.want)
		}
	}
}

func TestRollbackDAVDestination(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "target")
	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	rollbackDAVDestination(dst, davDestinationStage{})
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("stage without backup: target should be removed, err=%v", err)
	}

	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup")
	if err := os.Rename(dst, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	rollbackDAVDestination(dst, davDestinationStage{Existed: true, Backup: backup})
	if data, err := os.ReadFile(filepath.Join(dst, "a.txt")); err != nil || string(data) != "old" {
		t.Fatalf("rollback did not restore backup: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup should be gone, err=%v", err)
	}
}

func TestHandleGetVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	book := filepath.Join(internal, "book.fb2")
	if err := os.WriteFile(book, []byte("story"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(internal, "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "GET", "http://pb/dav/internal/book.fb2", "", nil)
	if rr.Code != 200 || rr.Body.String() != "story" {
		t.Fatalf("file get: %d %q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("missing ETag")
	}

	rr = davRequest(t, dav, "GET", "http://pb/dav/internal/book.fb2?download=1", "", nil)
	if rr.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing Content-Disposition")
	}

	rr = davRequest(t, dav, "GET", "http://pb/dav/internal/", "", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "sub") || !strings.Contains(rr.Body.String(), "book.fb2") {
		t.Fatalf("dir listing: %d %q", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "HEAD", "http://pb/dav/internal/", "", nil)
	if rr.Code != 200 {
		t.Fatalf("HEAD dir: %d", rr.Code)
	}

	rr = davRequest(t, dav, "GET", "http://pb/dav/internal/", "", map[string]string{"User-Agent": "Mozilla/5.0"})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<html") {
		t.Fatalf("browser dir: %d", rr.Code)
	}

	rr = davRequest(t, dav, "GET", "http://pb/dav/internal/missing.fb2", "", nil)
	if rr.Code != 404 {
		t.Fatalf("missing file: %d", rr.Code)
	}
}

func TestCopyDAVPathBranches(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.fb2"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.fb2"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.me"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "skip.me"), filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	if err := copyDAVPath(src, dst, 0, 0); err != nil {
		t.Fatalf("depth0 dir: %v", err)
	}
	if st, err := os.Stat(dst); err != nil || !st.IsDir() {
		t.Fatalf("depth0 dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "a.fb2")); err == nil {
		t.Fatal("depth0 copied file (should be empty)")
	}

	dst2 := filepath.Join(dir, "dst2")
	if err := copyDAVPath(src, dst2, 1, 0); err != nil {
		t.Fatalf("depth1 dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst2, "sub", "b.fb2")); err != nil {
		t.Fatalf("depth1 nested file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst2, "link")); err == nil {
		t.Fatal("symlink copied")
	}

	if err := copyDAVPath(filepath.Join(dir, "nope"), filepath.Join(dir, "x"), 1, 0); err == nil {
		t.Fatal("missing src accepted")
	}
	if err := copyDAVPath(src, filepath.Join(dir, "dst3"), 1, 129); err == nil || err.Error() != "directory nesting is too deep" {
		t.Fatalf("recursion limit: %v", err)
	}
	linkSrc := filepath.Join(dir, "real-link")
	if err := os.Symlink(filepath.Join(dir, "skip.me"), linkSrc); err != nil {
		t.Fatal(err)
	}
	if err := copyDAVPath(linkSrc, filepath.Join(dir, "x"), 1, 0); err == nil || err.Error() != "symbolic links are not available through WebDAV" {
		t.Fatalf("symlink src: %v", err)
	}
}

func TestHandleLockVariants(t *testing.T) {
	dav, _ := newTestDAV(t)

	rr := davRequest(t, dav, "LOCK", "http://pb/dav/", "", map[string]string{"Timeout": "Second-30"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("lock root = %d", rr.Code)
	}

	rr = davRequest(t, dav, "LOCK", "http://pb/dav/internal/newlock.fb2", `<d:owner>x</d:owner>`, map[string]string{"Timeout": "Second-30"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("lock missing = %d", rr.Code)
	}
	lockToken := rr.Header().Get("Lock-Token")
	if lockToken == "" {
		t.Fatal("missing Lock-Token")
	}

	rr = davRequest(t, dav, "LOCK", "http://pb/dav/internal/newlock.fb2", `<d:owner>x</d:owner>`, map[string]string{"Timeout": "Second-30"})
	if rr.Code != 423 {
		t.Fatalf("lock existing = %d, want 423", rr.Code)
	}

	rr = davRequest(t, dav, "LOCK", "http://pb/dav/internal/newlock.fb2", "", map[string]string{"If": lockToken, "Timeout": "Second-60"})
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh = %d", rr.Code)
	}
	if rr.Header().Get("Timeout") != "Second-60" {
		t.Fatalf("refresh timeout = %q", rr.Header().Get("Timeout"))
	}

	rr = davRequest(t, dav, "LOCK", "http://pb/dav/internal/newlock.fb2", "", map[string]string{"If": "<opaquelocktoken:unknown>", "Timeout": "Second-30"})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("refresh unknown = %d", rr.Code)
	}

	rr = davRequest(t, dav, "UNLOCK", "http://pb/dav/internal/newlock.fb2", "", map[string]string{"Lock-Token": ""})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unlock no token = %d", rr.Code)
	}

	rr = davRequest(t, dav, "UNLOCK", "http://pb/dav/internal/newlock.fb2", "", map[string]string{"Lock-Token": lockToken})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("unlock = %d, want 204", rr.Code)
	}
}

func TestHandleLockExistingAndUnlockMissing(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "dir"), 0755); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "LOCK", "http://pb/dav/internal/dir", "", map[string]string{"Timeout": "Second-30"})
	if rr.Code != http.StatusOK {
		t.Fatalf("lock existing dir = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "UNLOCK", "http://pb/dav/internal/dir", "", map[string]string{"Lock-Token": "<opaquelocktoken:unknown>"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("unlock missing = %d", rr.Code)
	}
}

func TestDAVHTTPErrorStatuses(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{os.ErrNotExist, http.StatusNotFound},
		{os.ErrExist, http.StatusPreconditionFailed},
		{os.ErrPermission, http.StatusForbidden},
		{errors.New("protected area"), http.StatusForbidden},
		{errors.New("служба отключена"), http.StatusForbidden},
		{os.ErrInvalid, http.StatusBadRequest},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		davHTTPError(rr, tc.err)
		if rr.Code != tc.want {
			t.Fatalf("davHTTPError(%v) = %d, want %d", tc.err, rr.Code, tc.want)
		}
	}
}

func TestHandleMkcolVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "exists"), 0755); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "MKCOL", "http://pb/dav/internal/withbody", "x", nil)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("mkcol with body = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MKCOL", "http://pb/dav/internal/nope/sub", "", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("mkcol missing parent = %d body=%q", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "MKCOL", "http://pb/dav/internal/exists", "", nil)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("mkcol existing = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MKCOL", "http://pb/dav/internal/system/x", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mkcol protected = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MKCOL", "http://pb/dav/internal/NewDir", "", nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("mkcol ok = %d", rr.Code)
	}
	if st, err := os.Stat(filepath.Join(internal, "NewDir")); err != nil || !st.IsDir() {
		t.Fatalf("mkcol dir missing: %v", err)
	}
}

func TestHandleDeleteVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.WriteFile(filepath.Join(internal, "file.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(internal, "dir", "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, http.MethodDelete, "http://pb/dav/internal/missing.txt", "", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", rr.Code)
	}

	rr = davRequest(t, dav, http.MethodDelete, "http://pb/dav/internal/system/x", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("delete protected = %d", rr.Code)
	}

	rr = davRequest(t, dav, http.MethodDelete, "http://pb/dav/internal/file.txt", "", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete file = %d", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(internal, "file.txt")); !os.IsNotExist(err) {
		t.Fatalf("file not removed: %v", err)
	}

	rr = davRequest(t, dav, http.MethodDelete, "http://pb/dav/internal/dir", "", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete dir = %d", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(internal, "dir")); !os.IsNotExist(err) {
		t.Fatalf("dir not removed: %v", err)
	}
}

func TestHandleMoveVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	sd := dav.app.roots["sd"]
	books := filepath.Join(internal, "Books")
	if err := os.MkdirAll(books, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "a.txt"), []byte("A"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("move no destination = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", map[string]string{"Destination": "http://evil/dav/internal/x"})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("move foreign host = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav", "", map[string]string{"Destination": "http://pb/dav/internal/x"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("move root src = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", map[string]string{"Destination": "http://pb/dav"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("move root dst = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books", "", map[string]string{"Destination": "http://pb/dav/internal/Books/Sub"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("move into itself = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/missing.txt", "", map[string]string{"Destination": "http://pb/dav/internal/x.txt"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("move missing src = %d", rr.Code)
	}

	if err := os.WriteFile(filepath.Join(internal, "afile.txt"), []byte("F"), 0644); err != nil {
		t.Fatal(err)
	}
	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", map[string]string{"Destination": "http://pb/dav/internal/afile.txt/sub.txt"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("move parent not a dir = %d body=%q", rr.Code, rr.Body.String())
	}

	if err := os.WriteFile(filepath.Join(books, "b.txt"), []byte("B"), 0644); err != nil {
		t.Fatal(err)
	}
	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", map[string]string{
		"Destination": "http://pb/dav/internal/Books/b.txt",
		"Overwrite":   "F",
	})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("move no overwrite = %d", rr.Code)
	}

	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/a.txt", "", map[string]string{
		"Destination": "http://pb/dav/internal/Books/b.txt",
		"Overwrite":   "T",
	})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("move overwrite = %d", rr.Code)
	}
	if data, err := os.ReadFile(filepath.Join(books, "b.txt")); err != nil || string(data) != "A" {
		t.Fatalf("move overwrite content: %q %v", data, err)
	}

	if err := os.WriteFile(filepath.Join(books, "c.txt"), []byte("C"), 0644); err != nil {
		t.Fatal(err)
	}
	rr = davRequest(t, dav, "MOVE", "http://pb/dav/internal/Books/c.txt", "", map[string]string{
		"Destination": "http://pb/dav/sd/c.txt",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("move cross-volume = %d", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(books, "c.txt")); !os.IsNotExist(err) {
		t.Fatalf("cross-volume src remains: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(sd, "c.txt")); err != nil || string(data) != "C" {
		t.Fatalf("cross-volume dst: %q %v", data, err)
	}
}

func TestRenameDAVSameFileVariants(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")

	if err := renameDAVSameFile(src, src); err != nil {
		t.Fatalf("same path = %v", err)
	}

	if err := renameDAVSameFile(filepath.Join(dir, "nope.txt"), dst); err == nil {
		t.Fatal("missing src accepted")
	}

	if err := os.WriteFile(src, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "child.txt"), []byte("c"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := renameDAVSameFile(src, dst); err == nil {
		t.Fatal("rename onto directory accepted")
	}
	if data, err := os.ReadFile(src); err != nil || string(data) != "content" {
		t.Fatalf("rollback failed: %q %v", data, err)
	}

	if err := os.Remove(filepath.Join(dst, "child.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}
	if err := renameDAVSameFile(src, dst); err != nil {
		t.Fatalf("rename ok: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("src remains: %v", err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "content" {
		t.Fatalf("dst: %q %v", data, err)
	}
}

func TestHandlePropfindVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "a.epub"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/Books", "", map[string]string{"Depth": "2"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("invalid depth = %d", rr.Code)
	}

	rr = davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/nope", "", map[string]string{"Depth": "0"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing propfind = %d", rr.Code)
	}

	rr = davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/Books", "", map[string]string{"Depth": "infinity"})
	if rr.Code != 207 || !strings.Contains(rr.Body.String(), "a.epub") {
		t.Fatalf("infinity propfind = %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.MkdirAll(filepath.Join(internal, "adir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "existing.txt"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/existing.txt", "new", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("put overwrite = %d", rr.Code)
	}
	if data, err := os.ReadFile(filepath.Join(internal, "existing.txt")); err != nil || string(data) != "new" {
		t.Fatalf("overwrite content: %q %v", data, err)
	}

	rr = davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/adir", "x", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("put onto dir = %d", rr.Code)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingReadCloser) Close() error             { return nil }

func TestHandlePutMoreBranches(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.WriteFile(filepath.Join(internal, "file.txt"), []byte("f"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/x.txt", "x", map[string]string{"Content-Range": "bytes 0-1/2"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("put with content-range = %d", rr.Code)
	}

	rr = davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/Books/nope.txt", "x", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("put missing parent = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/file.txt/x.txt", "x", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("put parent is file = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, http.MethodPut, "http://pb/dav/internal/fresh.txt", "hello", nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("put new file = %d body=%s", rr.Code, rr.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(internal, "fresh.txt")); err != nil || string(data) != "hello" {
		t.Fatalf("new file content: %q %v", data, err)
	}

	req := httptest.NewRequest(http.MethodPut, "http://pb/dav/internal/fail.txt", failingReadCloser{})
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("pocketbook:650wifi")))
	rr = httptest.NewRecorder()
	dav.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("put failing body = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(internal, "fail.txt")); !os.IsNotExist(err) {
		t.Fatal("failed put left a file behind")
	}
}

func TestHandleCopyVariants(t *testing.T) {
	dav, internal := newTestDAV(t)
	books := filepath.Join(internal, "Books")
	if err := os.MkdirAll(filepath.Join(books, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(books, "a.epub"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "COPY", "http://pb/dav/internal/Books/a.epub", "", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("copy no destination = %d", rr.Code)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books/a.epub", "", map[string]string{"Destination": "http://evil/dav/x"})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("copy foreign host = %d", rr.Code)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav", "", map[string]string{"Destination": "http://pb/dav/internal/x"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("copy root src = %d", rr.Code)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books/a.epub", "", map[string]string{"Destination": "http://pb/dav/internal/Books/a.epub"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("copy same path = %d", rr.Code)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/missing.epub", "", map[string]string{"Destination": "http://pb/dav/internal/x.epub"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("copy missing src = %d", rr.Code)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books", "", map[string]string{"Destination": "http://pb/dav/internal/Copied", "Depth": "0"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("copy dir depth0 = %d body=%s", rr.Code, rr.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(internal, "Copied"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("depth0 copy contents: %v err=%v", entries, err)
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books", "", map[string]string{"Destination": "http://pb/dav/internal/CopiedFull"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("copy dir full = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(internal, "CopiedFull", "sub")); err != nil {
		t.Fatalf("nested copy missing: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(internal, "CopiedFull", "a.epub")); err != nil || string(data) != "a" {
		t.Fatalf("copied file: %q %v", data, err)
	}
}

func TestDAVUnusedPathErrors(t *testing.T) {
	if _, err := davUnusedPath(filepath.Join(t.TempDir(), "missing"), ".x-"); err == nil {
		t.Fatal("unused path in missing parent accepted")
	}
}

func TestNonceLifecycle(t *testing.T) {
	dav, _ := newTestDAV(t)
	token := dav.newNonce()
	if token == "" {
		t.Fatal("empty nonce")
	}
	if !dav.validNonce(token) {
		t.Fatal("fresh nonce rejected")
	}
	if dav.validNonce("unknown-nonce") {
		t.Fatal("unknown nonce accepted")
	}
	dav.mu.Lock()
	dav.nonces["expired-nonce"] = time.Now().Add(-time.Second)
	dav.mu.Unlock()
	if dav.validNonce("expired-nonce") {
		t.Fatal("expired nonce accepted")
	}
	dav.mu.Lock()
	dav.nonces["stale-nonce"] = time.Now().Add(-time.Second)
	dav.mu.Unlock()
	_ = dav.newNonce()
	dav.mu.Lock()
	_, stale := dav.nonces["stale-nonce"]
	dav.mu.Unlock()
	if stale {
		t.Fatal("stale nonce not pruned by newNonce")
	}
}

func TestDAVContentType(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "a.epub")
	if err := os.WriteFile(book, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	noext := filepath.Join(dir, "noext")
	if err := os.WriteFile(noext, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(book)
	if err != nil {
		t.Fatal(err)
	}
	if got := davContentType(davResource{Info: info}); got != "application/epub+zip" {
		t.Fatalf("epub type = %q", got)
	}

	info, err = os.Stat(noext)
	if err != nil {
		t.Fatal(err)
	}
	if got := davContentType(davResource{Info: info}); got != "application/octet-stream" {
		t.Fatalf("noext type = %q", got)
	}

	if got := davContentType(davResource{Info: davRootInfo{}}); got != "httpd/unix-directory" {
		t.Fatalf("dir type = %q", got)
	}
}

func TestDigestHelpers(t *testing.T) {
	parsed := parseDigestHeader("Digest username=\"pb\", realm=\"WiFiFiles\", qop=auth, nc=00000001")
	if parsed["username"] != "pb" || parsed["realm"] != "WiFiFiles" || parsed["qop"] != "auth" || parsed["nc"] != "00000001" {
		t.Fatalf("parsed = %+v", parsed)
	}
	if len(parseDigestHeader("Basic abc")) != 0 {
		t.Fatal("non-digest accepted")
	}
	if len(parseDigestHeader("")) != 0 {
		t.Fatal("empty accepted")
	}
	if got := parseDigestHeader("Digest =x"); len(got) != 0 {
		t.Fatalf("eq-at-start = %+v", got)
	}
	if got := parseDigestHeader("Digest name=\"a\\\"b\""); got["name"] != `a"b` {
		t.Fatalf("escaped = %q", got["name"])
	}
	if got := parseDigestHeader("Digest extra=\"v1\" trailing=no-comma"); got["trailing"] != "no-comma" {
		t.Fatalf("trailing = %+v", got)
	}
}

func TestDigestURIEquals(t *testing.T) {
	r := httptest.NewRequest("GET", "http://pb/dav/internal", nil)
	if !digestURIEquals("/dav/internal", r) {
		t.Fatal("RequestURI match failed")
	}
	if digestURIEquals("http://[bad", r) {
		t.Fatal("bad url accepted")
	}
	if digestURIEquals("/dav/internal?x=1", r) {
		t.Fatal("query mismatch accepted")
	}
	if !digestURIEquals("/dav/internal/", r) {
		t.Fatal("trailing slash mismatch")
	}

	r = httptest.NewRequest("GET", "http://pb/dav/internal?x=1", nil)
	if !digestURIEquals("/dav/internal/?x=1", r) {
		t.Fatal("normalize with query failed")
	}
	if digestURIEquals("/dav/internal/?y=1", r) {
		t.Fatal("query mismatch after normalize accepted")
	}
}

func TestDigestAuthenticatedVariants(t *testing.T) {
	dav, _ := newTestDAV(t)
	nonce := dav.newNonce()
	cfg := dav.app.configSnapshot()
	uri := "/dav/internal/Books"

	mk := func(n string, extra string) *http.Request {
		r := httptest.NewRequest("PROPFIND", "http://pb"+uri, nil)
		r.Header.Set("Authorization", fmt.Sprintf("Digest username=%q, realm=%q, nonce=%q, uri=%q, %s", cfg.Username, davRealm, n, uri, extra))
		return r
	}

	ha2 := md5Hex("PROPFIND:" + uri)
	plain := fmt.Sprintf("response=%q", md5Hex(cfg.DAVDigestHA1+":"+nonce+":"+ha2))
	qop := fmt.Sprintf("qop=auth, nc=00000001, cnonce=%q, response=%q", "abc", md5Hex(cfg.DAVDigestHA1+":"+nonce+":00000001:abc:auth:"+ha2))

	if !dav.digestAuthenticated(mk(nonce, plain)) {
		t.Fatal("valid plain digest rejected")
	}
	if !dav.digestAuthenticated(mk(nonce, qop)) {
		t.Fatal("valid qop digest rejected")
	}
	if dav.digestAuthenticated(mk("unknown-nonce", plain)) {
		t.Fatal("bad nonce accepted")
	}
	if dav.digestAuthenticated(mk(nonce, `response="deadbeef"`)) {
		t.Fatal("bad response accepted")
	}
	if dav.digestAuthenticated(mk(nonce, "qop=auth, response=\""+md5Hex("x")+"\"")) {
		t.Fatal("qop without nc accepted")
	}

	badUser := httptest.NewRequest("PROPFIND", "http://pb"+uri, nil)
	badUser.Header.Set("Authorization", fmt.Sprintf("Digest username=%q, realm=%q, nonce=%q, uri=%q, %s", "other", davRealm, nonce, uri, plain))
	if dav.digestAuthenticated(badUser) {
		t.Fatal("username mismatch accepted")
	}

	badURI := httptest.NewRequest("PROPFIND", "http://pb"+uri, nil)
	badURI.Header.Set("Authorization", fmt.Sprintf("Digest username=%q, realm=%q, nonce=%q, uri=%q, %s", cfg.Username, davRealm, nonce, "/dav/sd", plain))
	if dav.digestAuthenticated(badURI) {
		t.Fatal("uri mismatch accepted")
	}

	badRealm := httptest.NewRequest("PROPFIND", "http://pb"+uri, nil)
	badRealm.Header.Set("Authorization", fmt.Sprintf("Digest username=%q, realm=%q, nonce=%q, uri=%q, %s", cfg.Username, "Other", nonce, uri, plain))
	if dav.digestAuthenticated(badRealm) {
		t.Fatal("realm mismatch accepted")
	}
}

func TestDAVTimeoutAndClientAddress(t *testing.T) {
	if got := davTimeout(""); got != time.Hour {
		t.Fatalf("empty = %v", got)
	}
	if got := davTimeout("Infinite"); got != time.Hour {
		t.Fatalf("infinite = %v", got)
	}
	if got := davTimeout("Second-30"); got != 30*time.Second {
		t.Fatalf("30s = %v", got)
	}
	if got := davTimeout("Second-999999"); got != 24*time.Hour {
		t.Fatalf("cap = %v", got)
	}
	if got := davTimeout("Second-0"); got != time.Hour {
		t.Fatalf("zero = %v", got)
	}
	if got := davTimeout("Second-abc"); got != time.Hour {
		t.Fatalf("bad = %v", got)
	}
	if got := davTimeout("Second-5, Infinite"); got != 5*time.Second {
		t.Fatalf("multi = %v", got)
	}

	r := httptest.NewRequest("GET", "http://pb/dav", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if got := davClientAddress(r); got != "10.0.0.5" {
		t.Fatalf("addr = %q", got)
	}
	r.RemoteAddr = "10.0.0.5"
	if got := davClientAddress(r); got != "10.0.0.5" {
		t.Fatalf("raw addr = %q", got)
	}
}

func TestCopyDAVPathErrBranches(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyDAVPath(filepath.Join(base, "missing"), filepath.Join(base, "x"), -1, 0); err == nil {
		t.Fatal("missing src accepted")
	}
	if err := copyDAVPath(srcDir, dstDir, -1, 0); err == nil {
		t.Fatal("existing dst dir accepted")
	}
	srcFile := filepath.Join(srcDir, "a.txt")
	if err := copyDAVPath(srcFile, dstDir, -1, 0); err == nil {
		t.Fatal("existing dst file accepted")
	}
}

func TestDestinationDAVPathVariants(t *testing.T) {
	base := httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)

	req := httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	if _, err := destinationDAVPath(req); err == nil {
		t.Fatal("empty destination accepted")
	}

	req = httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	req.Header.Set("Destination", "http://%zz")
	if _, err := destinationDAVPath(req); err == nil {
		t.Fatal("malformed url accepted")
	}

	req = httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	req.Header.Set("Destination", "http://otherhost/dav/x")
	if _, err := destinationDAVPath(req); err == nil {
		t.Fatal("foreign host accepted")
	}

	req = httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	req.Header.Set("Destination", "http://pb/dav")
	if got, err := destinationDAVPath(req); err != nil || got != "/" {
		t.Fatalf("dav root destination = %q %v", got, err)
	}

	req = httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	req.Header.Set("Destination", "http://pb/other/x")
	if _, err := destinationDAVPath(req); err == nil {
		t.Fatal("outside webdav accepted")
	}

	req = httptest.NewRequest("COPY", "http://pb/dav/internal/a.txt", nil)
	req.Header.Set("Destination", "http://pb/dav/internal/Books/a.txt")
	if got, err := destinationDAVPath(req); err != nil || got != "/internal/Books/a.txt" {
		t.Fatalf("clean destination = %q %v", got, err)
	}

	_ = base
}

func TestStageDAVDestinationVariants(t *testing.T) {
	root := t.TempDir()

	stage, err := stageDAVDestination(filepath.Join(root, "missing"), true)
	if err != nil || stage.Existed || stage.Backup != "" {
		t.Fatalf("missing dst: stage=%+v err=%v", stage, err)
	}

	dst := filepath.Join(root, "target")
	if err := os.WriteFile(dst, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageDAVDestination(dst, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-overwrite existing dst err=%v", err)
	}

	stage, err = stageDAVDestination(dst, true)
	if err != nil || !stage.Existed || stage.Backup == "" {
		t.Fatalf("overwrite stage: %+v err=%v", stage, err)
	}
	if data, err := os.ReadFile(stage.Backup); err != nil || string(data) != "old" {
		t.Fatalf("backup content: %q %v", data, err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst still exists after staging: %v", err)
	}
	commitDAVDestination(stage)
	if _, err := os.Stat(stage.Backup); !os.IsNotExist(err) {
		t.Fatalf("backup not removed by commit: %v", err)
	}

	if _, err := stageDAVDestination(filepath.Join(root, "missing"), false); err != nil {
		t.Fatalf("missing dst no-overwrite err=%v", err)
	}
}

func TestHandleCopyMissingParentAndSymlinkSrc(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.WriteFile(filepath.Join(internal, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(internal, "a.txt"), filepath.Join(internal, "link.txt")); err != nil {
		t.Fatal(err)
	}

	rr := davRequest(t, dav, "COPY", "http://pb/dav/internal/a.txt", "", map[string]string{"Destination": "http://pb/dav/internal/Books/nope/x.txt"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("copy missing dst parent = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/a.txt", "", map[string]string{"Destination": "http://pb/dav/internal/a.txt/x.txt"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("copy dst inside src = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/link.txt", "", map[string]string{"Destination": "http://pb/dav/internal/copied.txt"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("copy symlink src = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVServeHTTPAndPropfindBranches(t *testing.T) {
	dav, internal := newTestDAV(t)

	rr := davRequest(t, dav, http.MethodGet, "http://pb/foo", "", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-dav path = %d", rr.Code)
	}

	rr = davRequest(t, dav, "PATCH", "http://pb/dav/internal/", "", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH = %d", rr.Code)
	}

	rr = davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/", "", nil)
	if rr.Code != 207 {
		t.Fatalf("propfind no depth = %d", rr.Code)
	}

	for _, name := range []string{"beta.txt", "gamma.txt"} {
		if err := os.WriteFile(filepath.Join(internal, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(internal, "Alpha"), 0755); err != nil {
		t.Fatal(err)
	}
	rr = davRequest(t, dav, "PROPFIND", "http://pb/dav/internal/", "", map[string]string{"Depth": "1"})
	if rr.Code != 207 || !strings.Contains(rr.Body.String(), "Alpha") || !strings.Contains(rr.Body.String(), "beta.txt") || !strings.Contains(rr.Body.String(), "gamma.txt") {
		t.Fatalf("propfind depth1 = %d %s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVMoveCopyBranches(t *testing.T) {
	dav, internal := newTestDAV(t)
	if err := os.WriteFile(filepath.Join(internal, "a.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(internal, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "inner.txt"), []byte("inner"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(internal, "src.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "Books", "dst.txt"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	rr := davRequest(t, dav, "COPY", "http://pb/dav/internal/src.txt", "", map[string]string{"Destination": "http://pb/dav/internal/Books/dst.txt", "Overwrite": "T"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("copy overwrite existing = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = davRequest(t, dav, "COPY", "http://pb/dav/internal/Books", "", map[string]string{"Destination": "http://pb/dav/internal/shallow", "Depth": "0"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("copy depth0 = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(internal, "shallow", "inner.txt")); !os.IsNotExist(err) {
		t.Fatalf("depth0 copied children: %v", err)
	}
}

func TestWebDAVLockBranches(t *testing.T) {
	dav, _ := newTestDAV(t)

	rr := davRequest(t, dav, "LOCK", "http://pb/dav/internal/new.fb2", "", map[string]string{"Timeout": "Second-1"})
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Header().Get("Lock-Token"), "opaquelocktoken:") {
		t.Fatalf("lock missing file = %d %s", rr.Code, rr.Header().Get("Lock-Token"))
	}

	time.Sleep(1200 * time.Millisecond)
	rr = davRequest(t, dav, "LOCK", "http://pb/dav/internal/new.fb2", "", map[string]string{"Timeout": "Second-3600"})
	if rr.Code != http.StatusOK {
		t.Fatalf("lock after expired = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebDAVDeleteSuccess(t *testing.T) {
	dav, internal := newTestDAV(t)
	dir := filepath.Join(internal, "del-dir")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	rec := davRequest(t, dav, "DELETE", "/dav/internal/del-dir", "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir not removed: %v", err)
	}
}

func TestWebDAVDeleteMissing(t *testing.T) {
	dav, _ := newTestDAV(t)
	rec := davRequest(t, dav, "DELETE", "/dav/internal/does-not-exist", "", nil)
	if rec.Code == http.StatusNoContent {
		t.Fatal("DELETE missing returned 204")
	}
}

func TestWebDAVDeleteBlocked(t *testing.T) {
	dav, _ := newTestDAV(t)
	rec := davRequest(t, dav, "DELETE", "/dav/system/anything", "", nil)
	if rec.Code == http.StatusNoContent {
		t.Fatal("DELETE blocked path returned 204")
	}
}

func TestDAVUnusedPathError(t *testing.T) {
	if _, err := davUnusedPath("/nonexistent-parent-dir-xyz", "prefix-"); err == nil {
		t.Fatal("CreateTemp in missing parent should fail")
	}
}

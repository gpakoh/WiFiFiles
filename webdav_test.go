package main

import (
	"encoding/base64"
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

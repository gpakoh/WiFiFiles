package main

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const davRealm = "WiFiFiles"

type davLock struct {
	Token  string
	Path   string
	Owner  string
	Expiry time.Time
}

type DAVServer struct {
	app          *App
	mu           sync.Mutex
	nonces       map[string]time.Time
	locks        map[string]davLock
	authLogUntil map[string]time.Time
	clientLogged map[string]time.Time
}

type davResource struct {
	Virtual string
	Full    string
	Info    os.FileInfo
	Root    bool
}

type davRootInfo struct{}

func (davRootInfo) Name() string       { return "WiFiFiles" }
func (davRootInfo) Size() int64        { return 0 }
func (davRootInfo) Mode() os.FileMode  { return os.ModeDir | 0755 }
func (davRootInfo) ModTime() time.Time { return time.Unix(0, 0).UTC() }
func (davRootInfo) IsDir() bool        { return true }
func (davRootInfo) Sys() any           { return nil }

func newDAVServer(app *App) *DAVServer {
	return &DAVServer{app: app, nonces: make(map[string]time.Time), locks: make(map[string]davLock), authLogUntil: make(map[string]time.Time), clientLogged: make(map[string]time.Time)}
}

func digestHA1(username, password string) string {
	sum := md5.Sum([]byte(username + ":" + davRealm + ":" + password))
	return hex.EncodeToString(sum[:])
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (d *DAVServer) newNonce() string {
	token, err := randomHex(24)
	if err != nil {
		token = fmt.Sprintf("%x", time.Now().UnixNano())
	}
	d.mu.Lock()
	now := time.Now()
	for nonce, expiry := range d.nonces {
		if now.After(expiry) {
			delete(d.nonces, nonce)
		}
	}
	d.nonces[token] = now.Add(12 * time.Hour)
	d.mu.Unlock()
	return token
}

func (d *DAVServer) validNonce(nonce string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	expiry, ok := d.nonces[nonce]
	if !ok || time.Now().After(expiry) {
		delete(d.nonces, nonce)
		return false
	}
	return true
}

func parseDigestHeader(header string) map[string]string {
	out := make(map[string]string)
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "Digest ") {
		return out
	}
	s := header[7:]
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = strings.TrimLeft(s[eq+1:], " \t")
		var value string
		if strings.HasPrefix(s, "\"") {
			s = s[1:]
			var b strings.Builder
			escaped := false
			i := 0
			for ; i < len(s); i++ {
				c := s[i]
				if escaped {
					b.WriteByte(c)
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					i++
					break
				}
				b.WriteByte(c)
			}
			value = b.String()
			s = s[i:]
		} else {
			i := strings.IndexByte(s, ',')
			if i < 0 {
				value, s = strings.TrimSpace(s), ""
			} else {
				value, s = strings.TrimSpace(s[:i]), s[i+1:]
			}
		}
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func digestURIEquals(headerURI string, r *http.Request) bool {
	if headerURI == r.RequestURI {
		return true
	}
	u, err := url.Parse(headerURI)
	if err != nil {
		return false
	}
	if u.RequestURI() == r.URL.RequestURI() {
		return true
	}
	// Windows MiniRedir may remove or restore a trailing slash between the
	// unauthenticated challenge and the authenticated retry. Treat those two
	// collection spellings as the same Digest target while keeping the query
	// string exact.
	normalize := func(pathValue string) string {
		if len(pathValue) > 1 {
			pathValue = strings.TrimSuffix(pathValue, "/")
		}
		return pathValue
	}
	return u.RawQuery == r.URL.RawQuery && normalize(u.EscapedPath()) == normalize(r.URL.EscapedPath())
}

func (d *DAVServer) digestAuthenticated(r *http.Request) bool {
	values := parseDigestHeader(r.Header.Get("Authorization"))
	if len(values) == 0 || values["realm"] != davRealm || !d.validNonce(values["nonce"]) {
		return false
	}
	cfg := d.app.configSnapshot()
	if cfg.DAVDigestHA1 == "" || values["username"] != cfg.Username || !digestURIEquals(values["uri"], r) {
		return false
	}
	ha2 := md5Hex(r.Method + ":" + values["uri"])
	expected := ""
	if values["qop"] != "" {
		if !strings.EqualFold(values["qop"], "auth") || values["nc"] == "" || values["cnonce"] == "" {
			return false
		}
		expected = md5Hex(cfg.DAVDigestHA1 + ":" + values["nonce"] + ":" + values["nc"] + ":" + values["cnonce"] + ":auth:" + ha2)
	} else {
		expected = md5Hex(cfg.DAVDigestHA1 + ":" + values["nonce"] + ":" + ha2)
	}
	got := strings.ToLower(values["response"])
	return len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func (d *DAVServer) authenticated(r *http.Request) bool {
	return d.digestAuthenticated(r)
}

func isWindowsWebDAV(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.UserAgent()), "microsoft-webdav-miniredir/")
}

func davClientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (d *DAVServer) logAuthChallenge(r *http.Request) {
	key := davClientAddress(r)
	now := time.Now()
	d.mu.Lock()
	until := d.authLogUntil[key]
	if now.Before(until) {
		d.mu.Unlock()
		return
	}
	d.authLogUntil[key] = now.Add(30 * time.Second)
	d.mu.Unlock()
	appendLog("", fmt.Sprintf("WebDAV authentication requested client=%s", key))
}

func (d *DAVServer) logClientConnected(r *http.Request) {
	key := davClientAddress(r)
	now := time.Now()
	d.mu.Lock()
	until := d.clientLogged[key]
	if now.Before(until) {
		d.mu.Unlock()
		return
	}
	d.clientLogged[key] = now.Add(time.Hour)
	d.mu.Unlock()
	client := "WebDAV client"
	if isWindowsWebDAV(r) {
		client = "Windows WebDAV client"
	}
	appendLog("", fmt.Sprintf("%s authenticated client=%s", client, key))
}

func isDAVRootRequest(r *http.Request) bool {
	return r.URL.Path == "/dav" || r.URL.Path == "/dav/"
}

func windowsDAVVolume(pathValue string) (string, bool) {
	clean := pathpkg.Clean("/" + strings.TrimPrefix(pathValue, "/"))
	switch clean {
	case "/dav/internal":
		return "/internal", true
	case "/dav/sd":
		return "/sd", true
	default:
		return "", false
	}
}

func isWindowsShellMetadata(pathValue string) bool {
	base := strings.ToLower(pathpkg.Base(pathpkg.Clean(pathValue)))
	switch base {
	case "desktop.ini", "folder.jpg", "folder.jpeg", "folder.gif", "thumbs.db", "autorun.inf":
		return true
	default:
		return false
	}
}

func (d *DAVServer) challenge(w http.ResponseWriter, stale bool) {
	nonce := d.newNonce()
	stalePart := ""
	if stale {
		stalePart = ", stale=true"
	}
	// Keep the challenge deliberately small. Windows WebClient is sensitive to
	// optional Digest directives and to chunked/non-empty 401 responses.
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"%s`, davRealm, nonce, stalePart))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusUnauthorized)
}

func (d *DAVServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dav" && !strings.HasPrefix(r.URL.Path, "/dav/") {
		http.NotFound(w, r)
		return
	}

	// Windows WebClient probes a WebDAV endpoint with unauthenticated OPTIONS
	// and may remove the trailing slash entered in the Network Location wizard.
	// Advertise DAV support before authentication and serve /dav directly instead
	// of redirecting it; the Windows redirector does not reliably follow that
	// redirect during endpoint validation.
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-WiFiFiles-WebDAV", "read-write")

	if r.Method == http.MethodOptions {
		d.handleOptions(w, r)
		return
	}
	// Windows Explorer probes desktop.ini/folder.jpg before it opens a WebDAV
	// collection. Challenging those optional shell metadata files with 401 makes
	// MiniRedir report that the whole folder name is invalid. They are absent, so
	// return a normal empty 404 before authentication.
	if isWindowsWebDAV(r) && r.Header.Get("Authorization") == "" &&
		(r.Method == "PROPFIND" || r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		isWindowsShellMetadata(r.URL.Path) {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Do not expose even the virtual WebDAV root anonymously. Windows MiniRedir
	// caches a location as guest-accessible when the first PROPFIND succeeds
	// without credentials. A later 401 on /dav/internal or /dav/sd then becomes
	// a plain "access denied" error and Windows never opens the credential
	// dialog. OPTIONS and absent shell metadata remain anonymous, but the first
	// real PROPFIND must always negotiate Digest authentication.
	if !d.authenticated(r) {
		d.logAuthChallenge(r)
		d.challenge(w, false)
		return
	}
	d.logClientConnected(r)
	switch r.Method {
	case http.MethodOptions:
		d.handleOptions(w, r)
	case "PROPFIND":
		d.handlePropfind(w, r)
	case "PROPPATCH":
		d.handleProppatch(w, r)
	case http.MethodGet, http.MethodHead:
		d.handleGet(w, r)
	case http.MethodPut:
		d.handlePut(w, r)
	case "MKCOL":
		d.handleMkcol(w, r)
	case http.MethodDelete:
		d.handleDelete(w, r)
	case "MOVE":
		d.handleMove(w, r)
	case "COPY":
		d.handleCopy(w, r)
	case "LOCK":
		d.handleLock(w, r)
	case "UNLOCK":
		d.handleUnlock(w, r)
	default:
		w.Header().Set("Allow", davAllowHeader())
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func davAllowHeader() string {
	return "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK"
}

func (d *DAVServer) handleOptions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", davAllowHeader())
	w.Header().Set("Public", davAllowHeader())
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func davRequestPath(r *http.Request) string {
	value := strings.TrimPrefix(r.URL.Path, "/dav")
	if value == "" {
		value = "/"
	}
	return pathpkg.Clean("/" + strings.TrimPrefix(value, "/"))
}

func (d *DAVServer) resolve(virtual string, allowVolumeRoot, allowMissingLeaf bool) (string, string, error) {
	virtual = pathpkg.Clean("/" + strings.TrimPrefix(virtual, "/"))
	if virtual == "/" {
		return "", "/", nil
	}
	clean := strings.TrimPrefix(virtual, "/")
	full, canonical, err := d.app.resolvePath(clean, allowVolumeRoot)
	if err != nil {
		return "", "", err
	}
	rootName := strings.SplitN(canonical, "/", 2)[0]
	root := d.app.roots[rootName]
	if err := rejectDAVSymlink(root, full, allowMissingLeaf); err != nil {
		return "", "", err
	}
	return full, "/" + canonical, nil
}

func rejectDAVSymlink(root, full string, allowMissingLeaf bool) error {
	root = filepath.Clean(root)
	full = filepath.Clean(full)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("invalid path")
	}
	if rel == "." {
		return nil
	}
	current := root
	parts := strings.Split(rel, string(os.PathSeparator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if err != nil {
			if allowMissingLeaf && i == len(parts)-1 && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic links are not available through WebDAV")
		}
	}
	return nil
}

func (d *DAVServer) stat(virtual string) (davResource, error) {
	if pathpkg.Clean(virtual) == "/" {
		return davResource{Virtual: "/", Info: davRootInfo{}, Root: true}, nil
	}
	full, canonical, err := d.resolve(virtual, true, false)
	if err != nil {
		return davResource{}, err
	}
	st, err := os.Stat(full)
	if err != nil {
		return davResource{}, err
	}
	return davResource{Virtual: canonical, Full: full, Info: st}, nil
}

func (d *DAVServer) children(resource davResource) ([]davResource, error) {
	if !resource.Info.IsDir() {
		return nil, nil
	}
	if resource.Root {
		cfg := d.app.configSnapshot()
		names := make([]string, 0, 2)
		if cfg.InternalEnabled {
			names = append(names, "internal")
		}
		if cfg.SDEnabled {
			if st, err := os.Stat(d.app.roots["sd"]); err == nil && st.IsDir() {
				names = append(names, "sd")
			}
		}
		out := make([]davResource, 0, len(names))
		for _, name := range names {
			child, err := d.stat("/" + name)
			if err == nil {
				out = append(out, child)
			}
		}
		return out, nil
	}
	entries, err := os.ReadDir(resource.Full)
	if err != nil {
		return nil, err
	}
	out := make([]davResource, 0, len(entries))
	parent := strings.TrimPrefix(resource.Virtual, "/")
	for _, entry := range entries {
		if isHiddenSystemPath(parent, entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		childPath := pathpkg.Join(resource.Virtual, entry.Name())
		child, err := d.stat(childPath)
		if err == nil {
			out = append(out, child)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Info.IsDir() != out[j].Info.IsDir() {
			return out[i].Info.IsDir()
		}
		return strings.ToLower(out[i].Info.Name()) < strings.ToLower(out[j].Info.Name())
	})
	return out, nil
}

func davHref(virtual string, isDir bool) string {
	virtual = pathpkg.Clean("/" + strings.TrimPrefix(virtual, "/"))
	if virtual == "/" {
		return "/dav/"
	}
	parts := strings.Split(strings.TrimPrefix(virtual, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	href := "/dav/" + strings.Join(parts, "/")
	if isDir && !strings.HasSuffix(href, "/") {
		href += "/"
	}
	return href
}

func xmlText(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func davDisplayName(resource davResource) string {
	switch resource.Virtual {
	case "/":
		return "WiFiFiles"
	case "/internal":
		return "INTERNAL"
	case "/sd":
		return "SDCARD"
	default:
		return resource.Info.Name()
	}
}

func davETag(info os.FileInfo) string {
	return fmt.Sprintf("\"%x-%x\"", info.ModTime().UnixNano(), info.Size())
}

func davContentType(resource davResource) string {
	if resource.Info.IsDir() {
		return "httpd/unix-directory"
	}
	if value := mime.TypeByExtension(strings.ToLower(filepath.Ext(resource.Info.Name()))); value != "" {
		return value
	}
	return "application/octet-stream"
}

func writeDAVResponse(b *strings.Builder, resource davResource) {
	info := resource.Info
	b.WriteString("<D:response><D:href>")
	b.WriteString(xmlText(davHref(resource.Virtual, info.IsDir())))
	b.WriteString("</D:href><D:propstat><D:prop>")
	b.WriteString("<D:displayname>" + xmlText(davDisplayName(resource)) + "</D:displayname>")
	if info.IsDir() {
		b.WriteString("<D:resourcetype><D:collection/></D:resourcetype>")
	} else {
		b.WriteString("<D:resourcetype/>")
		b.WriteString("<D:getcontentlength>" + strconv.FormatInt(info.Size(), 10) + "</D:getcontentlength>")
	}
	b.WriteString("<D:getcontenttype>" + xmlText(davContentType(resource)) + "</D:getcontenttype>")
	b.WriteString("<D:getlastmodified>" + info.ModTime().UTC().Format(http.TimeFormat) + "</D:getlastmodified>")
	b.WriteString("<D:creationdate>" + info.ModTime().UTC().Format(time.RFC3339) + "</D:creationdate>")
	b.WriteString("<D:getetag>" + xmlText(davETag(info)) + "</D:getetag>")
	b.WriteString("<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>")
	b.WriteString("<D:lockdiscovery/>")
	b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
}

func (d *DAVServer) handlePropfind(w http.ResponseWriter, r *http.Request) {
	depth := strings.ToLower(strings.TrimSpace(r.Header.Get("Depth")))
	if depth == "" {
		depth = "infinity"
	}
	if depth != "0" && depth != "1" && depth != "infinity" {
		http.Error(w, "WebDAV Depth must be 0, 1, or infinity", http.StatusForbidden)
		return
	}
	resource, err := d.stat(davRequestPath(r))
	if err != nil {
		davHTTPError(w, err)
		return
	}
	resources := []davResource{resource}
	if resource.Info.IsDir() && depth != "0" {
		if depth == "1" {
			children, childErr := d.children(resource)
			if childErr != nil {
				davHTTPError(w, childErr)
				return
			}
			resources = append(resources, children...)
		} else {
			const maxResources = 4096
			queue := []davResource{resource}
			for len(queue) > 0 {
				current := queue[0]
				queue = queue[1:]
				children, childErr := d.children(current)
				if childErr != nil {
					davHTTPError(w, childErr)
					return
				}
				if len(resources)+len(children) > maxResources {
					http.Error(w, "Слишком много объектов для одного PROPFIND", http.StatusInsufficientStorage)
					return
				}
				resources = append(resources, children...)
				for _, child := range children {
					if child.Info.IsDir() {
						queue = append(queue, child)
					}
				}
			}
		}
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
	for _, item := range resources {
		writeDAVResponse(&b, item)
	}
	b.WriteString("</D:multistatus>")
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = io.WriteString(w, b.String())
}

func (d *DAVServer) handleProppatch(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	resource, err := d.stat(davRequestPath(r))
	if err != nil {
		davHTTPError(w, err)
		return
	}
	href := xmlText(davHref(resource.Virtual, resource.Info.IsDir()))
	body := `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>` + href + `</D:href><D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = io.WriteString(w, body)
}

func (d *DAVServer) handleGet(w http.ResponseWriter, r *http.Request) {
	resource, err := d.stat(davRequestPath(r))
	if err != nil {
		davHTTPError(w, err)
		return
	}
	if resource.Info.IsDir() {
		children, err := d.children(resource)
		if err != nil {
			davHTTPError(w, err)
			return
		}
		if r.Method == http.MethodGet && davBrowserRequest(r) {
			d.renderDAVBrowser(w, resource, children)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		for _, child := range children {
			suffix := ""
			if child.Info.IsDir() {
				suffix = "/"
			}
			_, _ = fmt.Fprintln(w, child.Info.Name()+suffix)
		}
		return
	}
	file, err := os.Open(resource.Full)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	defer file.Close()
	w.Header().Set("ETag", davETag(resource.Info))
	w.Header().Set("Accept-Ranges", "bytes")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", davAttachmentName(resource.Info.Name()))
	}
	http.ServeContent(w, r, resource.Info.Name(), resource.Info.ModTime(), file)
}

func (d *DAVServer) handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Range") != "" {
		http.Error(w, "Content-Range not supported", http.StatusBadRequest)
		return
	}
	full, canonical, err := d.resolve(davRequestPath(r), false, true)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	parent := filepath.Dir(full)
	if st, err := os.Stat(parent); err != nil || !st.IsDir() {
		http.Error(w, "Родительская папка не существует", http.StatusConflict)
		return
	}
	if r.ContentLength > 0 {
		free, freeErr := availableBytes(parent)
		if freeErr == nil && uint64(r.ContentLength)+uploadSafetyReserve > free {
			http.Error(w, fmt.Sprintf("Недостаточно свободного места: требуется %s, доступно %s", humanSize(r.ContentLength), humanSize(int64(free))), http.StatusInsufficientStorage)
			return
		}
	}
	existed := false
	if st, statErr := os.Stat(full); statErr == nil {
		existed = true
		if st.IsDir() {
			http.Error(w, "Нельзя записать файл поверх папки", http.StatusMethodNotAllowed)
			return
		}
	}
	if existed && strings.TrimSpace(r.Header.Get("If-None-Match")) == "*" {
		http.Error(w, "Файл с таким именем уже существует", http.StatusPreconditionFailed)
		return
	}
	tmp, err := os.CreateTemp(parent, ".wififiles-dav-upload-")
	if err != nil {
		davHTTPError(w, err)
		return
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = io.Copy(tmp, r.Body); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		// FAT does not implement Unix permissions and returns EPERM here.
		// The file is already safely written and synced, so chmod is optional.
		chmodBestEffort(tmpName, 0644)
		err = os.Rename(tmpName, full)
	}
	if err != nil {
		davHTTPError(w, err)
		return
	}
	ok = true
	d.app.scheduleLibraryRefresh(full)
	appendLog(runtimeDirPath, "WebDAV PUT "+canonical)
	activity.addUpload()
	activity.addEvent(tr(d.app.cfgLang(), "Загружено: ", "Uploaded: ", "Téléversé : ", "Hochgeladen: ") + filepath.Base(canonical))
	if existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (d *DAVServer) handleMkcol(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		http.Error(w, "Тело MKCOL не поддерживается", http.StatusUnsupportedMediaType)
		return
	}
	full, _, err := d.resolve(davRequestPath(r), false, true)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	if _, err := os.Stat(filepath.Dir(full)); err != nil {
		http.Error(w, "Родительская папка не существует", http.StatusConflict)
		return
	}
	if err := os.Mkdir(full, 0755); err != nil {
		davHTTPError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (d *DAVServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	full, _, err := d.resolve(davRequestPath(r), false, false)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	if _, err := os.Lstat(full); err != nil {
		davHTTPError(w, err)
		return
	}
	if err := os.RemoveAll(full); err != nil {
		davHTTPError(w, err)
		return
	}
	d.app.scheduleLibraryRefresh(full)
	appendLog(runtimeDirPath, "WebDAV DELETE "+davRequestPath(r))
	activity.addDelete()
	activity.addEvent(tr(d.app.cfgLang(), "Удалено: ", "Deleted: ", "Supprimé : ", "Gelöscht: ") + filepath.Base(davRequestPath(r)))
	w.WriteHeader(http.StatusNoContent)
}

func destinationDAVPath(r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.Header.Get("Destination"))
	if raw == "" {
		return "", errors.New("destination header is missing")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host != "" && !strings.EqualFold(u.Host, r.Host) {
		return "", errors.New("destination points to another host")
	}
	if u.Path == "/dav" {
		return "/", nil
	}
	if !strings.HasPrefix(u.Path, "/dav/") {
		return "", errors.New("destination is outside WebDAV")
	}
	return pathpkg.Clean("/" + strings.TrimPrefix(u.Path, "/dav/")), nil
}

func overwriteAllowed(r *http.Request) bool {
	return !strings.EqualFold(strings.TrimSpace(r.Header.Get("Overwrite")), "F")
}

type davDestinationStage struct {
	Existed bool
	Backup  string
}

func davUnusedPath(parent, prefix string) (string, error) {
	f, err := os.CreateTemp(parent, prefix)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(name)
		return "", closeErr
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func stageDAVDestination(dst string, overwrite bool) (davDestinationStage, error) {
	_, err := os.Lstat(dst)
	if os.IsNotExist(err) {
		return davDestinationStage{}, nil
	}
	if err != nil {
		return davDestinationStage{}, err
	}
	if !overwrite {
		return davDestinationStage{Existed: true}, os.ErrExist
	}
	backup, err := davUnusedPath(filepath.Dir(dst), ".wififiles-dav-backup-")
	if err != nil {
		return davDestinationStage{}, err
	}
	if err := os.Rename(dst, backup); err != nil {
		return davDestinationStage{}, err
	}
	return davDestinationStage{Existed: true, Backup: backup}, nil
}

func rollbackDAVDestination(dst string, stage davDestinationStage) {
	_ = os.RemoveAll(dst)
	if stage.Backup != "" {
		_ = os.Rename(stage.Backup, dst)
	}
}

func commitDAVDestination(stage davDestinationStage) {
	if stage.Backup != "" {
		_ = os.RemoveAll(stage.Backup)
	}
}

func renameDAVSameFile(src, dst string) error {
	if filepath.Clean(src) == filepath.Clean(dst) {
		return nil
	}
	tmp, err := davUnusedPath(filepath.Dir(src), ".wififiles-dav-rename-")
	if err != nil {
		return err
	}
	if err := os.Rename(src, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(tmp, src)
		return err
	}
	return nil
}

func sameDAVVolume(a, b string) bool {
	first := func(v string) string {
		v = strings.TrimPrefix(pathpkg.Clean(v), "/")
		if i := strings.IndexByte(v, '/'); i >= 0 {
			return v[:i]
		}
		return v
	}
	return first(a) == first(b)
}

func (d *DAVServer) handleMove(w http.ResponseWriter, r *http.Request) {
	srcVirtual := davRequestPath(r)
	dstVirtual, err := destinationDAVPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if srcVirtual == dstVirtual {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if srcVirtual == "/" || dstVirtual == "/" || strings.HasPrefix(dstVirtual+"/", srcVirtual+"/") {
		http.Error(w, "Недопустимое перемещение", http.StatusForbidden)
		return
	}
	src, _, err := d.resolve(srcVirtual, false, false)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	dst, _, err := d.resolve(dstVirtual, false, true)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	if st, err := os.Stat(filepath.Dir(dst)); err != nil || !st.IsDir() {
		http.Error(w, "Родительская папка назначения не существует", http.StatusConflict)
		return
	}
	if filepath.Clean(src) == filepath.Clean(dst) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if srcInfo, srcErr := os.Stat(src); srcErr == nil {
		if dstInfo, dstErr := os.Stat(dst); dstErr == nil && os.SameFile(srcInfo, dstInfo) {
			if err := renameDAVSameFile(src, dst); err != nil {
				davHTTPError(w, err)
				return
			}
			d.app.scheduleLibraryRefresh(src)
			d.app.scheduleLibraryRefresh(dst)
			appendLog(runtimeDirPath, "WebDAV MOVE "+srcVirtual+" -> "+dstVirtual)
			activity.addEvent(tr(d.app.cfgLang(), "Переименовано: ", "Renamed: ", "Renommé : ", "Umbenannt: ") + filepath.Base(srcVirtual) + " -> " + filepath.Base(dstVirtual))
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	stage, err := stageDAVDestination(dst, overwriteAllowed(r))
	if errors.Is(err, os.ErrExist) {
		http.Error(w, "Файл назначения уже существует", http.StatusPreconditionFailed)
		return
	}
	if err != nil {
		davHTTPError(w, err)
		return
	}
	success := false
	defer func() {
		if success {
			commitDAVDestination(stage)
		} else {
			rollbackDAVDestination(dst, stage)
		}
	}()
	if sameDAVVolume(srcVirtual, dstVirtual) {
		err = os.Rename(src, dst)
	} else {
		tmpDst, tmpErr := davUnusedPath(filepath.Dir(dst), ".wififiles-dav-move-")
		if tmpErr != nil {
			err = tmpErr
		} else {
			err = copyDAVPath(src, tmpDst, -1, 0)
			if err == nil {
				err = os.Rename(tmpDst, dst)
			}
			if err != nil {
				_ = os.RemoveAll(tmpDst)
			} else {
				err = os.RemoveAll(src)
			}
		}
	}
	if err != nil {
		davHTTPError(w, err)
		return
	}
	success = true
	d.app.scheduleLibraryRefresh(src)
	d.app.scheduleLibraryRefresh(dst)
	appendLog(runtimeDirPath, "WebDAV MOVE "+srcVirtual+" -> "+dstVirtual)
	activity.addEvent(tr(d.app.cfgLang(), "Переименовано: ", "Renamed: ", "Renommé : ", "Umbenannt: ") + filepath.Base(srcVirtual) + " -> " + filepath.Base(dstVirtual))
	if stage.Existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (d *DAVServer) handleCopy(w http.ResponseWriter, r *http.Request) {
	srcVirtual := davRequestPath(r)
	dstVirtual, err := destinationDAVPath(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if srcVirtual == "/" || dstVirtual == "/" || strings.HasPrefix(dstVirtual+"/", srcVirtual+"/") {
		http.Error(w, "Недопустимое копирование", http.StatusForbidden)
		return
	}
	src, _, err := d.resolve(srcVirtual, false, false)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	dst, _, err := d.resolve(dstVirtual, false, true)
	if err != nil {
		davHTTPError(w, err)
		return
	}
	if st, err := os.Stat(filepath.Dir(dst)); err != nil || !st.IsDir() {
		http.Error(w, "Родительская папка назначения не существует", http.StatusConflict)
		return
	}
	if filepath.Clean(src) == filepath.Clean(dst) {
		http.Error(w, "Источник и назначение совпадают", http.StatusForbidden)
		return
	}
	stage, err := stageDAVDestination(dst, overwriteAllowed(r))
	if errors.Is(err, os.ErrExist) {
		http.Error(w, "Файл назначения уже существует", http.StatusPreconditionFailed)
		return
	}
	if err != nil {
		davHTTPError(w, err)
		return
	}
	success := false
	defer func() {
		if success {
			commitDAVDestination(stage)
		} else {
			rollbackDAVDestination(dst, stage)
		}
	}()
	depth := -1
	if strings.TrimSpace(r.Header.Get("Depth")) == "0" {
		depth = 0
	}
	tmpDst, err := davUnusedPath(filepath.Dir(dst), ".wififiles-dav-copy-")
	if err == nil {
		err = copyDAVPath(src, tmpDst, depth, 0)
	}
	if err == nil {
		err = os.Rename(tmpDst, dst)
	}
	if err != nil {
		_ = os.RemoveAll(tmpDst)
		davHTTPError(w, err)
		return
	}
	success = true
	d.app.scheduleLibraryRefresh(dst)
	appendLog(runtimeDirPath, "WebDAV COPY "+srcVirtual+" -> "+dstVirtual)
	activity.addUpload()
	activity.addEvent(tr(d.app.cfgLang(), "Скопировано: ", "Copied: ", "Copié : ", "Kopiert: ") + filepath.Base(dstVirtual))
	if stage.Existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func copyDAVPath(src, dst string, depth, recursion int) error {
	if recursion > 128 {
		return errors.New("directory nesting is too deep")
	}
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic links are not available through WebDAV")
	}
	if st.IsDir() {
		if err := os.Mkdir(dst, st.Mode().Perm()); err != nil {
			return err
		}
		if depth == 0 {
			return nil
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 || blockedSMBName(entry.Name()) {
				continue
			}
			if err := copyDAVPath(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name()), depth, recursion+1); err != nil {
				return err
			}
		}
		_ = os.Chtimes(dst, st.ModTime(), st.ModTime())
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, st.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return closeErr
	}
	_ = os.Chtimes(dst, st.ModTime(), st.ModTime())
	return nil
}

func parseDAVToken(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, '<'); i >= 0 {
		if j := strings.IndexByte(value[i+1:], '>'); j >= 0 {
			return value[i+1 : i+1+j]
		}
	}
	return strings.Trim(value, "<>() ")
}

func davTimeout(value string) time.Duration {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if strings.EqualFold(part, "Infinite") {
			return time.Hour
		}
		if strings.HasPrefix(strings.ToLower(part), "second-") {
			seconds, err := strconv.Atoi(strings.TrimSpace(part[7:]))
			if err == nil && seconds > 0 {
				if seconds > 86400 {
					seconds = 86400
				}
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return time.Hour
}

func (d *DAVServer) handleLock(w http.ResponseWriter, r *http.Request) {
	virtual := davRequestPath(r)
	if virtual == "/" {
		http.Error(w, "Корень WebDAV нельзя блокировать", http.StatusForbidden)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	refreshToken := parseDAVToken(r.Header.Get("If"))
	duration := davTimeout(r.Header.Get("Timeout"))
	now := time.Now()
	d.mu.Lock()
	for key, lock := range d.locks {
		if now.After(lock.Expiry) {
			delete(d.locks, key)
		}
	}
	if len(strings.TrimSpace(string(body))) == 0 && refreshToken != "" {
		for key, lock := range d.locks {
			if lock.Token == refreshToken {
				lock.Expiry = now.Add(duration)
				d.locks[key] = lock
				d.mu.Unlock()
				d.writeLockResponse(w, lock, http.StatusOK, duration)
				return
			}
		}
		d.mu.Unlock()
		http.Error(w, "Блокировка не найдена", http.StatusPreconditionFailed)
		return
	}
	if lock, ok := d.locks[virtual]; ok && now.Before(lock.Expiry) {
		d.mu.Unlock()
		http.Error(w, "Ресурс уже заблокирован", 423)
		return
	}
	d.mu.Unlock()

	created := false
	if _, err := d.stat(virtual); err != nil {
		if !os.IsNotExist(err) {
			davHTTPError(w, err)
			return
		}
		full, _, resolveErr := d.resolve(virtual, false, true)
		if resolveErr != nil {
			davHTTPError(w, resolveErr)
			return
		}
		f, createErr := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if createErr != nil {
			davHTTPError(w, createErr)
			return
		}
		_ = f.Close()
		created = true
	}
	tokenBytes, _ := randomHex(16)
	token := "opaquelocktoken:" + tokenBytes
	owner := ""
	text := string(body)
	if start := strings.Index(strings.ToLower(text), "<d:owner"); start >= 0 {
		owner = "WiFiFiles client"
	}
	lock := davLock{Token: token, Path: virtual, Owner: owner, Expiry: now.Add(duration)}
	d.mu.Lock()
	d.locks[virtual] = lock
	d.mu.Unlock()
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	d.writeLockResponse(w, lock, status, duration)
}

func (d *DAVServer) writeLockResponse(w http.ResponseWriter, lock davLock, status int, duration time.Duration) {
	seconds := int(duration / time.Second)
	if seconds <= 0 {
		seconds = 3600
	}
	w.Header().Set("Lock-Token", "<"+lock.Token+">")
	w.Header().Set("Timeout", fmt.Sprintf("Second-%d", seconds))
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(status)
	body := `<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth><D:owner>` + xmlText(lock.Owner) + `</D:owner><D:timeout>Second-` + strconv.Itoa(seconds) + `</D:timeout><D:locktoken><D:href>` + xmlText(lock.Token) + `</D:href></D:locktoken><D:lockroot><D:href>` + xmlText(davHref(lock.Path, false)) + `</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>`
	_, _ = io.WriteString(w, body)
}

func (d *DAVServer) handleUnlock(w http.ResponseWriter, r *http.Request) {
	token := parseDAVToken(r.Header.Get("Lock-Token"))
	if token == "" {
		http.Error(w, "Lock-Token required", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	found := false
	for key, lock := range d.locks {
		if lock.Token == token {
			delete(d.locks, key)
			found = true
			break
		}
	}
	d.mu.Unlock()
	if !found {
		http.Error(w, "Блокировка не найдена", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func davHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case os.IsNotExist(err):
		status = http.StatusNotFound
	case os.IsExist(err):
		status = http.StatusPreconditionFailed
	case os.IsPermission(err), strings.Contains(strings.ToLower(err.Error()), "protected"), strings.Contains(strings.ToLower(err.Error()), "отключена"):
		status = http.StatusForbidden
	case errors.Is(err, os.ErrInvalid):
		status = http.StatusBadRequest
	}
	http.Error(w, err.Error(), status)
}

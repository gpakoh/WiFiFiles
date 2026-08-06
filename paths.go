package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) resolvePath(virtual string, allowRoot bool) (string, string, error) {
	virtual = strings.TrimSpace(strings.ReplaceAll(virtual, "\\", "/"))
	virtual = strings.TrimPrefix(virtual, "/")
	clean := filepath.ToSlash(filepath.Clean(virtual))
	if clean == "." || clean == "" {
		clean = a.defaultRoot()
	}
	parts := strings.Split(clean, "/")
	rootName := parts[0]
	root, ok := a.roots[rootName]
	if !ok {
		return "", "", errors.New("unknown volume")
	}
	if !a.enabledRoot(rootName) {
		return "", "", errors.New("storage disabled in settings")
	}
	if rootName == "sd" {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			return "", "", errors.New("memory card not found")
		}
	}
	rel := ""
	if len(parts) > 1 {
		rel = filepath.Join(parts[1:]...)
	}
	full := filepath.Clean(filepath.Join(root, rel))
	rootClean := filepath.Clean(root)
	if full != rootClean && !strings.HasPrefix(full, rootClean+string(os.PathSeparator)) {
		return "", "", errors.New("invalid path")
	}
	if !allowRoot && full == rootClean {
		return "", "", errors.New("volume root is protected")
	}
	if isProtectedVirtual(clean) {
		return "", "", errors.New("system path is protected")
	}
	if err := rejectSymlinkWalk(root, full); err != nil {
		return "", "", err
	}
	return full, clean, nil
}

// rejectSymlinkWalk rejects paths whose existing prefix crosses a symbolic
// link below the volume root. Missing components are tolerated (resolvePath
// stays lexical for paths that do not exist yet); WebDAV applies its own
// stricter missing-parent checks on top.
func rejectSymlinkWalk(root, full string) error {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic links are not available")
		}
	}
	return nil
}

var protectedRootNames = map[string]map[string]struct{}{
	"internal": {
		"system": {}, "applications": {}, ".wififiles": {},
		"wififiles.log": {}, "wififiles_preparation.log": {},
		"system volume information": {}, ".adobe-digital-editions": {}, ".adobe-hidden-files": {},
	},
	"sd": {
		"system volume information": {}, "lost.dir": {}, ".adobe-digital-editions": {}, ".adobe-hidden-files": {},
	},
}

func isProtectedVirtual(v string) bool {
	v = strings.ToLower(strings.Trim(v, "/"))
	parts := strings.Split(v, "/")
	if len(parts) < 2 {
		return false
	}
	names, ok := protectedRootNames[parts[0]]
	if !ok {
		return false
	}
	_, protected := names[parts[1]]
	return protected
}

func isHiddenSystemPath(parent, name string) bool {
	parent = strings.ToLower(strings.Trim(parent, "/"))
	if strings.Contains(parent, "/") {
		return false
	}
	names, ok := protectedRootNames[parent]
	if !ok {
		return false
	}
	_, hidden := names[strings.ToLower(strings.TrimSpace(name))]
	return hidden
}

func parentVirtual(v string) string {
	v = strings.Trim(v, "/")
	if v == "internal" || v == "sd" || v == "" {
		return ""
	}
	p := filepath.ToSlash(filepath.Dir(v))
	if p == "." {
		return ""
	}
	return p
}

func encodeVirtualPath(v string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(v))
}

func requestVirtualPath(r *http.Request) string {
	if key := strings.TrimSpace(r.URL.Query().Get("k")); key != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(key); err == nil {
			return string(decoded)
		}
	}
	v := r.URL.Query().Get("p")
	for i := 0; i < 3 && strings.Contains(v, "%"); i++ {
		decoded, err := url.QueryUnescape(v)
		if err != nil || decoded == v {
			break
		}
		v = decoded
	}
	return v
}

func redirectMsg(w http.ResponseWriter, r *http.Request, p, msg string) {
	http.Redirect(w, r, "/?k="+encodeVirtualPath(p)+"&msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

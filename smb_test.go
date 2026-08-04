package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	smbntlm "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	smbvfs "github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func newTestSMB(t *testing.T) (*safeSMBBackend, string) {
	t.Helper()
	root := t.TempDir()
	b, err := newSafeSMBBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	return b, root
}

func TestSMBAccessDeniedPaths(t *testing.T) {
	b, root := newTestSMB(t)
	if err := os.MkdirAll(filepath.Join(root, "system"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := b.Open(ctx, smbvfs.OpenOptions{Path: "system"}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Open(system) = %v, want permission denied", err)
	}
	if err := b.Remove(ctx, "system/file"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Remove(system/file) = %v, want permission denied", err)
	}
	if err := b.Mkdir(ctx, "applications"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Mkdir(applications) = %v, want permission denied", err)
	}

	h, err := b.Open(ctx, smbvfs.OpenOptions{Path: "ok.txt", Disposition: smbvfs.DispositionSupersede})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.(smbvfs.Renamer).Rename(ctx, "system/evil", false); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Rename to protected = %v, want permission denied", err)
	}
	_ = h.Close(ctx)
}

func TestSMBWriteReadStatAndCallback(t *testing.T) {
	b, root := newTestSMB(t)
	ctx := context.Background()
	changed := make(chan string, 1)
	withCallback, err := newSafeSMBBackend(root, func(p string) { changed <- p })
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	h, err := withCallback.Open(ctx, smbvfs.OpenOptions{Path: "Books/novel.txt", Disposition: smbvfs.DispositionOverwriteIf})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write(ctx, 0, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-changed:
		if filepath.Clean(p) != filepath.Join(root, "Books", "novel.txt") {
			t.Fatalf("change callback path = %q", p)
		}
	default:
		t.Fatal("write close did not fire change callback")
	}

	data, err := os.ReadFile(filepath.Join(root, "Books", "novel.txt"))
	if err != nil || string(data) != "hello world" {
		t.Fatalf("file content=%q err=%v", data, err)
	}

	ro, err := b.Open(ctx, smbvfs.OpenOptions{Path: "Books/novel.txt", Disposition: smbvfs.DispositionOpen})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close(ctx)
	buf := make([]byte, 5)
	n, err := ro.Read(ctx, 6, buf)
	if err != nil || n != 5 || string(buf) != "world" {
		t.Fatalf("read offset=6: n=%d buf=%q err=%v", n, buf, err)
	}
	info, err := ro.Stat(ctx)
	if err != nil || info.Size != 11 || info.Name != "novel.txt" {
		t.Fatalf("stat = %+v err=%v", info, err)
	}
}

func TestSMBEnumerateFiltersProtectedNames(t *testing.T) {
	b, root := newTestSMB(t)
	ctx := context.Background()
	for _, name := range []string{"Books", "system", ".wififiles"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "readme.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	h, err := b.Open(ctx, smbvfs.OpenOptions{Path: "", Disposition: smbvfs.DispositionOpen})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(ctx)
	seen := map[string]bool{}
	for info, err := range h.Enumerate(ctx, "*") {
		if err != nil {
			t.Fatal(err)
		}
		seen[info.Name] = true
	}
	if !seen["Books"] || !seen["readme.txt"] {
		t.Fatalf("listing missing entries: %v", seen)
	}
	if seen["system"] || seen[".wififiles"] {
		t.Fatalf("protected entries leaked into SMB listing: %v", seen)
	}
}

func TestSMBRenameAndSetInfo(t *testing.T) {
	b, root := newTestSMB(t)
	ctx := context.Background()
	changed := make(chan string, 1)
	withCallback, err := newSafeSMBBackend(root, func(p string) { changed <- p })
	if err != nil {
		t.Fatal(err)
	}

	h, err := withCallback.Open(ctx, smbvfs.OpenOptions{Path: "a.txt", Disposition: smbvfs.DispositionOverwriteIf})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write(ctx, 0, []byte("renamed")); err != nil {
		t.Fatal(err)
	}
	if err := h.(smbvfs.Renamer).Rename(ctx, "b.txt", false); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-changed:
		if filepath.Clean(p) != filepath.Join(root, "b.txt") {
			t.Fatalf("rename callback path = %q", p)
		}
	default:
		t.Fatal("rename did not fire change callback")
	}
	if err := h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("close after write did not fire change callback")
	}
	if _, err := os.Stat(filepath.Join(root, "a.txt")); !os.IsNotExist(err) {
		t.Fatalf("old path still exists, err=%v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "b.txt")); err != nil || string(data) != "renamed" {
		t.Fatalf("renamed content=%q err=%v", data, err)
	}

	h2, err := b.Open(ctx, smbvfs.OpenOptions{Path: "b.txt"})
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close(ctx)
	if err := h2.(smbvfs.SetInfoer).SetInfo(ctx, &smbvfs.SetInfoRequest{}); err != nil {
		t.Fatalf("SetInfo empty request: %v", err)
	}
}

func TestSMBMkdirRemoveAndCredentialLookup(t *testing.T) {
	b, root := newTestSMB(t)
	ctx := context.Background()

	if err := b.Mkdir(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "d1")); err != nil || !st.IsDir() {
		t.Fatalf("mkdir d1: stat=%v err=%v", st, err)
	}
	if err := b.Remove(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "d1")); !os.IsNotExist(err) {
		t.Fatalf("remove d1: err=%v", err)
	}

	lookup := smbCredentialLookup{username: "pocketbook", ntHash: make([]byte, 16)}
	if _, err := lookup.LookupNTOWFv2(ctx, "DOM", "someone-else"); !errors.Is(err, smbntlm.ErrUnknownUser) {
		t.Fatalf("wrong user = %v, want ErrUnknownUser", err)
	}
	hash, err := lookup.LookupNTOWFv2(ctx, "DOM", "pocketbook")
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) == 0 {
		t.Fatal("NTOWFv2 hash is empty")
	}
}

func TestSMBServerHelpers(t *testing.T) {
	cfg := Config{SMBPort: 4455}
	if got := smbListenPort(cfg); got != 4455 {
		t.Fatalf("smbListenPort(4455) = %d", got)
	}
	cfg.SMBPort = 80
	if got := smbListenPort(cfg); got != 4445 {
		t.Fatalf("smbListenPort(invalid) = %d, want 4445", got)
	}
	t.Setenv("WIFIFILES_SMB_PORT", "9000")
	if got := smbListenPort(cfg); got != 9000 {
		t.Fatalf("smbListenPort(env) = %d, want 9000", got)
	}
	t.Setenv("WIFIFILES_SMB_PORT", "")

	app := newTestAuthApp(t)
	sm := &ServiceManager{app: app}
	ok, msg := sm.smbAvailability()
	if !ok || !strings.Contains(msg, "модуль встроен") {
		t.Fatalf("smbAvailability no hash: ok=%v msg=%q", ok, msg)
	}
	app.cfg.SMBNTHash = "00112233445566778899aabbccddeeff"
	ok, msg = sm.smbAvailability()
	if !ok || !strings.Contains(msg, "4445") {
		t.Fatalf("smbAvailability with hash: ok=%v msg=%q", ok, msg)
	}

	perm := friendlySMBListenError(445, syscall.EACCES)
	if !strings.Contains(perm, "запрещён") {
		t.Fatalf("friendly EACCES = %q", perm)
	}
	busy := friendlySMBListenError(4445, syscall.EADDRINUSE)
	if !strings.Contains(busy, "занят") {
		t.Fatalf("friendly EADDRINUSE = %q", busy)
	}
	other := friendlySMBListenError(4445, errors.New("boom"))
	if other != "boom" {
		t.Fatalf("friendly other = %q", other)
	}
}

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	pathpkg "path"

	smbntlm "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	smbserver "github.com/sonroyaalmerol/go-smb-server/smb/server"
	smbvfs "github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func smbListenPort(cfg Config) int {
	if value := strings.TrimSpace(os.Getenv("WIFIFILES_SMB_PORT")); value != "" {
		if port, err := strconv.Atoi(value); err == nil && port >= 1024 && port <= 65535 {
			return port
		}
	}
	if cfg.SMBPort >= 1024 && cfg.SMBPort <= 65535 {
		return cfg.SMBPort
	}
	return 4445
}

type smbCredentialLookup struct {
	username string
	ntHash   []byte
}

type safeSMBBackend struct {
	base     *smbvfs.LocalBackend
	root     string
	onChange func(string)
}

type safeSMBHandle struct {
	base     smbvfs.Handle
	rootEnum bool
	root     string
	path     string
	onChange func(string)
	changed  bool
}

func blockedSMBName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "system", "applications", ".wififiles", "wififiles.log", "wififiles_preparation.log",
		"system volume information", "lost.dir", ".adobe-digital-editions", ".adobe-hidden-files":
		return true
	default:
		return false
	}
}

func blockedSMBPath(value string) bool {
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.Trim(pathpkg.Clean("/"+value), "/")
	if value == "" || value == "." {
		return false
	}
	first := value
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	return blockedSMBName(first)
}

func newSafeSMBBackend(root string, callbacks ...func(string)) (*safeSMBBackend, error) {
	base, err := smbvfs.NewLocalBackend(root)
	if err != nil {
		return nil, err
	}
	var onChange func(string)
	if len(callbacks) > 0 {
		onChange = callbacks[0]
	}
	return &safeSMBBackend{base: base, root: filepath.Clean(root), onChange: onChange}, nil
}

func (b *safeSMBBackend) Open(ctx context.Context, opts smbvfs.OpenOptions) (smbvfs.Handle, error) {
	if blockedSMBPath(opts.Path) {
		return nil, os.ErrPermission
	}
	h, err := b.base.Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	clean := strings.Trim(pathpkg.Clean("/"+strings.ReplaceAll(opts.Path, "\\", "/")), "/")
	full := b.root
	if clean != "" && clean != "." {
		full = filepath.Join(b.root, filepath.FromSlash(clean))
	}
	return &safeSMBHandle{base: h, rootEnum: clean == "" || clean == ".", root: b.root, path: full, onChange: b.onChange}, nil
}

func (b *safeSMBBackend) Remove(ctx context.Context, value string) error {
	if blockedSMBPath(value) {
		return os.ErrPermission
	}
	return b.base.Remove(ctx, value)
}

func (b *safeSMBBackend) Mkdir(ctx context.Context, value string) error {
	if blockedSMBPath(value) {
		return os.ErrPermission
	}
	return b.base.Mkdir(ctx, value)
}

func (h *safeSMBHandle) Read(ctx context.Context, offset int64, p []byte) (int, error) {
	return h.base.Read(ctx, offset, p)
}

func (h *safeSMBHandle) Write(ctx context.Context, offset int64, p []byte) (int, error) {
	n, err := h.base.Write(ctx, offset, p)
	if n > 0 {
		h.changed = true
	}
	return n, err
}

func (h *safeSMBHandle) Close(ctx context.Context) error {
	err := h.base.Close(ctx)
	if err == nil && h.changed && h.onChange != nil {
		h.onChange(h.path)
	}
	return err
}
func (h *safeSMBHandle) Stat(ctx context.Context) (smbvfs.FileInfo, error) {
	return h.base.Stat(ctx)
}

func (h *safeSMBHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[smbvfs.FileInfo, error] {
	return func(yield func(smbvfs.FileInfo, error) bool) {
		for info, err := range h.base.Enumerate(ctx, pattern) {
			if err != nil {
				yield(info, err)
				return
			}
			if h.rootEnum && blockedSMBName(info.Name) {
				continue
			}
			if !yield(info, nil) {
				return
			}
		}
	}
}

func (h *safeSMBHandle) SetInfo(ctx context.Context, req *smbvfs.SetInfoRequest) error {
	if setter, ok := h.base.(smbvfs.SetInfoer); ok {
		return setter.SetInfo(ctx, req)
	}
	return errors.New("SMB SetInfo is not supported")
}

func (h *safeSMBHandle) Rename(ctx context.Context, newPath string, replace bool) error {
	if blockedSMBPath(newPath) {
		return os.ErrPermission
	}
	if renamer, ok := h.base.(smbvfs.Renamer); ok {
		if err := renamer.Rename(ctx, newPath, replace); err != nil {
			return err
		}
		if h.onChange != nil {
			clean := strings.Trim(pathpkg.Clean("/"+strings.ReplaceAll(newPath, "\\", "/")), "/")
			h.onChange(filepath.Join(h.root, filepath.FromSlash(clean)))
		}
		return nil
	}
	return errors.New("SMB rename is not supported")
}

func (c smbCredentialLookup) LookupNTOWFv2(_ context.Context, domain, user string) ([]byte, error) {
	if !strings.EqualFold(strings.TrimSpace(user), strings.TrimSpace(c.username)) {
		return nil, smbntlm.ErrUnknownUser
	}
	return smbntlm.NTOWFv2FromNTHash(c.ntHash, user, domain), nil
}

func (sm *ServiceManager) startSMBLocked(cfg Config, key string) {
	if strings.TrimSpace(cfg.SMBNTHash) == "" {
		sm.smbErr = "SMB: re-enter password and press Start"
		appendLog(sm.appDir, "SMB not started: NT hash is missing")
		return
	}
	ntHash, err := hex.DecodeString(cfg.SMBNTHash)
	if err != nil || len(ntHash) != 16 {
		sm.smbErr = "SMB password data corrupted; re-enter password"
		appendLog(sm.appDir, "SMB credentials: invalid NT hash")
		return
	}

	shares := make([]smbvfs.Share, 0, 2)
	if cfg.InternalEnabled {
		if st, statErr := os.Stat("/mnt/ext1"); statErr == nil && st.IsDir() {
			backend, backendErr := newSafeSMBBackend("/mnt/ext1", sm.app.scheduleLibraryRefresh)
			if backendErr != nil {
				sm.smbErr = "internal storage: " + backendErr.Error()
				return
			}
			shares = append(shares, smbvfs.NewDiskShare("INTERNAL", backend))
		}
	}
	if cfg.SDEnabled {
		if st, statErr := os.Stat("/mnt/ext2"); statErr == nil && st.IsDir() {
			backend, backendErr := newSafeSMBBackend("/mnt/ext2", sm.app.scheduleLibraryRefresh)
			if backendErr != nil {
				sm.smbErr = "SD card: " + backendErr.Error()
				return
			}
			shares = append(shares, smbvfs.NewDiskShare("SDCARD", backend))
		}
	}
	if len(shares) == 0 {
		sm.smbErr = "no storage available for SMB"
		return
	}

	port := smbListenPort(cfg)
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		sm.smbErr = friendlySMBListenError(port, err)
		appendLog(sm.appDir, fmt.Sprintf("SMB listen :%d: %v", port, err))
		return
	}
	lookup := smbCredentialLookup{username: cfg.Username, ntHash: ntHash}
	srv, err := smbserver.New(
		smbserver.WithAuth(smbntlm.NewServer(lookup, "POCKETBOOK")),
		smbserver.WithShares(shares...),
	)
	if err != nil {
		_ = ln.Close()
		sm.smbErr = err.Error()
		appendLog(sm.appDir, "SMB init: "+err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	sm.smbSrv = srv
	sm.smbCancel = cancel
	sm.smbPort = port
	sm.smbErr = ""
	sm.smbKey = key
	appendLog(sm.appDir, fmt.Sprintf("SMB2/3 started on :%d", port))
	go func(server *smbserver.Server, serverCtx context.Context) {
		err := server.Serve(serverCtx, ln)
		unexpected := err != nil && serverCtx.Err() == nil
		sm.mu.Lock()
		if sm.smbSrv == server {
			sm.smbSrv = nil
			sm.smbCancel = nil
			sm.smbPort = 0
			sm.smbKey = ""
			if unexpected {
				sm.smbErr = err.Error()
			}
		}
		sm.mu.Unlock()
		if unexpected {
			appendLog(sm.appDir, "SMB server: "+err.Error())
			writeNativeState(sm, "Ошибка SMB: "+err.Error())
		}
	}(srv, ctx)
}

func friendlySMBListenError(port int, err error) string {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		return fmt.Sprintf("Порт %d запрещён UID %d; выберите порт 1024–65535", port, os.Getuid())
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Sprintf("Порт %d уже занят другим процессом", port)
	}
	return err.Error()
}

func (sm *ServiceManager) smbAvailability() (bool, string) {
	cfg := sm.app.configSnapshot()
	if cfg.SMBNTHash == "" {
		return true, "модуль встроен; для первого запуска SMB введите пароль заново"
	}
	port := smbListenPort(cfg)
	return true, fmt.Sprintf("встроенный SMB2/3-сервер работает без root на порту %d; Проводнику Windows для нестандартного порта потребуется локальная переадресация", port)
}

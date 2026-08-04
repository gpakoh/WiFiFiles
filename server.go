package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"iter"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	smbntlm "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	smbserver "github.com/sonroyaalmerol/go-smb-server/smb/server"
	smbvfs "github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

const version = "0.7.22"

var chmodFile = os.Chmod

// chmodBestEffort applies conventional Unix permissions when the backing
// filesystem supports them. PocketBook internal storage and SD cards are
// commonly FAT-formatted, where chmod returns EPERM even though the file is
// otherwise writable and valid.
func chmodBestEffort(path string, mode os.FileMode) {
	_ = chmodFile(path, mode)
}

const (
	runtimeDirPath          = "/tmp/WiFiFiles"
	persistentConfigPath    = "/mnt/ext1/system/config/WiFiFiles.json"
	unifiedLogPath          = "/mnt/ext1/WiFiFiles.log"
	legacyAppDirPath        = "/mnt/ext1/applications/.wififiles"
	nativeFolderRequestPath = "/tmp/WiFiFiles/native_folder_request.ini"
	nativeFolderListPath    = "/tmp/WiFiFiles/native_folder_list.ini"
	nativeMobileRequestPath = "/tmp/WiFiFiles/native_mobile_request.ini"
	nativeMobileQRPath      = "/tmp/WiFiFiles/native_mobile_qr.ini"
	mobileTokenPath         = "/tmp/WiFiFiles/mobile_token.json"
)

type Config struct {
	ConfigVersion int    `json:"config_version"`
	Username      string `json:"username"`
	PasswordSalt  string `json:"password_salt"`
	PasswordHash  string `json:"password_hash"`
	SMBNTHash     string `json:"smb_nt_hash,omitempty"`
	DAVDigestHA1  string `json:"dav_digest_ha1,omitempty"`

	// Port is retained for migration from WiFiFiles 0.1.x.
	Port           int    `json:"port,omitempty"`
	HTTPEnabled    bool   `json:"http_enabled"`
	HTTPPort       int    `json:"http_port"`
	FTPEnabled     bool   `json:"ftp_enabled"`
	FTPPort        int    `json:"ftp_port"`
	SMBEnabled     bool   `json:"smb_enabled"`
	SMBPort        int    `json:"smb_port"`
	LoggingEnabled bool   `json:"logging_enabled"`
	Language       string `json:"language,omitempty"`

	InternalEnabled bool `json:"internal_enabled"`
	SDEnabled       bool `json:"sd_enabled"`
}

type App struct {
	cfgPath  string
	cfgMu    sync.RWMutex
	cfg      Config
	sessions map[string]time.Time
	sessMu   sync.Mutex
	roots    map[string]string
	tmpl     *template.Template

	libraryMu      sync.Mutex
	libraryTimer   *time.Timer
	libraryTargets map[string]struct{}

	mobileMu       sync.Mutex
	mobilePending  map[string]map[string]struct{}
	mobileTimers   map[string]*time.Timer
	mobileReceipts map[string]map[string]MobileUploadResult
}

var bookFileSuffixes = []string{
	".epub", ".fb2", ".fb2.zip", ".pdf", ".djvu", ".djv", ".mobi", ".prc",
	".azw", ".azw3", ".txt", ".rtf", ".doc", ".docx", ".chm", ".html", ".htm",
	".cbz", ".cbr", ".tcr", ".pdb",
}

func isBookFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	for _, suffix := range bookFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

const uploadSafetyReserve = uint64(4 << 20)

func availableBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func totalUploadBytes(files []*multipart.FileHeader) uint64 {
	var total uint64
	for _, file := range files {
		if file != nil && file.Size > 0 {
			total += uint64(file.Size)
		}
	}
	return total
}

func ensureUploadSpace(dir string, files []*multipart.FileHeader) error {
	required := totalUploadBytes(files)
	free, err := availableBytes(dir)
	if err != nil {
		return fmt.Errorf("не удалось проверить свободное место: %w", err)
	}
	if required+uploadSafetyReserve > free {
		return fmt.Errorf("недостаточно свободного места: требуется %s, доступно %s", humanSize(int64(required)), humanSize(int64(free)))
	}
	return nil
}

func freeSpaceText(path string) string {
	free, err := availableBytes(path)
	if err != nil {
		return "не удалось определить"
	}
	return humanSize(int64(free))
}

func ensureRequestUploadSpace(dir string, contentLength int64) error {
	if contentLength <= 0 {
		return nil
	}
	free, err := availableBytes(dir)
	if err != nil {
		return fmt.Errorf("не удалось проверить свободное место: %w", err)
	}
	required := uint64(contentLength)
	if required+uploadSafetyReserve > free {
		return fmt.Errorf("недостаточно свободного места: требуется около %s, доступно %s", humanSize(contentLength), humanSize(int64(free)))
	}
	return nil
}

// writeStreamTemp writes an incoming upload directly into the selected reader
// folder. It deliberately avoids ParseMultipartForm/FileHeader.Open because Go's
// multipart parser spills large parts into the tiny PocketBook /tmp filesystem.
func writeStreamTemp(dir string, src io.Reader) (string, int64, error) {
	tmp, err := os.CreateTemp(dir, ".wififiles-upload-*.part")
	if err != nil {
		return "", 0, err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	chmodBestEffort(tmpPath, 0644)
	buf := make([]byte, 64<<10)
	written, err := io.CopyBuffer(tmp, src, buf)
	if err != nil {
		return "", written, err
	}
	if err := tmp.Sync(); err != nil {
		return "", written, err
	}
	if err := tmp.Close(); err != nil {
		return "", written, err
	}
	ok = true
	return tmpPath, written, nil
}

func writeMultipartTemp(dir string, hdr *multipart.FileHeader) (string, error) {
	src, err := hdr.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	tmpPath, _, err := writeStreamTemp(dir, src)
	return tmpPath, err
}

func commitTempAutoRename(dir, name, tmpPath string) (string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 0; i < 10000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		finalPath := filepath.Join(dir, candidate)
		if _, statErr := os.Stat(finalPath); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		if err := os.Rename(tmpPath, finalPath); err != nil {
			return "", err
		}
		return candidate, nil
	}
	return "", errors.New("too many files with the same name")
}

func libraryScanTarget(filePath string) (string, bool) {
	if !isBookFile(filePath) {
		return "", false
	}
	clean := filepath.Clean(filePath)
	for _, root := range []string{"/mnt/ext1", "/mnt/ext2"} {
		if clean != root && strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			rel, err := filepath.Rel(root, clean)
			if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return "", false
			}
			first := strings.Split(filepath.ToSlash(rel), "/")[0]
			if blockedSMBName(first) {
				return "", false
			}
			return filepath.Dir(clean), true
		}
	}
	return "", false
}

func collapseLibraryTargets(targets []string) []string {
	sort.Slice(targets, func(i, j int) bool {
		if len(targets[i]) == len(targets[j]) {
			return targets[i] < targets[j]
		}
		return len(targets[i]) < len(targets[j])
	})
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		covered := false
		for _, parent := range result {
			if target == parent || strings.HasPrefix(target, parent+string(os.PathSeparator)) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, target)
		}
	}
	return result
}

func findPocketBookExecutable(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if !strings.ContainsRune(candidate, os.PathSeparator) {
			if found, err := exec.LookPath(candidate); err == nil {
				return found
			}
			continue
		}
		if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return candidate
		}
	}
	return ""
}

func (a *App) scheduleLibraryRefresh(filePath string) {
	target, ok := libraryScanTarget(filePath)
	if !ok {
		return
	}
	a.libraryMu.Lock()
	if a.libraryTargets == nil {
		a.libraryTargets = make(map[string]struct{})
	}
	a.libraryTargets[target] = struct{}{}
	if a.libraryTimer != nil {
		a.libraryTimer.Stop()
	}
	a.libraryTimer = time.AfterFunc(2500*time.Millisecond, a.flushLibraryRefresh)
	a.libraryMu.Unlock()
}

func (a *App) flushLibraryRefresh() {
	a.libraryMu.Lock()
	targets := make([]string, 0, len(a.libraryTargets))
	for target := range a.libraryTargets {
		targets = append(targets, target)
	}
	a.libraryTargets = make(map[string]struct{})
	a.libraryTimer = nil
	a.libraryMu.Unlock()

	targets = collapseLibraryTargets(targets)
	if len(targets) == 0 {
		return
	}
	a.runPocketBookScanner(targets)
}

func (a *App) runPocketBookScanner(targets []string) {
	scanner := findPocketBookExecutable(
		"/mnt/ext1/system/bin/scanner.app",
		"/ebrmain/bin/scanner.app",
		"/ebrmain/cramfs/bin/scanner.app",
	)
	if scanner == "" {
		appendLog(runtimeDirPath, "Library refresh skipped: scanner.app not found")
		return
	}
	logFile, err := os.CreateTemp("/tmp", "wififiles-library-scan-")
	if err != nil {
		appendLog(runtimeDirPath, "Library refresh log: "+err.Error())
		return
	}
	logPath := logFile.Name()
	cmd := exec.Command(scanner)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		_ = os.Remove(logPath)
		appendLog(runtimeDirPath, fmt.Sprintf("Library refresh start failed: %v", err))
		return
	}
	appendLog(runtimeDirPath, "Library refresh started for: "+strings.Join(targets, ", "))

	go func() {
		defer os.Remove(logPath)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		timeout := time.NewTimer(30 * time.Second)
		defer timeout.Stop()
		expectedStop := false

		stopScanner := func(reason string) error {
			expectedStop = true
			appendLog(runtimeDirPath, "Library refresh stopping: "+reason)
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case waitErr := <-done:
				return waitErr
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				return <-done
			}
		}

		var waitErr error
		finished := false
		for !finished {
			select {
			case waitErr = <-done:
				finished = true
			case <-ticker.C:
				_ = logFile.Sync()
				if data, readErr := os.ReadFile(logPath); readErr == nil && strings.Contains(string(data), "Scan finished") {
					waitErr = stopScanner("scan completed")
					finished = true
				}
			case <-timeout.C:
				waitErr = stopScanner("30-second safety timeout")
				finished = true
			}
		}
		_ = logFile.Close()
		if data, readErr := os.ReadFile(logPath); readErr == nil {
			text := strings.TrimSpace(string(data))
			if len(text) > 2048 {
				text = text[len(text)-2048:]
			}
			if text != "" {
				appendLog(runtimeDirPath, "Library scanner output: "+text)
			}
		}
		if waitErr != nil && !expectedStop {
			appendLog(runtimeDirPath, "Library refresh process: "+waitErr.Error())
		} else {
			appendLog(runtimeDirPath, "Library refresh finished")
		}
	}()
}

type Entry struct {
	Name    string
	Path    string
	IsDir   bool
	Size    string
	ModTime string
}

type Breadcrumb struct {
	Path  string
	Label string
}

type UploadDestination struct {
	Path     string
	Label    string
	Selected bool
}

type MobileTokenRecord struct {
	Token   string `json:"token"`
	Target  string `json:"target"`
	Mode    string `json:"mode"`
	Expires int64  `json:"expires"`
}

type PageData struct {
	Version      string
	Username     string
	CurrentPath  string
	ParentPath   string
	Entries      []Entry
	Error        string
	Message      string
	Roots        []string
	Breadcrumbs  []Breadcrumb
	Destinations []UploadDestination
	FreeSpace    string
}

type ControlData struct {
	Version          string
	IPs              []string
	AccessHost       string
	HTTPEnabled      bool
	HTTPPort         int
	HTTPRunning      bool
	HTTPError        string
	FTPEnabled       bool
	FTPPort          int
	FTPRunning       bool
	FTPError         string
	SMBEnabled       bool
	LoggingEnabled   bool
	SMBRunning       bool
	SMBPort          int
	SMBError         string
	SMBAvailable     bool
	SMBReason        string
	SMBCredentials   bool
	PortSMBAvailable bool
	PortSMBReason    string
	InternalEnabled  bool
	InternalStatus   string
	SDEnabled        bool
	SDStatus         string
	Username         string
	UID              int
	Message          string
	Error            string
}

const controlPort = 8090

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

func stopManagerPID(pid int) {
	if pid <= 1 || !processAlive(pid) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 30 && processAlive(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if processAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func prepareStorageLayout() {
	_ = os.MkdirAll(runtimeDirPath, 0700)
	_ = os.MkdirAll(filepath.Dir(persistentConfigPath), 0755)

	legacyPIDPath := filepath.Join(legacyAppDirPath, "wififiles.pid")
	if data, err := os.ReadFile(legacyPIDPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 && processAlive(pid) && processIsWiFiFiles(pid) {
			stopManagerPID(pid)
		}
	}

	if _, err := os.Stat(persistentConfigPath); os.IsNotExist(err) {
		legacyConfig := filepath.Join(legacyAppDirPath, "config.json")
		if data, readErr := os.ReadFile(legacyConfig); readErr == nil {
			_ = os.WriteFile(persistentConfigPath, data, 0600)
		}
	}

	_ = os.RemoveAll(legacyAppDirPath)
	for _, oldPath := range []string{
		"/mnt/ext1/WiFiFiles_NATIVE.log",
		"/mnt/ext1/WiFiFiles_STATUS.txt",
		"/mnt/ext1/WiFiFiles_Diagnostic.txt",
	} {
		_ = os.Remove(oldPath)
	}
}

func main() {
	prepareStorageLayout()
	appDir := runtimeDirPath
	if err := os.MkdirAll(appDir, 0700); err != nil {
		appDir = "/tmp"
	}
	_ = os.Chdir(appDir)

	base := strings.ToLower(filepath.Base(os.Args[0]))
	if strings.Contains(base, "diagnostic") {
		writeDiagnostic(appDir)
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--manager":
			runManager(appDir)
			return
		case "--stop", "--native-stop":
			nativeStop(appDir)
			return
		case "--native-start":
			nativeStart(appDir)
			return
		case "--native-state":
			nativeStateCommand(appDir)
			return
		case "--native-apply-file":
			nativeApplyFile(appDir)
			return
		case "--native-set-language-file":
			nativeSetLanguageFile(appDir)
			return
		case "--native-folder-list-file":
			nativeFolderListFile(appDir)
			return
		case "--native-mobile-qr-file":
			nativeMobileQRFile(appDir)
			return
		case "--serve": // compatibility with 0.1.x
			runServer(appDir)
			return
		}
	}
	// The server binary is normally controlled by the native InkView app.
	// Retain the browser launcher only for direct/manual execution.
	launchManagerAndUI(appDir)
}

type ServiceManager struct {
	app       *App
	appDir    string
	mu        sync.Mutex
	httpSrv   *http.Server
	httpLn    net.Listener
	httpPort  int
	httpErr   string
	ftpSrv    *FTPServer
	ftpPort   int
	ftpErr    string
	smbSrv    *smbserver.Server
	smbCancel context.CancelFunc
	smbPort   int
	smbErr    string
	smbKey    string
	control   *http.Server
	stopCh    chan struct{}
	stopOnce  sync.Once
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

func launchManagerAndUI(appDir string) {
	pid, alive := readLivePID(appDir)
	// WiFiFiles 0.1.x left a standalone HTTP process under the same PID file.
	// Stop it during the first 0.2.x launch so the new manager can take over
	// without requiring a reboot or a manual second tap.
	if alive && !controlPanelReady(appDir) && processIsWiFiFiles(pid) {
		appendLog(appDir, fmt.Sprintf("stopping legacy WiFiFiles process pid=%d", pid))
		_ = syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 30 && processAlive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if !processAlive(pid) {
			_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
			_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
			pid, alive = 0, false
		}
	}
	if !alive {
		exe, err := os.Executable()
		if err != nil {
			writeStatus("WiFiFiles: не найден путь приложения.\n" + err.Error() + "\n")
			return
		}
		logFile, err := openProcessOutput()
		if err != nil {
			writeStatus("WiFiFiles: не удалось подготовить вывод процесса.\n" + err.Error() + "\n")
			return
		}
		cmd := exec.Command(exe, "--manager")
		cmd.Dir = appDir
		cmd.Stdin = nil
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			writeStatus("WiFiFiles: менеджер не запустился.\n" + err.Error() + "\n")
			appendLog(appDir, "manager start: "+err.Error())
			return
		}
		pid = cmd.Process.Pid
		_ = cmd.Process.Release()
		_ = logFile.Close()
	}

	ready := false
	for i := 0; i < 50; i++ {
		if !processAlive(pid) {
			break
		}
		if controlPanelReady(appDir) {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		writeStatus("WiFiFiles: панель управления не запустилась.\nСмотрите WiFiFiles.log\n")
		writeDiagnostic(appDir)
		return
	}

	var ips []string
	for i := 0; i < 60; i++ {
		ips = localIPv4s()
		if len(ips) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(ips) == 0 {
		writeStatus(fmt.Sprintf("WiFiFiles %s запущен, но Wi-Fi IP не определён.\nПодключите ридер к Wi-Fi и снова откройте WiFiFiles.\nПанель слушает порт %d.\n", version, controlPort))
		appendLog(appDir, "browser: no local IPv4 address")
		return
	}
	target := fmt.Sprintf("http://%s:%d/", ips[0], controlPort)
	if err := launchPocketBookBrowser(appDir, target); err != nil {
		text := "WiFiFiles запущен, но штатный браузер не открылся.\n"
		text += "Откройте на ридере браузер и введите: " + target + "\n"
		text += "С другого устройства панель запросит логин и пароль WiFiFiles.\n"
		text += "Ошибка браузера: " + err.Error() + "\n"
		writeStatus(text)
		appendLog(appDir, "browser: "+err.Error())
	}
}

func controlPanelReady(appDir string) bool {
	data, err := os.ReadFile(filepath.Join(appDir, "wififiles.ready"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return err == nil && pid > 1 && processAlive(pid) && processIsWiFiFiles(pid)
}

func processIsWiFiFiles(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	cmdline := strings.ToLower(strings.ReplaceAll(string(data), "\x00", " "))
	return strings.Contains(cmdline, "wififiles")
}

func launchPocketBookBrowser(appDir, target string) error {
	type candidate struct {
		path string
		args []string
	}
	candidates := []candidate{
		// On firmware W650.5.14.798 the browser accepts the URL most
		// reliably when it is the only application argument.
		{path: "/ebrmain/bin/browser.app", args: []string{target}},
		{path: "/ebrmain/bin/webbrowser.sh", args: []string{target}},
		{path: "/ebrmain/bin/webbrowser.app", args: []string{target}},
		{path: "/ebrmain/bin/browser.app", args: []string{"-platform", "PocketBook", target}},
		{path: "/ebrmain/bin/browser", args: []string{"-platform", "PocketBook", target}},
	}
	var errs []string
	for _, c := range candidates {
		if _, err := os.Stat(c.path); err != nil {
			continue
		}
		cmd := exec.Command(c.path, c.args...)
		cmd.Dir = appDir
		cmd.Stdin = nil
		logFile, _ := openProcessOutput()
		if logFile != nil {
			cmd.Stdout = logFile
			cmd.Stderr = logFile
		}
		if err := cmd.Start(); err == nil {
			_ = cmd.Process.Release()
			if logFile != nil {
				_ = logFile.Close()
			}
			appendLog(appDir, "opened control UI with "+c.path)
			return nil
		} else {
			errs = append(errs, c.path+": "+err.Error())
		}
		if logFile != nil {
			_ = logFile.Close()
		}
	}
	if len(errs) == 0 {
		return errors.New("исполняемый файл браузера не найден")
	}
	return errors.New(strings.Join(errs, "; "))
}

func runManager(appDir string) {
	if pid, ok := readLivePID(appDir); ok && pid != os.Getpid() {
		appendLog(appDir, fmt.Sprintf("manager already running pid %d", pid))
		return
	}
	_ = os.WriteFile(filepath.Join(appDir, "wififiles.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
	defer os.Remove(filepath.Join(appDir, "wififiles.pid"))
	defer os.Remove(filepath.Join(appDir, "wififiles.ready"))

	app, err := newApp(persistentConfigPath)
	if err != nil {
		appendLog(appDir, "manager init: "+err.Error())
		return
	}
	if usesDefaultPassword(app.configSnapshot()) {
		appendLog(appDir, "manager start blocked: default password must be changed")
		writeNativeStateStopped(appDir, "Перед первым запуском задайте новый пароль")
		return
	}
	sm := &ServiceManager{app: app, appDir: appDir, stopCh: make(chan struct{})}
	if err := sm.startControl(); err != nil {
		appendLog(appDir, "control listen: "+err.Error())
		return
	}
	// Signal readiness only after HTTP/FTP/SMB have been initialized and the
	// native state file contains their final startup result.
	sm.applyServices()
	go app.keepNetworkAlive()
	appendLog(appDir, fmt.Sprintf("WiFiFiles %s manager started, uid=%d", version, os.Getuid()))
	writeManagerStatus(sm)
	writeNativeState(sm, "")
	_ = os.WriteFile(filepath.Join(appDir, "wififiles.ready"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sigCh:
	case <-sm.stopCh:
	}
	signal.Stop(sigCh)
	sm.shutdown()
	appendLog(appDir, "manager stopped")
	writeStatus("WiFiFiles выключен.\n")
	writeNativeStateStopped(appDir, "Серверы выключены")
}

func writeManagerStatus(sm *ServiceManager) {
	cfg := sm.app.configSnapshot()
	ips := localIPv4s()
	var b strings.Builder
	fmt.Fprintf(&b, "WiFiFiles %s включен.\n", version)
	if len(ips) > 0 {
		fmt.Fprintf(&b, "Панель управления: http://%s:%d/\n", ips[0], controlPort)
	} else {
		fmt.Fprintf(&b, "Панель управления слушает порт %d; Wi-Fi IP пока не определён.\n", controlPort)
	}
	if len(ips) == 0 {
		b.WriteString("Wi-Fi IP пока не определён.\n")
	} else {
		for _, ip := range ips {
			if cfg.HTTPEnabled {
				fmt.Fprintf(&b, "Веб-файлы: http://%s:%d/\n", ip, cfg.HTTPPort)
				fmt.Fprintf(&b, "WebDAV root: http://%s:%d/dav/\nWebDAV internal: http://%s:%d/dav/internal/\nWebDAV SD: http://%s:%d/dav/sd/\n", ip, cfg.HTTPPort, ip, cfg.HTTPPort, ip, cfg.HTTPPort)
			}
			if cfg.FTPEnabled {
				fmt.Fprintf(&b, "FTP: ftp://%s:%d/\n", ip, cfg.FTPPort)
			}
			if cfg.SMBEnabled {
				if cfg.InternalEnabled {
					fmt.Fprintf(&b, "SMB внутренняя память: smb://%s:%d/INTERNAL\n", ip, smbListenPort(cfg))
				}
				if cfg.SDEnabled {
					fmt.Fprintf(&b, "SMB карта SD: smb://%s:%d/SDCARD\n", ip, smbListenPort(cfg))
				}
			}
		}
	}
	fmt.Fprintf(&b, "Логин: %s\nПароль: установлен в панели управления.\n", cfg.Username)
	writeStatus(b.String())
}

func (sm *ServiceManager) startControl() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", sm.handleControl)
	mux.HandleFunc("/services", sm.handleServices)
	mux.HandleFunc("/credentials", sm.handleCredentials)
	mux.HandleFunc("/stop", sm.handleStop)
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", controlPort))
	if err != nil {
		return err
	}
	sm.control = &http.Server{Handler: securityHeaders(sm.controlAuth(mux)), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := sm.control.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			appendLog(sm.appDir, "control server: "+err.Error())
		}
	}()
	return nil
}

func (sm *ServiceManager) applyServices() {
	sm.mu.Lock()
	cfg := sm.app.configSnapshot()

	if cfg.HTTPEnabled {
		if sm.httpSrv == nil || sm.httpPort != cfg.HTTPPort {
			sm.stopHTTPLocked()
			ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", cfg.HTTPPort))
			if err != nil {
				sm.httpErr = err.Error()
				appendLog(sm.appDir, "http listen: "+err.Error())
			} else {
				sm.httpLn = ln
				sm.httpPort = cfg.HTTPPort
				sm.httpErr = ""
				sm.httpSrv = &http.Server{Handler: sm.app.routes(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 5 * time.Minute, MaxHeaderBytes: 1 << 20}
				go func(srv *http.Server, listener net.Listener) {
					if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
						appendLog(sm.appDir, "http server: "+err.Error())
					}
				}(sm.httpSrv, sm.httpLn)
				appendLog(sm.appDir, fmt.Sprintf("HTTP started on :%d", cfg.HTTPPort))
			}
		}
	} else {
		sm.stopHTTPLocked()
		sm.httpErr = ""
	}

	if cfg.FTPEnabled {
		if sm.ftpSrv == nil || sm.ftpPort != cfg.FTPPort {
			sm.stopFTPLocked()
			ftp := NewFTPServer(sm.app, sm.appDir, cfg.FTPPort)
			if err := ftp.Start(); err != nil {
				sm.ftpErr = err.Error()
				appendLog(sm.appDir, "ftp listen: "+err.Error())
			} else {
				sm.ftpSrv = ftp
				sm.ftpPort = cfg.FTPPort
				sm.ftpErr = ""
				appendLog(sm.appDir, fmt.Sprintf("FTP started on :%d", cfg.FTPPort))
			}
		}
	} else {
		sm.stopFTPLocked()
		sm.ftpErr = ""
	}

	smbKey := fmt.Sprintf("%s|%s|%t|%t|%d", strings.ToLower(cfg.Username), cfg.SMBNTHash, cfg.InternalEnabled, cfg.SDEnabled, smbListenPort(cfg))
	if cfg.SMBEnabled {
		if sm.smbSrv == nil || sm.smbKey != smbKey {
			sm.stopSMBLocked()
			sm.startSMBLocked(cfg, smbKey)
		}
	} else {
		sm.stopSMBLocked()
		sm.smbErr = ""
	}
	sm.mu.Unlock()
	writeManagerStatus(sm)
	writeNativeState(sm, "")
}

func (sm *ServiceManager) startSMBLocked(cfg Config, key string) {
	if strings.TrimSpace(cfg.SMBNTHash) == "" {
		sm.smbErr = "Для SMB введите пароль заново и нажмите Старт"
		appendLog(sm.appDir, "SMB not started: NT hash is missing")
		return
	}
	ntHash, err := hex.DecodeString(cfg.SMBNTHash)
	if err != nil || len(ntHash) != 16 {
		sm.smbErr = "Повреждены данные пароля SMB; введите пароль заново"
		appendLog(sm.appDir, "SMB credentials: invalid NT hash")
		return
	}

	shares := make([]smbvfs.Share, 0, 2)
	if cfg.InternalEnabled {
		if st, statErr := os.Stat("/mnt/ext1"); statErr == nil && st.IsDir() {
			backend, backendErr := newSafeSMBBackend("/mnt/ext1", sm.app.scheduleLibraryRefresh)
			if backendErr != nil {
				sm.smbErr = "Внутренняя память: " + backendErr.Error()
				return
			}
			shares = append(shares, smbvfs.NewDiskShare("INTERNAL", backend))
		}
	}
	if cfg.SDEnabled {
		if st, statErr := os.Stat("/mnt/ext2"); statErr == nil && st.IsDir() {
			backend, backendErr := newSafeSMBBackend("/mnt/ext2", sm.app.scheduleLibraryRefresh)
			if backendErr != nil {
				sm.smbErr = "Карта SD: " + backendErr.Error()
				return
			}
			shares = append(shares, smbvfs.NewDiskShare("SDCARD", backend))
		}
	}
	if len(shares) == 0 {
		sm.smbErr = "Нет доступной памяти для SMB"
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

func (sm *ServiceManager) stopHTTPLocked() {
	_ = os.Remove(mobileTokenPath)
	if sm.httpSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = sm.httpSrv.Shutdown(ctx)
	cancel()
	if sm.httpLn != nil {
		_ = sm.httpLn.Close()
	}
	sm.httpSrv = nil
	sm.httpLn = nil
	sm.httpPort = 0
	appendLog(sm.appDir, "HTTP stopped")
}

func (sm *ServiceManager) stopFTPLocked() {
	if sm.ftpSrv == nil {
		return
	}
	sm.ftpSrv.Stop()
	sm.ftpSrv = nil
	sm.ftpPort = 0
	appendLog(sm.appDir, "FTP stopped")
}

func (sm *ServiceManager) stopSMBLocked() {
	if sm.smbSrv == nil {
		sm.smbCancel = nil
		sm.smbPort = 0
		sm.smbKey = ""
		return
	}
	if sm.smbCancel != nil {
		sm.smbCancel()
	}
	_ = sm.smbSrv.Shutdown()
	sm.smbSrv = nil
	sm.smbCancel = nil
	sm.smbPort = 0
	sm.smbKey = ""
	appendLog(sm.appDir, "SMB stopped")
}

func (sm *ServiceManager) shutdown() {
	sm.mu.Lock()
	sm.stopHTTPLocked()
	sm.stopFTPLocked()
	sm.stopSMBLocked()
	sm.mu.Unlock()
	if sm.control != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = sm.control.Shutdown(ctx)
		cancel()
	}
}

func (sm *ServiceManager) stop() {
	sm.stopOnce.Do(func() { close(sm.stopCh) })
}

func (sm *ServiceManager) controlData(r *http.Request) ControlData {
	cfg := sm.app.configSnapshot()
	sm.mu.Lock()
	data := ControlData{
		Version:         version,
		IPs:             localIPv4s(),
		HTTPEnabled:     cfg.HTTPEnabled,
		HTTPPort:        cfg.HTTPPort,
		HTTPRunning:     sm.httpSrv != nil,
		HTTPError:       sm.httpErr,
		FTPEnabled:      cfg.FTPEnabled,
		FTPPort:         cfg.FTPPort,
		FTPRunning:      sm.ftpSrv != nil,
		FTPError:        sm.ftpErr,
		SMBEnabled:      cfg.SMBEnabled,
		LoggingEnabled:  cfg.LoggingEnabled,
		SMBRunning:      sm.smbSrv != nil,
		SMBPort:         sm.smbPort,
		SMBError:        sm.smbErr,
		SMBCredentials:  cfg.SMBNTHash != "",
		InternalEnabled: cfg.InternalEnabled,
		InternalStatus:  pathStatus("/mnt/ext1"),
		SDEnabled:       cfg.SDEnabled,
		SDStatus:        pathStatus("/mnt/ext2"),
		Username:        cfg.Username,
		UID:             os.Getuid(),
		Message:         r.URL.Query().Get("msg"),
		Error:           r.URL.Query().Get("err"),
	}
	sm.mu.Unlock()
	if data.SMBPort == 0 {
		data.SMBPort = smbListenPort(cfg)
	}
	data.AccessHost = requestHost(r)
	if data.AccessHost == "" && len(data.IPs) > 0 {
		data.AccessHost = data.IPs[0]
	}
	data.SMBAvailable, data.SMBReason = sm.smbAvailability()
	if data.SMBRunning {
		data.PortSMBAvailable = true
		data.PortSMBReason = "порт занят сервером WiFiFiles"
	} else {
		data.PortSMBAvailable, data.PortSMBReason = testListenPort(smbListenPort(cfg))
	}
	return data
}

func (sm *ServiceManager) smbAvailability() (bool, string) {
	cfg := sm.app.configSnapshot()
	if cfg.SMBNTHash == "" {
		return true, "модуль встроен; для первого запуска SMB введите пароль заново"
	}
	port := smbListenPort(cfg)
	return true, fmt.Sprintf("встроенный SMB2/3-сервер работает без root на порту %d; Проводнику Windows для нестандартного порта потребуется локальная переадресация", port)
}

func testListenPort(port int) (bool, string) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return false, err.Error()
	}
	_ = ln.Close()
	return true, "порт доступен процессу приложения"
}

func requestHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func isOwnAddress(ip string) bool {
	for _, own := range localIPv4s() {
		if ip == own {
			return true
		}
	}
	return false
}

func (sm *ServiceManager) controlAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOwnAddress(remoteIP(r)) {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok || !sm.app.checkCredentials(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="WiFiFiles control"`)
			http.Error(w, "Требуется логин и пароль WiFiFiles", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (sm *ServiceManager) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := sm.controlData(r)
	if err := sm.app.tmpl.ExecuteTemplate(w, "control", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (sm *ServiceManager) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Не удалось прочитать настройки"), http.StatusSeeOther)
		return
	}
	httpPort, err1 := strconv.Atoi(r.FormValue("http_port"))
	ftpPort, err2 := strconv.Atoi(r.FormValue("ftp_port"))
	smbPort, err3 := strconv.Atoi(r.FormValue("smb_port"))
	if err1 != nil || httpPort < 1024 || httpPort > 65535 || err2 != nil || ftpPort < 1024 || ftpPort > 65535 || err3 != nil || smbPort < 1024 || smbPort > 65535 || httpPort == ftpPort || httpPort == smbPort || ftpPort == smbPort || httpPort == controlPort || ftpPort == controlPort || smbPort == controlPort {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Порты должны быть разными числами 1024–65535 и не равны 8090"), http.StatusSeeOther)
		return
	}
	internalEnabled := r.FormValue("internal") == "on"
	sdEnabled := r.FormValue("sd") == "on"
	if !internalEnabled && !sdEnabled {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Выберите хотя бы одну память"), http.StatusSeeOther)
		return
	}

	sm.app.cfgMu.Lock()
	sm.app.cfg.HTTPEnabled = r.FormValue("http_enabled") == "on"
	sm.app.cfg.HTTPPort = httpPort
	sm.app.cfg.Port = httpPort
	sm.app.cfg.FTPEnabled = r.FormValue("ftp_enabled") == "on"
	sm.app.cfg.FTPPort = ftpPort
	sm.app.cfg.SMBEnabled = r.FormValue("smb_enabled") == "on"
	sm.app.cfg.SMBPort = smbPort
	sm.app.cfg.LoggingEnabled = r.FormValue("logging_enabled") == "on"
	sm.app.cfg.InternalEnabled = internalEnabled
	sm.app.cfg.SDEnabled = sdEnabled
	sm.app.cfgMu.Unlock()
	if err := sm.app.saveConfig(); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Не удалось сохранить: "+err.Error()), http.StatusSeeOther)
		return
	}
	if !sm.app.configSnapshot().LoggingEnabled {
		_ = os.Remove(unifiedLogPath)
	}
	sm.app.resetSessions()
	sm.applyServices()
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Настройки служб сохранены"), http.StatusSeeOther)
}

func (sm *ServiceManager) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Логин должен содержать 3–32 символа"), http.StatusSeeOther)
		return
	}
	if password != "" && (len(password) < 6 || len(password) > 128) {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Пароль должен содержать 6–128 символов"), http.StatusSeeOther)
		return
	}
	sm.app.cfgMu.Lock()
	oldUsername := sm.app.cfg.Username
	sm.app.cfg.Username = username
	if password != "" {
		salt, err := randomHex(16)
		if err != nil {
			sm.app.cfgMu.Unlock()
			http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		sm.app.cfg.PasswordSalt = salt
		sm.app.cfg.PasswordHash = passwordHash(salt, password)
		sm.app.cfg.SMBNTHash = hex.EncodeToString(smbntlm.NTHash(password))
		sm.app.cfg.DAVDigestHA1 = digestHA1(username, password)
	} else if oldUsername != username {
		// Digest HA1 contains the username. The factory password is known and can
		// be recalculated; a custom password must be entered again.
		if usesDefaultPassword(sm.app.cfg) {
			sm.app.cfg.DAVDigestHA1 = digestHA1(username, "650wifi")
		} else {
			sm.app.cfg.DAVDigestHA1 = ""
		}
	}
	sm.app.cfgMu.Unlock()
	if err := sm.app.saveConfig(); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Не удалось сохранить: "+err.Error()), http.StatusSeeOther)
		return
	}
	sm.app.resetSessions()
	sm.applyServices()
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Логин и пароль сохранены"), http.StatusSeeOther)
}

func (sm *ServiceManager) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:28px sans-serif;padding:30px}button{font:inherit;padding:18px}</style><h1>WiFiFiles выключается</h1><p>Можно закрыть браузер и вернуться к чтению.</p>`)
	go func() {
		time.Sleep(250 * time.Millisecond)
		sm.stop()
	}()
}

func nativeStatePath(appDir string) string {
	return filepath.Join(appDir, "native_state.ini")
}

func bool01(v bool) int {
	if v {
		return 1
	}
	return 0
}

func cleanINIValue(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

func writeNativeState(sm *ServiceManager, message string) {
	cfg := sm.app.configSnapshot()
	sm.mu.Lock()
	httpRunning := sm.httpSrv != nil
	ftpRunning := sm.ftpSrv != nil
	httpErr := sm.httpErr
	ftpErr := sm.ftpErr
	smbRunning := sm.smbSrv != nil
	smbPort := sm.smbPort
	smbErr := sm.smbErr
	sm.mu.Unlock()
	pid, running := readLivePID(sm.appDir)
	ips := localIPv4s()
	ip := ""
	if len(ips) > 0 {
		ip = ips[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "version=%s\n", version)
	fmt.Fprintf(&b, "running=%d\n", bool01(running))
	fmt.Fprintf(&b, "pid=%d\n", pid)
	fmt.Fprintf(&b, "ip=%s\n", cleanINIValue(ip))
	fmt.Fprintf(&b, "http_enabled=%d\n", bool01(cfg.HTTPEnabled))
	fmt.Fprintf(&b, "http_running=%d\n", bool01(httpRunning))
	fmt.Fprintf(&b, "http_port=%d\n", cfg.HTTPPort)
	fmt.Fprintf(&b, "http_error=%s\n", cleanINIValue(httpErr))
	fmt.Fprintf(&b, "ftp_enabled=%d\n", bool01(cfg.FTPEnabled))
	fmt.Fprintf(&b, "ftp_running=%d\n", bool01(ftpRunning))
	fmt.Fprintf(&b, "ftp_port=%d\n", cfg.FTPPort)
	fmt.Fprintf(&b, "ftp_error=%s\n", cleanINIValue(ftpErr))
	fmt.Fprintf(&b, "smb_enabled=%d\n", bool01(cfg.SMBEnabled))
	fmt.Fprintf(&b, "smb_running=%d\n", bool01(smbRunning))
	if smbPort == 0 {
		smbPort = smbListenPort(cfg)
	}
	fmt.Fprintf(&b, "smb_port=%d\n", smbPort)
	fmt.Fprintf(&b, "smb_error=%s\n", cleanINIValue(smbErr))
	fmt.Fprintf(&b, "smb_credentials_ready=%d\n", bool01(cfg.SMBNTHash != ""))
	fmt.Fprintf(&b, "internal_enabled=%d\n", bool01(cfg.InternalEnabled))
	fmt.Fprintf(&b, "sd_enabled=%d\n", bool01(cfg.SDEnabled))
	fmt.Fprintf(&b, "logging_enabled=%d\n", bool01(cfg.LoggingEnabled))
	fmt.Fprintf(&b, "username=%s\n", cleanINIValue(cfg.Username))
	fmt.Fprintf(&b, "language=%s\n", cleanINIValue(cfg.Language))
	fmt.Fprintf(&b, "password_is_default=%d\n", bool01(usesDefaultPassword(cfg)))
	fmt.Fprintf(&b, "uid=%d\n", os.Getuid())
	fmt.Fprintf(&b, "smb_available=1\n")
	fmt.Fprintf(&b, "message=%s\n", cleanINIValue(message))
	statePath := nativeStatePath(sm.appDir)
	_ = os.Remove(statePath)
	_ = os.WriteFile(statePath, []byte(b.String()), 0666)
	_ = os.Chmod(statePath, 0666)
}

func writeNativeStateStopped(appDir, message string) {
	app, err := newApp(persistentConfigPath)
	if err != nil {
		statePath := nativeStatePath(appDir)
		_ = os.Remove(statePath)
		_ = os.WriteFile(statePath, []byte("version="+version+"\nrunning=0\nmessage="+cleanINIValue(err.Error())+"\n"), 0666)
		_ = os.Chmod(statePath, 0666)
		return
	}
	cfg := app.configSnapshot()
	ips := localIPv4s()
	ip := ""
	if len(ips) > 0 {
		ip = ips[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "version=%s\nrunning=0\npid=0\nip=%s\n", version, cleanINIValue(ip))
	fmt.Fprintf(&b, "http_enabled=%d\nhttp_running=0\nhttp_port=%d\nhttp_error=\n", bool01(cfg.HTTPEnabled), cfg.HTTPPort)
	fmt.Fprintf(&b, "ftp_enabled=%d\nftp_running=0\nftp_port=%d\nftp_error=\n", bool01(cfg.FTPEnabled), cfg.FTPPort)
	fmt.Fprintf(&b, "smb_enabled=%d\nsmb_running=0\nsmb_port=%d\nsmb_error=\nsmb_credentials_ready=%d\n", bool01(cfg.SMBEnabled), smbListenPort(cfg), bool01(cfg.SMBNTHash != ""))
	fmt.Fprintf(&b, "internal_enabled=%d\nsd_enabled=%d\nlogging_enabled=%d\n", bool01(cfg.InternalEnabled), bool01(cfg.SDEnabled), bool01(cfg.LoggingEnabled))
	fmt.Fprintf(&b, "username=%s\nlanguage=%s\npassword_is_default=%d\nuid=%d\nsmb_available=1\n", cleanINIValue(cfg.Username), cleanINIValue(cfg.Language), bool01(usesDefaultPassword(cfg)), os.Getuid())
	fmt.Fprintf(&b, "message=%s\n", cleanINIValue(message))
	statePath := nativeStatePath(appDir)
	_ = os.Remove(statePath)
	_ = os.WriteFile(statePath, []byte(b.String()), 0666)
	_ = os.Chmod(statePath, 0666)
}

func startManagerDetached(appDir string) error {
	if _, ok := readLivePID(appDir); ok {
		return nil
	}
	app, err := newApp(persistentConfigPath)
	if err != nil {
		return err
	}
	if usesDefaultPassword(app.configSnapshot()) {
		return errors.New("перед первым запуском задайте новый пароль")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := openProcessOutput()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
	cmd := exec.Command(exe, "--manager")
	cmd.Dir = appDir
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	_ = logFile.Close()
	for i := 0; i < 50; i++ {
		if !processAlive(pid) {
			break
		}
		if data, err := os.ReadFile(filepath.Join(appDir, "wififiles.ready")); err == nil && strings.TrimSpace(string(data)) == strconv.Itoa(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("менеджер не подтвердил запуск")
}

func nativeStart(appDir string) {
	if err := startManagerDetached(appDir); err != nil {
		writeNativeStateStopped(appDir, "Ошибка запуска: "+err.Error())
		return
	}
	nativeStateCommand(appDir)
}

func nativeStop(appDir string) {
	_ = os.Remove(mobileTokenPath)
	stopServer(appDir)
	for i := 0; i < 30; i++ {
		if _, ok := readLivePID(appDir); !ok {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	writeNativeStateStopped(appDir, "Серверы выключены")
}

func nativeStateCommand(appDir string) {
	pid, ok := readLivePID(appDir)
	if !ok {
		writeNativeStateStopped(appDir, "")
		return
	}
	statePath := nativeStatePath(appDir)
	// WiFiFiles 0.2.x did not create native_state.ini. During the first native
	// launch, replace that still-running manager with the 0.3.x server binary.
	if _, err := os.Stat(statePath); err != nil {
		stopManagerPID(pid)
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
		if err := startManagerDetached(appDir); err != nil {
			writeNativeStateStopped(appDir, "Ошибка обновления сервера: "+err.Error())
		}
		return
	}
	// Replace a still-running manager from an older native version after the
	// binaries are copied over USB. This avoids requiring a manual reboot.
	data, err := os.ReadFile(statePath)
	if err == nil && !strings.Contains(string(data), "version="+version+"\n") {
		stopManagerPID(pid)
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
		_ = os.Remove(statePath)
		if err := startManagerDetached(appDir); err != nil {
			writeNativeStateStopped(appDir, "Ошибка обновления сервера: "+err.Error())
		}
		return
	}
	// Refresh the address displayed by the native app when Wi-Fi was connected
	// after the server had already started.
	if err == nil {
		ip := ""
		if ips := localIPv4s(); len(ips) > 0 {
			ip = ips[0]
		}
		lines := strings.Split(string(data), "\n")
		for i := range lines {
			if strings.HasPrefix(lines[i], "ip=") {
				lines[i] = "ip=" + cleanINIValue(ip)
			}
		}
		_ = os.WriteFile(statePath, []byte(strings.Join(lines, "\n")), 0644)
	}
}

func normalizeLanguage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ru", "en", "fr", "de":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func nativeSetLanguageFile(appDir string) {
	path := filepath.Join(appDir, "native_language.ini")
	data, err := os.ReadFile(path)
	if err != nil {
		writeNativeStateStopped(appDir, "Не найден файл языка")
		return
	}
	_ = os.Remove(path)
	vals := parseNativeApply(data)
	lang := normalizeLanguage(vals["language"])
	if lang == "" {
		writeNativeStateStopped(appDir, "Неподдерживаемый язык")
		return
	}
	app, err := newApp(persistentConfigPath)
	if err != nil {
		writeNativeStateStopped(appDir, err.Error())
		return
	}
	app.cfgMu.Lock()
	app.cfg.Language = lang
	app.cfg.ConfigVersion = 7
	app.cfgMu.Unlock()
	if err := app.saveConfig(); err != nil {
		writeNativeStateStopped(appDir, "Ошибка сохранения языка: "+err.Error())
		return
	}
	nativeStateCommand(appDir)
	statePath := nativeStatePath(appDir)
	if state, readErr := os.ReadFile(statePath); readErr == nil {
		lines := strings.Split(string(state), "\n")
		found := false
		for i := range lines {
			if strings.HasPrefix(lines[i], "language=") {
				lines[i] = "language=" + lang
				found = true
			}
		}
		if !found {
			lines = append(lines, "language="+lang)
		}
		_ = os.WriteFile(statePath, []byte(strings.Join(lines, "\n")), 0666)
		_ = os.Chmod(statePath, 0666)
	}
}

func writeNativeINI(path string, lines []string) {
	data := []byte(strings.Join(lines, "\n") + "\n")
	_ = os.WriteFile(path, data, 0666)
	_ = os.Chmod(path, 0666)
}

func nativeFolderListFile(appDir string) {
	data, err := os.ReadFile(nativeFolderRequestPath)
	if err != nil {
		writeNativeINI(nativeFolderListPath, []string{"error=Не найден запрос выбора папки"})
		return
	}
	_ = os.Remove(nativeFolderRequestPath)
	vals := parseNativeApply(data)
	app, err := newApp(persistentConfigPath)
	if err != nil {
		writeNativeINI(nativeFolderListPath, []string{"error=" + err.Error()})
		return
	}
	full, current, err := app.resolvePath(vals["path"], true)
	if err != nil {
		writeNativeINI(nativeFolderListPath, []string{"error=" + err.Error()})
		return
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		writeNativeINI(nativeFolderListPath, []string{"error=" + err.Error()})
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	lines := []string{"error=", "current=" + current, "parent=" + parentVirtual(current)}
	count := 0
	for _, entry := range entries {
		if count >= 160 || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") || isHiddenSystemPath(current, entry.Name()) {
			continue
		}
		child := current + "/" + entry.Name()
		if isProtectedVirtual(child) {
			continue
		}
		lines = append(lines, fmt.Sprintf("dir%d=%s", count, child), fmt.Sprintf("name%d=%s", count, entry.Name()))
		count++
	}
	lines = append(lines, fmt.Sprintf("count=%d", count))
	writeNativeINI(nativeFolderListPath, lines)
}

func nativeMobileQRFile(appDir string) {
	data, err := os.ReadFile(nativeMobileRequestPath)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=Не найден запрос QR-кода"})
		return
	}
	_ = os.Remove(nativeMobileRequestPath)
	vals := parseNativeApply(data)
	app, err := newApp(persistentConfigPath)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=" + err.Error()})
		return
	}
	_, target, err := app.resolvePath(vals["target"], true)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=" + err.Error()})
		return
	}
	ip := strings.TrimSpace(vals["ip"])
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=Некорректный IP-адрес"})
		return
	}
	cfg := app.configSnapshot()
	token, err := randomHex(8)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=" + err.Error()})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(vals["mode"]))
	if mode != "edit" {
		mode = "safe"
	}
	record := MobileTokenRecord{Token: token, Target: target, Mode: mode, Expires: time.Now().Add(20 * time.Minute).Unix()}
	recordData, err := json.Marshal(record)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=" + err.Error()})
		return
	}
	_ = os.Remove(mobileReceiptPath)
	tmp := mobileTokenPath + ".tmp"
	if err := os.WriteFile(tmp, recordData, 0600); err != nil || os.Rename(tmp, mobileTokenPath) != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=Не удалось создать временную ссылку"})
		return
	}
	mobileURL := fmt.Sprintf("http://%s:%d/m/%s", ip, cfg.HTTPPort, token)
	rows, err := qrVersion5L(mobileURL)
	if err != nil {
		writeNativeINI(nativeMobileQRPath, []string{"error=" + err.Error()})
		return
	}
	lines := []string{"error=", "target=" + target, "mode=" + mode, "url=" + mobileURL, fmt.Sprintf("expires=%d", record.Expires), fmt.Sprintf("size=%d", len(rows))}
	for i, row := range rows {
		lines = append(lines, fmt.Sprintf("row%d=%s", i, row))
	}
	writeNativeINI(nativeMobileQRPath, lines)
	appendLog(appDir, "Temporary mobile "+mode+" QR created for /"+target)
}

func parseNativeApply(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			out[line[:i]] = line[i+1:]
		}
	}
	return out
}

func parseNativeBool(v string) bool {
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
}

func nativeApplyFile(appDir string) {
	applyPath := filepath.Join(appDir, "native_apply.ini")
	data, err := os.ReadFile(applyPath)
	if err != nil {
		writeNativeStateStopped(appDir, "Не найден файл настроек")
		return
	}
	_ = os.Remove(applyPath)
	vals := parseNativeApply(data)
	app, err := newApp(persistentConfigPath)
	if err != nil {
		writeNativeStateStopped(appDir, err.Error())
		return
	}
	username := strings.TrimSpace(vals["username"])
	if len(username) < 3 || len(username) > 32 || strings.ContainsAny(username, "\r\n") {
		writeNativeStateStopped(appDir, "Логин должен содержать 3–32 символа")
		return
	}
	httpPort, err1 := strconv.Atoi(vals["http_port"])
	ftpPort, err2 := strconv.Atoi(vals["ftp_port"])
	smbPort, err3 := strconv.Atoi(vals["smb_port"])
	if err1 != nil || httpPort < 1024 || httpPort > 65535 || err2 != nil || ftpPort < 1024 || ftpPort > 65535 || err3 != nil || smbPort < 1024 || smbPort > 65535 || httpPort == ftpPort || httpPort == smbPort || ftpPort == smbPort || httpPort == controlPort || ftpPort == controlPort || smbPort == controlPort {
		writeNativeStateStopped(appDir, "Порты должны быть разными числами 1024–65535 и не равны 8090")
		return
	}
	internal := parseNativeBool(vals["internal_enabled"])
	sd := parseNativeBool(vals["sd_enabled"])
	if !internal && !sd {
		writeNativeStateStopped(appDir, "Включите хотя бы одну память")
		return
	}
	app.cfgMu.Lock()
	oldUsername := app.cfg.Username
	app.cfg.ConfigVersion = 7
	app.cfg.Username = username
	app.cfg.HTTPEnabled = parseNativeBool(vals["http_enabled"])
	app.cfg.HTTPPort = httpPort
	app.cfg.Port = httpPort
	app.cfg.FTPEnabled = parseNativeBool(vals["ftp_enabled"])
	app.cfg.FTPPort = ftpPort
	app.cfg.SMBEnabled = parseNativeBool(vals["smb_enabled"])
	app.cfg.SMBPort = smbPort
	app.cfg.LoggingEnabled = parseNativeBool(vals["logging_enabled"])
	if lang := normalizeLanguage(vals["language"]); lang != "" {
		app.cfg.Language = lang
	}
	app.cfg.InternalEnabled = internal
	app.cfg.SDEnabled = sd
	password := vals["password"]
	if password != "" {
		if len(password) < 6 || len(password) > 128 || strings.ContainsAny(password, "\r\n") {
			app.cfgMu.Unlock()
			writeNativeStateStopped(appDir, "Пароль должен содержать 6–128 символов")
			return
		}
		salt, e := randomHex(16)
		if e != nil {
			app.cfgMu.Unlock()
			writeNativeStateStopped(appDir, e.Error())
			return
		}
		app.cfg.PasswordSalt = salt
		app.cfg.PasswordHash = passwordHash(salt, password)
		app.cfg.SMBNTHash = hex.EncodeToString(smbntlm.NTHash(password))
		app.cfg.DAVDigestHA1 = digestHA1(username, password)
	} else if oldUsername != username {
		if usesDefaultPassword(app.cfg) {
			app.cfg.DAVDigestHA1 = digestHA1(username, "650wifi")
		} else {
			app.cfg.DAVDigestHA1 = ""
		}
	}
	if app.cfg.SMBEnabled && app.cfg.SMBNTHash == "" {
		app.cfgMu.Unlock()
		writeNativeStateStopped(appDir, "Для SMB введите пароль заново и нажмите Старт")
		return
	}
	app.cfgMu.Unlock()
	if err := app.saveConfig(); err != nil {
		writeNativeStateStopped(appDir, "Ошибка сохранения: "+err.Error())
		return
	}
	if !app.configSnapshot().LoggingEnabled {
		_ = os.Remove(unifiedLogPath)
	}
	if pid, ok := readLivePID(appDir); ok {
		stopManagerPID(pid)
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
	}
	if err := startManagerDetached(appDir); err != nil {
		writeNativeStateStopped(appDir, "Ошибка запуска: "+err.Error())
		return
	}
	// The manager writes the final detailed state; this message is visible if
	// the UI refreshes before the first service status update.
	time.Sleep(200 * time.Millisecond)
	nativeStateCommand(appDir)
}

func runServer(appDir string) {
	cfgPath := persistentConfigPath
	app, err := newApp(cfgPath)
	if err != nil {
		appendLog(appDir, "init: "+err.Error())
		return
	}

	go app.keepNetworkAlive()
	addr := fmt.Sprintf(":%d", app.cfg.Port)
	appendLog(appDir, fmt.Sprintf("WiFiFiles %s serving on %s", version, addr))
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		appendLog(appDir, "listen: "+err.Error())
		_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
		return
	}
	_ = os.WriteFile(filepath.Join(appDir, "wififiles.ready"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
	server := &http.Server{
		Addr:              addr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		appendLog(appDir, "server: "+err.Error())
	}
	_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
}

func toggleServer(appDir string) {
	pid, ok := readLivePID(appDir)
	if ok {
		stopManagerPID(pid)
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		writeStatus("WiFiFiles выключен.\nПовторный запуск приложения включит сервер.\n")
		appendLog(appDir, fmt.Sprintf("stopped pid %d", pid))
		return
	}

	exe, err := os.Executable()
	if err != nil {
		writeStatus("Ошибка запуска: не найден путь приложения.\n" + err.Error() + "\n")
		return
	}
	logFile, err := openProcessOutput()
	if err != nil {
		writeStatus("Ошибка подготовки вывода.\n" + err.Error() + "\n")
		return
	}
	readyPath := filepath.Join(appDir, "wififiles.ready")
	_ = os.Remove(readyPath)
	cmd := exec.Command(exe, "--serve")
	cmd.Dir = appDir
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		writeStatus("WiFiFiles не запустился.\n" + err.Error() + "\n")
		appendLog(appDir, "start: "+err.Error())
		return
	}
	pid = cmd.Process.Pid
	_ = os.WriteFile(filepath.Join(appDir, "wififiles.pid"), []byte(strconv.Itoa(pid)+"\n"), 0644)
	_ = cmd.Process.Release()
	_ = logFile.Close()

	ready := false
	for i := 0; i < 30; i++ {
		if !processAlive(pid) {
			break
		}
		data, err := os.ReadFile(readyPath)
		if err == nil && strings.TrimSpace(string(data)) == strconv.Itoa(pid) {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		writeStatus("WiFiFiles не запустился.\nОткройте WiFiFiles.log\n")
		writeDiagnostic(appDir)
		return
	}
	ips := localIPv4s()
	port := configuredPort(appDir)
	if len(ips) > 0 {
		writeStatus(fmt.Sprintf("WiFiFiles включен.\nАдрес: http://%s:%d\nЛогин: pocketbook\nПароль задаётся в приложении.\nПовторный запуск выключит сервер.\n", ips[0], port))
	} else {
		writeStatus(fmt.Sprintf("WiFiFiles включен на порту %d.\nПодключите PocketBook к Wi-Fi и посмотрите его IP-адрес в настройках сети.\nЛогин: pocketbook\nПароль задаётся в приложении.\nПовторный запуск выключит сервер.\n", port))
	}
	writeDiagnostic(appDir)
}

func stopServer(appDir string) {
	pid, ok := readLivePID(appDir)
	if ok {
		stopManagerPID(pid)
	}
	_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
	_ = os.Remove(filepath.Join(appDir, "wififiles.ready"))
	writeStatus("WiFiFiles выключен.\n")
}

func readLivePID(appDir string) (int, bool) {
	data, err := os.ReadFile(filepath.Join(appDir, "wififiles.pid"))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 || !processAlive(pid) {
		_ = os.Remove(filepath.Join(appDir, "wififiles.pid"))
		return 0, false
	}
	return pid, true
}

func configuredPort(appDir string) int {
	data, err := os.ReadFile(persistentConfigPath)
	if err == nil {
		var cfg Config
		if json.Unmarshal(data, &cfg) == nil && cfg.Port >= 1024 && cfg.Port <= 65535 {
			return cfg.Port
		}
	}
	return 8080
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func writeStatus(text string) {
	_ = os.MkdirAll(runtimeDirPath, 0700)
	_ = os.WriteFile(filepath.Join(runtimeDirPath, "status.txt"), []byte(text), 0600)
}

func loggingEnabledNow() bool {
	data, err := os.ReadFile(persistentConfigPath)
	if err != nil {
		return false
	}
	var value struct {
		LoggingEnabled bool `json:"logging_enabled"`
	}
	return json.Unmarshal(data, &value) == nil && value.LoggingEnabled
}

func openProcessOutput() (*os.File, error) {
	if loggingEnabledNow() {
		return os.OpenFile(unifiedLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	}
	return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
}

func appendLog(_ string, text string) {
	if !loggingEnabledNow() {
		return
	}
	f, err := os.OpenFile(unifiedLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), text)
}

func writeDiagnostic(appDir string) {
	if !loggingEnabledNow() {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "WiFiFiles diagnostic %s\n", version)
	fmt.Fprintf(&b, "time=%s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "goos=%s goarch=%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "uid=%d euid=%d gid=%d pid=%d\n", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getpid())
	fmt.Fprintf(&b, "executable=%s\n", os.Args[0])
	fmt.Fprintf(&b, "runtime=%s\n", appDir)
	fmt.Fprintf(&b, "config=%s\n", persistentConfigPath)
	fmt.Fprintf(&b, "ips=%s\n", strings.Join(localIPv4s(), ","))
	for _, path := range []string{"/mnt/ext1", "/mnt/ext2", "/ebrmain/bin/netagent", "/ebrmain/bin/auto_connect.app", appDir} {
		st, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(&b, "%s: %v\n", path, err)
		} else {
			fmt.Fprintf(&b, "%s: mode=%s size=%d\n", path, st.Mode(), st.Size())
		}
	}
	for _, port := range []int{4445, 8080, 8090, 2121} {
		conn, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
		if err != nil {
			fmt.Fprintf(&b, "port_%d=%v\n", port, err)
		} else {
			fmt.Fprintf(&b, "port_%d=open\n", port)
			_ = conn.Close()
		}
	}
	appendLog(appDir, strings.TrimRight(b.String(), "\n"))
}

func newApp(cfgPath string) (*App, error) {
	a := &App{
		cfgPath:  cfgPath,
		sessions: make(map[string]time.Time),
		roots: map[string]string{
			"internal": "/mnt/ext1",
			"sd":       "/mnt/ext2",
		},
		libraryTargets: make(map[string]struct{}),
		mobilePending:  make(map[string]map[string]struct{}),
		mobileTimers:   make(map[string]*time.Timer),
		mobileReceipts: make(map[string]map[string]MobileUploadResult),
	}
	if err := a.loadOrCreateConfig(); err != nil {
		return nil, err
	}
	t, err := template.New("pages").Funcs(template.FuncMap{
		// Base64url tokens avoid the double URL escaping performed by the
		// old Qt 4.8 browser and html/template for paths containing slashes.
		"pathkey": func(v string) string {
			return base64.RawURLEncoding.EncodeToString([]byte(v))
		},
	}).Parse(pageTemplates)
	if err != nil {
		return nil, err
	}
	a.tmpl = t
	return a, nil
}

func (a *App) loadOrCreateConfig() error {
	data, err := os.ReadFile(a.cfgPath)
	if err == nil {
		var cfg Config
		if json.Unmarshal(data, &cfg) == nil && cfg.Username != "" && cfg.PasswordHash != "" {
			migrated := false
			if cfg.ConfigVersion < 2 {
				if cfg.Port < 1024 || cfg.Port > 65535 {
					cfg.Port = 8080
				}
				cfg.HTTPEnabled = true
				cfg.HTTPPort = cfg.Port
				cfg.FTPEnabled = false
				cfg.FTPPort = 2121
				cfg.SMBEnabled = false
				cfg.InternalEnabled = true
				cfg.SDEnabled = true
				cfg.ConfigVersion = 2
				migrated = true
			}
			if cfg.HTTPPort < 1024 || cfg.HTTPPort > 65535 {
				cfg.HTTPPort = 8080
				migrated = true
			}
			if cfg.FTPPort < 1024 || cfg.FTPPort > 65535 {
				cfg.FTPPort = 2121
				migrated = true
			}
			if cfg.SMBPort < 1024 || cfg.SMBPort > 65535 || cfg.SMBPort == 445 {
				cfg.SMBPort = 4445
				migrated = true
			}
			if !cfg.InternalEnabled && !cfg.SDEnabled {
				cfg.InternalEnabled = true
				cfg.SDEnabled = true
				migrated = true
			}
			if usesDefaultPassword(cfg) {
				if cfg.SMBNTHash == "" {
					cfg.SMBNTHash = hex.EncodeToString(smbntlm.NTHash("650wifi"))
					migrated = true
				}
				if cfg.DAVDigestHA1 == "" {
					cfg.DAVDigestHA1 = digestHA1(cfg.Username, "650wifi")
					migrated = true
				}
			}
			if cfg.ConfigVersion < 7 {
				cfg.ConfigVersion = 7
				migrated = true
			}
			cfg.Port = cfg.HTTPPort
			a.cfg = cfg
			if migrated {
				return a.saveConfig()
			}
			return nil
		}
	}
	salt, err := randomHex(16)
	if err != nil {
		return err
	}
	a.cfg = Config{
		ConfigVersion:   7,
		Username:        "pocketbook",
		PasswordSalt:    salt,
		PasswordHash:    passwordHash(salt, "650wifi"),
		SMBNTHash:       hex.EncodeToString(smbntlm.NTHash("650wifi")),
		DAVDigestHA1:    digestHA1("pocketbook", "650wifi"),
		Port:            8080,
		HTTPEnabled:     true,
		HTTPPort:        8080,
		FTPEnabled:      false,
		FTPPort:         2121,
		SMBEnabled:      false,
		SMBPort:         4445,
		LoggingEnabled:  false,
		Language:        "",
		InternalEnabled: true,
		SDEnabled:       true,
	}
	return a.saveConfig()
}

func (a *App) saveConfig() error {
	a.cfgMu.RLock()
	data, err := json.MarshalIndent(a.cfg, "", "  ")
	a.cfgMu.RUnlock()
	if err != nil {
		return err
	}
	ownerUID, ownerGID := -1, -1
	if st, statErr := os.Stat(a.cfgPath); statErr == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			ownerUID, ownerGID = int(sys.Uid), int(sys.Gid)
		}
	}
	tmp := a.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if ownerUID >= 0 && os.Geteuid() == 0 {
		_ = os.Chown(tmp, ownerUID, ownerGID)
	}
	return os.Rename(tmp, a.cfgPath)
}

func (a *App) configSnapshot() Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

func (a *App) resetSessions() {
	a.sessMu.Lock()
	a.sessions = make(map[string]time.Time)
	a.sessMu.Unlock()
}

func (a *App) checkCredentials(username, password string) bool {
	cfg := a.configSnapshot()
	wantUser := []byte(cfg.Username)
	gotUser := []byte(username)
	userOK := len(wantUser) == len(gotUser) && subtle.ConstantTimeCompare(wantUser, gotUser) == 1
	gotHash := []byte(passwordHash(cfg.PasswordSalt, password))
	wantHash := []byte(cfg.PasswordHash)
	passOK := len(wantHash) == len(gotHash) && subtle.ConstantTimeCompare(wantHash, gotHash) == 1
	return userOK && passOK
}

func (a *App) enabledRoot(name string) bool {
	cfg := a.configSnapshot()
	switch name {
	case "internal":
		return cfg.InternalEnabled
	case "sd":
		return cfg.SDEnabled
	default:
		return false
	}
}

func (a *App) defaultRoot() string {
	cfg := a.configSnapshot()
	if cfg.InternalEnabled {
		return "internal"
	}
	if cfg.SDEnabled {
		return "sd"
	}
	return "internal"
}

func passwordHash(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

func usesDefaultPassword(cfg Config) bool {
	return passwordHash(cfg.PasswordSalt, "650wifi") == cfg.PasswordHash
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	dav := newDAVServer(a)
	mux.Handle("/dav", dav)
	mux.Handle("/dav/", dav)
	mux.HandleFunc("/m/", a.handleMobile)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.handleLogout)
	mux.HandleFunc("/download", a.auth(a.handleDownload))
	mux.HandleFunc("/upload", a.auth(a.handleUpload))
	mux.HandleFunc("/mkdir", a.auth(a.handleMkdir))
	mux.HandleFunc("/delete", a.auth(a.handleDelete))
	mux.HandleFunc("/settings", a.auth(a.handleSettings))
	mux.HandleFunc("/info", a.auth(a.handleInfo))
	mux.HandleFunc("/", a.auth(a.handleIndex))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("pbwf_session")
		if err != nil || !a.validSession(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (a *App) validSession(token string) bool {
	if token == "" {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	expiry, ok := a.sessions[token]
	if !ok || time.Now().After(expiry) {
		delete(a.sessions, token)
		return false
	}
	a.sessions[token] = time.Now().Add(12 * time.Hour)
	return true
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_ = a.tmpl.ExecuteTemplate(w, "login", PageData{Version: version})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")

	if !a.checkCredentials(user, pass) {
		time.Sleep(400 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		_ = a.tmpl.ExecuteTemplate(w, "login", PageData{Version: version, Error: "Неверный логин или пароль"})
		return
	}
	token, err := randomHex(32)
	if err != nil {
		http.Error(w, "cannot create session", http.StatusInternalServerError)
		return
	}
	a.sessMu.Lock()
	a.sessions[token] = time.Now().Add(12 * time.Hour)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "pbwf_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	http.Redirect(w, r, "/?k="+encodeVirtualPath(a.defaultRoot()), http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("pbwf_session"); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, c.Value)
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "pbwf_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	p := requestVirtualPath(r)
	if p == "" {
		p = a.defaultRoot()
	}
	full, virtual, err := a.resolvePath(p, true)
	if err != nil {
		a.renderIndex(w, p, err.Error(), "")
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		a.renderIndex(w, p, "Папка не найдена", "")
		return
	}
	a.renderIndex(w, virtual, "", r.URL.Query().Get("msg"))
}

func (a *App) renderIndex(w http.ResponseWriter, p, errMsg, msg string) {
	full, virtual, err := a.resolvePath(p, true)
	if err != nil {
		errMsg = err.Error()
		virtual = a.defaultRoot()
		full = a.roots[virtual]
	}
	list, err := os.ReadDir(full)
	if err != nil {
		errMsg = "Не удалось прочитать папку: " + err.Error()
	}
	entries := make([]Entry, 0, len(list))
	for _, de := range list {
		if isHiddenSystemPath(virtual, de.Name()) {
			continue
		}
		info, e := de.Info()
		if e != nil {
			continue
		}
		child := virtual + "/" + de.Name()
		entries = append(entries, Entry{
			Name:    de.Name(),
			Path:    child,
			IsDir:   de.IsDir(),
			Size:    humanSize(info.Size()),
			ModTime: info.ModTime().Format("02.01.2006 15:04"),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	parent := parentVirtual(virtual)
	var roots []string
	if a.enabledRoot("internal") {
		roots = append(roots, "internal")
	}
	if a.enabledRoot("sd") {
		if st, e := os.Stat(a.roots["sd"]); e == nil && st.IsDir() {
			roots = append(roots, "sd")
		}
	}
	a.cfgMu.RLock()
	username := a.cfg.Username
	a.cfgMu.RUnlock()
	_ = a.tmpl.ExecuteTemplate(w, "index", PageData{
		Version: version, Username: username, CurrentPath: virtual, ParentPath: parent,
		Entries: entries, Error: errMsg, Message: msg, Roots: roots,
		Breadcrumbs: breadcrumbItems(virtual), Destinations: a.uploadDestinations(virtual),
		FreeSpace: freeSpaceText(full),
	})
}

func breadcrumbItems(virtual string) []Breadcrumb {
	virtual = strings.Trim(strings.ReplaceAll(virtual, "\\", "/"), "/")
	if virtual == "" {
		return nil
	}
	parts := strings.Split(virtual, "/")
	out := make([]Breadcrumb, 0, len(parts))
	for i := range parts {
		path := strings.Join(parts[:i+1], "/")
		label := parts[i]
		if i == 0 {
			if parts[i] == "internal" {
				label = "Внутренняя память"
			} else if parts[i] == "sd" {
				label = "Карта SD"
			}
		}
		out = append(out, Breadcrumb{Path: path, Label: label})
	}
	return out
}

func (a *App) uploadDestinations(current string) []UploadDestination {
	const maxDestinations = 500
	const maxDepth = 12
	out := make([]UploadDestination, 0, 64)
	seenCurrent := false
	var walk func(full, virtual, label string, depth int)
	walk = func(full, virtual, label string, depth int) {
		if len(out) >= maxDestinations {
			return
		}
		selected := virtual == current
		if selected {
			seenCurrent = true
		}
		out = append(out, UploadDestination{Path: virtual, Label: label, Selected: selected})
		if depth >= maxDepth {
			return
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return
		}
		sort.Slice(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
		})
		for _, entry := range entries {
			if len(out) >= maxDestinations {
				return
			}
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") || isHiddenSystemPath(virtual, entry.Name()) {
				continue
			}
			childVirtual := virtual + "/" + entry.Name()
			if isProtectedVirtual(childVirtual) {
				continue
			}
			walk(filepath.Join(full, entry.Name()), childVirtual, label+" / "+entry.Name(), depth+1)
		}
	}
	if a.enabledRoot("internal") {
		walk(a.roots["internal"], "internal", "Внутренняя память", 0)
	}
	if a.enabledRoot("sd") {
		if st, err := os.Stat(a.roots["sd"]); err == nil && st.IsDir() {
			walk(a.roots["sd"], "sd", "Карта SD", 0)
		}
	}
	if current != "" && !seenCurrent {
		out = append([]UploadDestination{{Path: current, Label: "/" + current, Selected: true}}, out...)
	}
	return out
}

func loadMobileToken(token string) (MobileTokenRecord, error) {
	var record MobileTokenRecord
	data, err := os.ReadFile(mobileTokenPath)
	if err != nil {
		return record, errors.New("temporary link not found")
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, errors.New("temporary link is damaged")
	}
	if token == "" || subtle.ConstantTimeCompare([]byte(record.Token), []byte(token)) != 1 {
		return record, errors.New("temporary link is invalid")
	}
	if time.Now().Unix() > record.Expires {
		_ = os.Remove(mobileTokenPath)
		_ = os.Remove(mobileReceiptPath)
		return record, errors.New("temporary link has expired")
	}
	record.Mode = normalizeMobileMode(record.Mode)
	return record, nil
}

func mobileText(lang, ru, en, fr, de string) string {
	switch normalizeLanguage(lang) {
	case "en":
		return en
	case "fr":
		return fr
	case "de":
		return de
	default:
		return ru
	}
}

func mobileTargetLabel(lang, target string) string {
	parts := strings.Split(strings.Trim(target, "/"), "/")
	if len(parts) == 0 {
		return target
	}
	if parts[0] == "internal" {
		parts[0] = mobileText(lang, "Память ридера", "Reader storage", "Mémoire du lecteur", "Reader-Speicher")
	} else if parts[0] == "sd" {
		parts[0] = mobileText(lang, "Карта SD", "SD card", "Carte SD", "SD-Karte")
	}
	return strings.Join(parts, " / ")
}

func (a *App) renderMobileLegacy(w http.ResponseWriter, token, target string, uploaded []string, pageErr string) {
	cfg := a.configSnapshot()
	lang := cfg.Language
	title := mobileText(lang, "Передача с телефона по QR-коду", "Phone transfer by QR code", "Transfert depuis un téléphone par code QR", "Übertragung vom Telefon per QR-Code")
	choose := mobileText(lang, "Выберите книгу или несколько файлов", "Choose a book or several files", "Choisissez un livre ou plusieurs fichiers", "Buch oder mehrere Dateien auswählen")
	send := mobileText(lang, "Отправить в выбранную папку", "Send to the selected folder", "Envoyer vers le dossier choisi", "In den gewählten Ordner senden")
	destination := mobileText(lang, "Папка на ридере", "Folder on the reader", "Dossier sur le lecteur", "Ordner auf dem Reader")
	freeLabel := mobileText(lang, "Свободное место", "Free space", "Espace libre", "Freier Speicher")
	note := mobileText(lang, "Ссылка действует 20 минут. Файл с совпадающим именем не заменяется: к новому имени добавляется номер.", "The link is valid for 20 minutes. An existing file is never replaced; a number is added to the new filename.", "Le lien reste valide pendant 20 minutes. Un fichier existant n’est jamais remplacé : un numéro est ajouté au nouveau nom.", "Der Link ist 20 Minuten gültig. Vorhandene Dateien werden nicht ersetzt; der neue Dateiname erhält eine Nummer.")
	done := mobileText(lang, "Передача завершена", "Transfer complete", "Transfert terminé", "Übertragung abgeschlossen")
	more := mobileText(lang, "Библиотека ридера обновляется. Через несколько секунд книга появится в разделе «Новые». Можно отправить ещё одну книгу.", "The reader library is updating. The book should appear under New in a few seconds. You can send another book.", "La bibliothèque du lecteur est en cours de mise à jour. Le livre devrait apparaître dans « Nouveaux » dans quelques secondes. Vous pouvez envoyer un autre livre.", "Die Bibliothek des Readers wird aktualisiert. Das Buch sollte in wenigen Sekunden unter „Neu“ erscheinen. Sie können ein weiteres Buch senden.")
	preparing := mobileText(lang, "Подготовка передачи…", "Preparing transfer…", "Préparation du transfert…", "Übertragung wird vorbereitet…")
	transferring := mobileText(lang, "Передача", "Transferring", "Transfert", "Übertragung")
	networkError := mobileText(lang, "Не удалось передать файл. Проверьте Wi‑Fi и повторите попытку.", "The file could not be transferred. Check Wi-Fi and try again.", "Le fichier n’a pas pu être transféré. Vérifiez le Wi-Fi et réessayez.", "Die Datei konnte nicht übertragen werden. Prüfen Sie das WLAN und versuchen Sie es erneut.")
	free := mobileText(lang, "не удалось определить", "unavailable", "indisponible", "nicht verfügbar")
	if targetDir, _, err := a.resolvePath(target, true); err == nil {
		free = freeSpaceText(targetDir)
	}

	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>WiFiFiles</title><style>body{font-family:system-ui,"Segoe UI",sans-serif;margin:0;background:#f2f2f7;color:#111;padding:max(18px,env(safe-area-inset-top)) 16px max(24px,env(safe-area-inset-bottom))}.wrap{max-width:620px;margin:auto}.card{background:white;border-radius:16px;padding:20px;margin:14px 0;box-shadow:0 1px 4px #0002}h1{font-size:30px;line-height:1.15;margin:8px 0 18px}.path{font-weight:700;word-break:break-word;background:#f2f2f7;border-radius:10px;padding:12px}input[type=file]{font-size:18px;width:100%;box-sizing:border-box;padding:14px;border:2px dashed #777;border-radius:12px;background:#fafafa}button{width:100%;font-size:20px;font-weight:700;padding:16px;border:0;border-radius:12px;background:#111;color:white;margin-top:16px}button:disabled{opacity:.55}.ok{background:#e9f8ed;border-left:5px solid #248a3d;padding:14px;border-radius:10px}.err{background:#fff0f0;border-left:5px solid #b00020;padding:14px;border-radius:10px}.muted{color:#555;line-height:1.4}ul{padding-left:22px}.progress{display:none;margin-top:16px}.progress.visible{display:block}progress{width:100%;height:22px}.progress-text{margin-top:7px;font-weight:700}</style></head><body><div class="wrap">`)
	fmt.Fprintf(w, "<h1>%s</h1>", template.HTMLEscapeString(title))
	if pageErr != "" {
		fmt.Fprintf(w, "<div class=\"err\">%s</div>", template.HTMLEscapeString(pageErr))
	}
	if len(uploaded) > 0 {
		fmt.Fprintf(w, "<div class=\"ok\"><strong>%s</strong><ul>", template.HTMLEscapeString(done))
		for _, name := range uploaded {
			fmt.Fprintf(w, "<li>%s</li>", template.HTMLEscapeString(name))
		}
		fmt.Fprintf(w, "</ul>%s</div>", template.HTMLEscapeString(more))
	}
	fmt.Fprintf(w, "<div class=\"card\"><div class=\"muted\">%s</div><div class=\"path\">%s</div><p class=\"muted\"><strong>%s:</strong> %s</p></div>", template.HTMLEscapeString(destination), template.HTMLEscapeString(mobileTargetLabel(lang, target)), template.HTMLEscapeString(freeLabel), template.HTMLEscapeString(free))
	fmt.Fprintf(w, "<form id=\"mobile-upload-form\" class=\"card\" method=\"post\" enctype=\"multipart/form-data\" action=\"/m/%s/upload\"><label><strong>%s</strong><br><br><input id=\"mobile-files\" type=\"file\" name=\"files\" multiple required></label><button id=\"mobile-send\" type=\"submit\">%s</button><div id=\"mobile-progress\" class=\"progress\"><progress id=\"mobile-progress-bar\" max=\"100\" value=\"0\"></progress><div id=\"mobile-progress-text\" class=\"progress-text\"></div></div></form>", template.HTMLEscapeString(token), template.HTMLEscapeString(choose), template.HTMLEscapeString(send))
	fmt.Fprintf(w, "<p class=\"muted\">%s</p>", template.HTMLEscapeString(note))
	fmt.Fprintf(w, `<script>(function(){var form=document.getElementById('mobile-upload-form'),button=document.getElementById('mobile-send'),box=document.getElementById('mobile-progress'),bar=document.getElementById('mobile-progress-bar'),text=document.getElementById('mobile-progress-text');if(!form||!window.XMLHttpRequest)return;form.addEventListener('submit',function(e){e.preventDefault();button.disabled=true;box.className='progress visible';bar.value=0;text.textContent=%s;var xhr=new XMLHttpRequest();xhr.open('POST',form.action,true);xhr.upload.onprogress=function(ev){if(!ev.lengthComputable)return;var pct=Math.max(0,Math.min(100,Math.round(ev.loaded*100/ev.total)));bar.value=pct;text.textContent=%s+' — '+pct+'%%';};xhr.onerror=function(){button.disabled=false;text.textContent=%s;};xhr.onload=function(){if(xhr.status>=200&&xhr.status<300){document.open();document.write(xhr.responseText);document.close();}else{button.disabled=false;text.textContent=xhr.responseText||%s;}};xhr.send(new FormData(form));});})();</script>`, strconv.Quote(preparing), strconv.Quote(transferring), strconv.Quote(networkError), strconv.Quote(networkError))
	fmt.Fprint(w, `</div></body></html>`)
}

func (a *App) handleMobileLegacy(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "m" {
		http.NotFound(w, r)
		return
	}
	token := parts[1]
	record, err := loadMobileToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}
	targetDir, target, err := a.resolvePath(record.Target, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		a.renderMobileLegacy(w, token, target, nil, "")
		return
	}
	if len(parts) != 3 || parts[2] != "upload" || r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		a.renderMobileLegacy(w, token, target, nil, "Upload error: "+err.Error())
		return
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		a.renderMobileLegacy(w, token, target, nil, mobileText(a.configSnapshot().Language, "Файл не выбран", "No file selected", "Aucun fichier sélectionné", "Keine Datei ausgewählt"))
		return
	}
	if err := ensureUploadSpace(targetDir, files); err != nil {
		a.renderMobileLegacy(w, token, target, nil, err.Error())
		return
	}
	uploaded := make([]string, 0, len(files))
	for _, hdr := range files {
		name, err := saveUploadAutoRename(targetDir, hdr)
		if err != nil {
			a.renderMobileLegacy(w, token, target, uploaded, "Upload error: "+err.Error())
			return
		}
		uploaded = append(uploaded, name)
		a.scheduleLibraryRefresh(filepath.Join(targetDir, name))
	}
	appendLog(runtimeDirPath, fmt.Sprintf("Mobile upload to /%s: %s", target, strings.Join(uploaded, ", ")))
	a.renderMobileLegacy(w, token, target, uploaded, "")
}

func saveUploadAutoRename(dir string, hdr *multipart.FileHeader) (string, error) {
	name, err := safeUploadName(hdr.Filename)
	if err != nil {
		return "", err
	}
	tmpPath, err := writeMultipartTemp(dir, hdr)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpPath)
	return commitTempAutoRename(dir, name, tmpPath)
}

func (a *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	full, _, err := a.resolvePath(requestVirtualPath(r), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(filepath.Base(full))))
	http.ServeFile(w, r, full)
}

func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "upload error: "+err.Error(), http.StatusBadRequest)
		return
	}

	type pendingUpload struct {
		name    string
		tmpPath string
	}
	var pending []pendingUpload
	defer func() {
		for _, item := range pending {
			if item.tmpPath != "" {
				_ = os.Remove(item.tmpPath)
			}
		}
	}()

	targetVirtual := ""
	target := ""
	overwrite := false
	spaceChecked := false
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			http.Error(w, "upload error: "+nextErr.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "target":
			value, readErr := readMultipartText(part, 4096)
			_ = part.Close()
			if readErr != nil {
				http.Error(w, "upload error: "+readErr.Error(), http.StatusBadRequest)
				return
			}
			targetVirtual = strings.TrimSpace(value)
		case "overwrite":
			value, readErr := readMultipartText(part, 16)
			_ = part.Close()
			if readErr != nil {
				http.Error(w, "upload error: "+readErr.Error(), http.StatusBadRequest)
				return
			}
			overwrite = strings.TrimSpace(value) == "1"
		case "files":
			if target == "" {
				if targetVirtual == "" {
					targetVirtual = requestVirtualPath(r)
				}
				target, targetVirtual, err = a.resolvePath(targetVirtual, true)
				if err != nil {
					_ = part.Close()
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			if !spaceChecked {
				if err := ensureRequestUploadSpace(target, r.ContentLength); err != nil {
					_ = part.Close()
					redirectMsg(w, r, targetVirtual, err.Error())
					return
				}
				spaceChecked = true
			}
			name, nameErr := safeUploadName(part.FileName())
			if nameErr != nil {
				_ = part.Close()
				http.Error(w, "upload error: "+nameErr.Error(), http.StatusBadRequest)
				return
			}
			tmpPath, _, writeErr := writeStreamTemp(target, part)
			_ = part.Close()
			if writeErr != nil {
				http.Error(w, "upload error: "+writeErr.Error(), http.StatusInternalServerError)
				return
			}
			pending = append(pending, pendingUpload{name: name, tmpPath: tmpPath})
		default:
			_ = part.Close()
		}
	}

	if len(pending) == 0 {
		if targetVirtual == "" {
			targetVirtual = requestVirtualPath(r)
		}
		redirectMsg(w, r, targetVirtual, "Файл не выбран")
		return
	}
	if target == "" {
		target, targetVirtual, err = a.resolvePath(targetVirtual, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	seen := make(map[string]struct{}, len(pending))
	if !overwrite {
		for _, item := range pending {
			key := strings.ToLower(item.name)
			if _, exists := seen[key]; exists {
				redirectMsg(w, r, targetVirtual, "Один файл выбран несколько раз: "+item.name)
				return
			}
			seen[key] = struct{}{}
			if _, statErr := os.Stat(filepath.Join(target, item.name)); statErr == nil {
				redirectMsg(w, r, targetVirtual, "Файл уже существует: "+item.name+". Для замены отметьте соответствующий пункт.")
				return
			} else if !errors.Is(statErr, os.ErrNotExist) {
				http.Error(w, "upload error: "+statErr.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	for i := range pending {
		item := &pending[i]
		finalPath := filepath.Join(target, item.name)
		if err := os.Rename(item.tmpPath, finalPath); err != nil {
			http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		item.tmpPath = ""
		a.scheduleLibraryRefresh(finalPath)
	}
	redirectMsg(w, r, targetVirtual, "Загрузка завершена")
}

func safeUploadName(filename string) (string, error) {
	name := filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	if name == "." || name == "" || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid filename")
	}
	return name, nil
}

func saveUpload(dir string, hdr *multipart.FileHeader, overwrite bool) error {
	name, err := safeUploadName(hdr.Filename)
	if err != nil {
		return err
	}
	finalPath := filepath.Join(dir, name)
	if !overwrite {
		if _, statErr := os.Stat(finalPath); statErr == nil {
			return os.ErrExist
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	tmpPath, err := writeMultipartTemp(dir, hdr)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	return nil
}

func (a *App) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parentV := r.FormValue("p")
	parent, _, err := a.resolvePath(parentV, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == "" || strings.ContainsRune(name, 0) {
		redirectMsg(w, r, parentV, "Некорректное имя папки")
		return
	}
	if err := os.Mkdir(filepath.Join(parent, name), 0755); err != nil {
		redirectMsg(w, r, parentV, "Не удалось создать папку: "+err.Error())
		return
	}
	redirectMsg(w, r, parentV, "Папка создана")
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	virtual := r.FormValue("p")
	full, cleanV, err := a.resolvePath(virtual, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Protect virtual volume roots and app/system folders.
	if cleanV == "internal" || cleanV == "sd" || isProtectedVirtual(cleanV) {
		http.Error(w, "protected path", http.StatusForbidden)
		return
	}
	if err := os.Remove(full); err != nil {
		redirectMsg(w, r, parentVirtual(cleanV), "Не удалось удалить: "+err.Error())
		return
	}
	redirectMsg(w, r, parentVirtual(cleanV), "Удалено")
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.cfgMu.RLock()
		u := a.cfg.Username
		a.cfgMu.RUnlock()
		_ = a.tmpl.ExecuteTemplate(w, "settings", PageData{Version: version, Username: u})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 || len(password) < 6 || len(password) > 128 {
		w.WriteHeader(http.StatusBadRequest)
		_ = a.tmpl.ExecuteTemplate(w, "settings", PageData{Version: version, Username: username, Error: "Логин: 3–32 символа; пароль: 6–128 символов"})
		return
	}
	salt, err := randomHex(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.cfgMu.Lock()
	a.cfg.Username = username
	a.cfg.PasswordSalt = salt
	a.cfg.PasswordHash = passwordHash(salt, password)
	a.cfg.SMBNTHash = hex.EncodeToString(smbntlm.NTHash(password))
	a.cfg.DAVDigestHA1 = digestHA1(username, password)
	a.cfgMu.Unlock()
	if err := a.saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.sessMu.Lock()
	a.sessions = make(map[string]time.Time)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "pbwf_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleInfo(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	ips := localIPv4s()
	cfg := a.configSnapshot()
	port := cfg.HTTPPort
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "WiFiFiles %s\nHostname: %s\nUID: %d\nPort: %d\nWebDAV: /dav/\nIP: %s\nInternal: %s\nSD: %s\n", version, host, os.Getuid(), port, strings.Join(ips, ", "), pathStatus("/mnt/ext1"), pathStatus("/mnt/ext2"))
}

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
		return "", "", errors.New("эта память отключена в настройках")
	}
	if rootName == "sd" {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			return "", "", errors.New("карта памяти не найдена")
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
	return full, clean, nil
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
	// Only hide reserved entries at the root of each storage. A user-created
	// folder with the same name deeper in the tree remains visible.
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

type FTPServer struct {
	app    *App
	appDir string
	port   int
	ln     *net.TCPListener
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewFTPServer(app *App, appDir string, port int) *FTPServer {
	return &FTPServer{app: app, appDir: appDir, port: port, stopCh: make(chan struct{})}
}

func (s *FTPServer) Start() error {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *FTPServer) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (s *FTPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.AcceptTCP()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				appendLog(s.appDir, "ftp accept: "+err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		_ = conn.SetKeepAlive(true)
		_ = conn.SetKeepAlivePeriod(60 * time.Second)
		s.wg.Add(1)
		go func(c *net.TCPConn) {
			defer s.wg.Done()
			defer c.Close()
			(&ftpSession{server: s, conn: c, rw: bufio.NewReadWriter(bufio.NewReaderSize(c, 16*1024), bufio.NewWriterSize(c, 16*1024)), cwd: "/"}).run()
		}(conn)
	}
}

type ftpSession struct {
	server     *FTPServer
	conn       *net.TCPConn
	rw         *bufio.ReadWriter
	username   string
	authed     bool
	cwd        string
	pasv       *net.TCPListener
	renameFrom string
	rest       int64
}

func (s *ftpSession) run() {
	s.reply(220, "WiFiFiles FTP %s ready", version)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(strings.TrimSpace(cmd))
		arg = strings.TrimSpace(arg)
		if cmd == "QUIT" {
			s.reply(221, "До свидания")
			return
		}
		if !s.authed && cmd != "USER" && cmd != "PASS" && cmd != "SYST" && cmd != "FEAT" && cmd != "OPTS" && cmd != "NOOP" && cmd != "CLNT" && cmd != "AUTH" {
			s.reply(530, "Сначала выполните вход")
			continue
		}
		if !s.handle(cmd, arg) {
			return
		}
	}
}

func (s *ftpSession) handle(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.username = arg
		s.authed = false
		s.reply(331, "Введите пароль")
	case "PASS":
		if s.server.app.checkCredentials(s.username, arg) {
			s.authed = true
			s.reply(230, "Вход выполнен")
		} else {
			time.Sleep(350 * time.Millisecond)
			s.reply(530, "Неверный логин или пароль")
		}
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		s.multiline(211, []string{"Features:", " UTF8", " EPSV", " PASV", " SIZE", " MDTM", " REST STREAM", " MLST type*;size*;modify*;", " MLSD", "End"})
	case "OPTS":
		if strings.EqualFold(arg, "UTF8 ON") {
			s.reply(200, "UTF8 включён")
		} else {
			s.reply(200, "OK")
		}
	case "CLNT", "NOOP":
		s.reply(200, "OK")
	case "AUTH":
		s.reply(502, "TLS не поддерживается; используйте только доверенную локальную сеть")
	case "PBSZ", "PROT":
		s.reply(502, "Команда не поддерживается")
	case "TYPE":
		s.reply(200, "Тип установлен")
	case "MODE":
		if strings.EqualFold(arg, "S") {
			s.reply(200, "Режим S")
		} else {
			s.reply(504, "Поддерживается только режим S")
		}
	case "STRU":
		if strings.EqualFold(arg, "F") {
			s.reply(200, "Структура F")
		} else {
			s.reply(504, "Поддерживается только структура F")
		}
	case "PWD", "XPWD":
		s.reply(257, "%q is current directory", s.cwd)
	case "CWD", "XCWD":
		s.changeDir(arg)
	case "CDUP":
		s.changeDir("..")
	case "PASV":
		s.enterPassive(false)
	case "EPSV":
		s.enterPassive(true)
	case "PORT", "EPRT":
		s.reply(502, "Активный FTP не поддерживается; используйте пассивный режим")
	case "LIST":
		s.sendList(arg, false, false)
	case "NLST":
		s.sendList(arg, true, false)
	case "MLSD":
		s.sendList(arg, false, true)
	case "MLST":
		s.sendMLST(arg)
	case "RETR":
		s.retrieve(arg)
	case "STOR":
		s.store(arg, false)
	case "APPE":
		s.store(arg, true)
	case "REST":
		n, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || n < 0 {
			s.reply(501, "Некорректная позиция")
		} else {
			s.rest = n
			s.reply(350, "Позиция сохранена")
		}
	case "SIZE":
		s.size(arg)
	case "MDTM":
		s.mdtm(arg)
	case "DELE":
		s.deleteFile(arg)
	case "MKD", "XMKD":
		s.makeDir(arg)
	case "RMD", "XRMD":
		s.removeDir(arg)
	case "RNFR":
		s.renameFromCmd(arg)
	case "RNTO":
		s.renameToCmd(arg)
	case "STAT":
		if arg == "" {
			s.reply(211, "WiFiFiles FTP работает; cwd=%s", s.cwd)
		} else {
			s.reply(502, "STAT для пути не поддерживается")
		}
	case "ABOR":
		s.closePassive()
		s.reply(226, "Передача остановлена")
	case "SITE", "ALLO", "LANG":
		s.reply(200, "OK")
	default:
		s.reply(502, "Команда %s не поддерживается", cmd)
	}
	return true
}

func (s *ftpSession) reply(code int, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(s.rw, "%d %s\r\n", code, fmt.Sprintf(format, args...))
	_ = s.rw.Flush()
}

func (s *ftpSession) multiline(code int, lines []string) {
	if len(lines) == 0 {
		s.reply(code, "")
		return
	}
	_, _ = fmt.Fprintf(s.rw, "%d-%s\r\n", code, lines[0])
	for _, line := range lines[1 : len(lines)-1] {
		_, _ = fmt.Fprintf(s.rw, "%s\r\n", line)
	}
	_, _ = fmt.Fprintf(s.rw, "%d %s\r\n", code, lines[len(lines)-1])
	_ = s.rw.Flush()
}

func (s *ftpSession) virtualPath(arg string) string {
	arg = strings.TrimSpace(strings.ReplaceAll(arg, "\\", "/"))
	if arg == "" {
		return s.cwd
	}
	if strings.HasPrefix(arg, "/") {
		return pathpkg.Clean(arg)
	}
	return pathpkg.Clean(pathpkg.Join(s.cwd, arg))
}

func (s *ftpSession) resolve(arg string, allowRoot bool) (string, string, error) {
	v := s.virtualPath(arg)
	if v == "/" || v == "." {
		if allowRoot {
			return "", "/", nil
		}
		return "", "", errors.New("корень защищён")
	}
	clean := strings.TrimPrefix(v, "/")
	full, virtual, err := s.server.app.resolvePath(clean, allowRoot)
	if err != nil {
		return "", "", err
	}
	return full, "/" + virtual, nil
}

func (s *ftpSession) changeDir(arg string) {
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if virtual == "/" {
		s.cwd = "/"
		s.reply(250, "Каталог изменён")
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		s.reply(550, "Каталог не найден")
		return
	}
	s.cwd = virtual
	s.reply(250, "Каталог изменён")
}

func (s *ftpSession) enterPassive(epsv bool) {
	s.closePassive()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		s.reply(425, "Не удалось открыть пассивный порт")
		return
	}
	s.pasv = ln
	port := ln.Addr().(*net.TCPAddr).Port
	if epsv {
		s.reply(229, "Entering Extended Passive Mode (|||%d|)", port)
		return
	}
	ip := s.conn.LocalAddr().(*net.TCPAddr).IP.To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		ips := localIPv4s()
		if len(ips) > 0 {
			ip = net.ParseIP(ips[0]).To4()
		}
	}
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	s.reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], port/256, port%256)
}

func (s *ftpSession) closePassive() {
	if s.pasv != nil {
		_ = s.pasv.Close()
		s.pasv = nil
	}
}

func (s *ftpSession) acceptData() (net.Conn, error) {
	if s.pasv == nil {
		return nil, errors.New("сначала включите пассивный режим")
	}
	ln := s.pasv
	s.pasv = nil
	_ = ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	return conn, nil
}

func stripListOptions(arg string) string {
	fields := strings.Fields(arg)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		fields = fields[1:]
	}
	return strings.Join(fields, " ")
}

type ftpListItem struct {
	name string
	info os.FileInfo
}

func (s *ftpSession) listItems(arg string) ([]ftpListItem, error) {
	arg = stripListOptions(arg)
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		return nil, err
	}
	if virtual == "/" {
		var out []ftpListItem
		for _, name := range []string{"internal", "sd"} {
			if !s.server.app.enabledRoot(name) {
				continue
			}
			st, err := os.Stat(s.server.app.roots[name])
			if err == nil && st.IsDir() {
				out = append(out, ftpListItem{name: name, info: st})
			}
		}
		return out, nil
	}
	st, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []ftpListItem{{name: filepath.Base(full), info: st}}, nil
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := make([]ftpListItem, 0, len(entries))
	parent := strings.TrimPrefix(virtual, "/")
	for _, de := range entries {
		if isHiddenSystemPath(parent, de.Name()) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, ftpListItem{name: de.Name(), info: info})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].info.IsDir() != out[j].info.IsDir() {
			return out[i].info.IsDir()
		}
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	return out, nil
}

func (s *ftpSession) sendList(arg string, namesOnly, machine bool) {
	items, err := s.listItems(arg)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	data, err := s.acceptData()
	if err != nil {
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Открываю соединение данных")
	bw := bufio.NewWriterSize(data, 16*1024)
	for _, item := range items {
		if namesOnly {
			_, _ = fmt.Fprintf(bw, "%s\r\n", item.name)
		} else if machine {
			typeName := "file"
			if item.info.IsDir() {
				typeName = "dir"
			}
			_, _ = fmt.Fprintf(bw, "type=%s;size=%d;modify=%s; %s\r\n", typeName, item.info.Size(), item.info.ModTime().UTC().Format("20060102150405"), item.name)
		} else {
			mode := item.info.Mode().String()
			_, _ = fmt.Fprintf(bw, "%s 1 pocketbook pocketbook %12d %s %s\r\n", mode, item.info.Size(), item.info.ModTime().Format("Jan _2 15:04"), item.name)
		}
	}
	_ = bw.Flush()
	_ = data.Close()
	s.reply(226, "Передача завершена")
}

func (s *ftpSession) sendMLST(arg string) {
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if virtual == "/" {
		s.multiline(250, []string{"Listing", " type=dir;size=0;modify=" + time.Now().UTC().Format("20060102150405") + "; /", "End"})
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		s.reply(550, "Не найдено")
		return
	}
	typeName := "file"
	if st.IsDir() {
		typeName = "dir"
	}
	s.multiline(250, []string{"Listing", fmt.Sprintf(" type=%s;size=%d;modify=%s; %s", typeName, st.Size(), st.ModTime().UTC().Format("20060102150405"), pathpkg.Base(virtual)), "End"})
}

func (s *ftpSession) retrieve(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	f, err := os.Open(full)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		s.reply(550, "Это не файл")
		return
	}
	if s.rest > 0 {
		_, _ = f.Seek(s.rest, io.SeekStart)
		s.rest = 0
	}
	data, err := s.acceptData()
	if err != nil {
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Открываю соединение данных (%d байт)", st.Size())
	_, copyErr := io.Copy(data, f)
	_ = data.Close()
	if copyErr != nil {
		s.reply(426, "Передача прервана: %s", copyErr.Error())
		return
	}
	s.reply(226, "Передача завершена")
}

func (s *ftpSession) store(arg string, appendMode bool) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	resumeOffset := s.rest
	s.rest = 0

	// A regular STOR is written to a temporary file and renamed only after a
	// successful fsync. APPE and REST keep their standard in-place semantics.
	atomicWrite := !appendMode && resumeOffset == 0
	writePath := full
	var tmpPath string
	if atomicWrite {
		tmp, createErr := os.CreateTemp(filepath.Dir(full), ".wififiles-ftp-*.part")
		if createErr != nil {
			s.reply(550, "%s", createErr.Error())
			return
		}
		writePath = tmp.Name()
		tmpPath = writePath
		chmodBestEffort(tmpPath, 0644)
		_ = tmp.Close()
		defer os.Remove(tmpPath)
	}

	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else if resumeOffset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(writePath, flags, 0644)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if resumeOffset > 0 {
		if _, err := f.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = f.Close()
			s.reply(550, "%s", err.Error())
			return
		}
	}
	data, err := s.acceptData()
	if err != nil {
		_ = f.Close()
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Открываю соединение данных")
	_, copyErr := io.Copy(f, data)
	_ = data.Close()
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		s.reply(426, "Передача прервана: %s", copyErr.Error())
		return
	}
	if syncErr != nil {
		s.reply(451, "Ошибка записи: %s", syncErr.Error())
		return
	}
	if closeErr != nil {
		s.reply(451, "Ошибка закрытия файла: %s", closeErr.Error())
		return
	}
	if atomicWrite {
		if err := os.Rename(tmpPath, full); err != nil {
			s.reply(451, "Ошибка завершения записи: %s", err.Error())
			return
		}
	}
	s.server.app.scheduleLibraryRefresh(full)
	s.reply(226, "Файл сохранён")
}

func (s *ftpSession) size(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		s.reply(550, "Файл не найден")
		return
	}
	s.reply(213, "%d", st.Size())
}

func (s *ftpSession) mdtm(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		s.reply(550, "Не найдено")
		return
	}
	s.reply(213, "%s", st.ModTime().UTC().Format("20060102150405"))
}

func (s *ftpSession) deleteFile(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		s.reply(550, "Файл не найден")
		return
	}
	if err := os.Remove(full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "Файл удалён")
}

func (s *ftpSession) makeDir(arg string) {
	full, virtual, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if err := os.Mkdir(full, 0755); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(257, "%q created", virtual)
}

func (s *ftpSession) removeDir(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		s.reply(550, "Каталог не найден")
		return
	}
	if err := os.Remove(full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "Каталог удалён")
}

func (s *ftpSession) renameFromCmd(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if _, err := os.Stat(full); err != nil {
		s.reply(550, "Не найдено")
		return
	}
	s.renameFrom = full
	s.reply(350, "Укажите новое имя")
}

func (s *ftpSession) renameToCmd(arg string) {
	if s.renameFrom == "" {
		s.reply(503, "Сначала RNFR")
		return
	}
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	from := s.renameFrom
	s.renameFrom = ""
	if err := os.Rename(from, full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "Переименовано")
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
	// Compatibility with 0.2.0/0.2.1 links. html/template could escape
	// the percent sign again, leaving values such as internal%2FBooks
	// after net/http had already decoded the query once.
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

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for q := n / unit; q >= unit; q /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func localIPv4s() []string {
	ifaces, _ := net.Interfaces()
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

func pathStatus(p string) string {
	st, err := os.Stat(p)
	if err != nil {
		return "недоступна (" + err.Error() + ")"
	}
	if !st.IsDir() {
		return "это не папка"
	}
	f, err := os.CreateTemp(p, ".pbwf-test-")
	if err != nil {
		return "только чтение (" + err.Error() + ")"
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return "чтение и запись"
}

func (a *App) keepNetworkAlive() {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		if len(localIPv4s()) == 0 {
			connect := "/ebrmain/bin/auto_connect.app"
			if _, err := os.Stat(connect); err != nil {
				connect = "/ebrmain/bin/netagent"
				_ = exec.Command(connect, "connect").Run()
			} else {
				_ = exec.Command(connect).Run()
			}
		}
		<-ticker.C
	}
}

const pageTemplates = `
{{define "head"}}<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WiFiFiles</title><style>
body{font-family:Arial,sans-serif;max-width:980px;margin:0 auto;padding:16px;background:#f5f5f5;color:#111}header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}a{color:#0645ad;text-decoration:none}.card{background:#fff;border:1px solid #bbb;border-radius:8px;padding:14px;margin:12px 0}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}button,.button,input[type=submit]{font:inherit;padding:8px 12px;border:1px solid #555;border-radius:5px;background:#eee;color:#111}.danger{background:#fff;border-color:#900;color:#900}input[type=text],input[type=password],input[type=file],select{font:inherit;padding:8px;border:1px solid #777;border-radius:4px;max-width:100%;box-sizing:border-box}select{width:100%;background:#fff}.upload-grid{display:grid;grid-template-columns:minmax(220px,1fr) minmax(260px,1.4fr);gap:12px;align-items:end}.upload-note{padding:9px;border-left:4px solid #397;background:#f3f8f8}.breadcrumbs{display:flex;gap:5px;flex-wrap:wrap;align-items:center}.breadcrumbs a{font-weight:bold}.file-summary{margin-top:7px;word-break:break-word}.upload-submit{margin-top:12px}.upload-progress{display:none;margin-top:12px}.upload-progress.visible{display:block}.upload-progress progress{width:100%;height:20px}.upload-progress-text{margin-top:6px;font-weight:bold}@media(max-width:700px){.upload-grid{grid-template-columns:1fr}}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:9px;border-bottom:1px solid #ddd}tr:hover{background:#f0f0f0}.msg{padding:10px;border:1px solid #397;background:#eef}.err{padding:10px;border:1px solid #a00;background:#fee}.muted{color:#555;font-size:.9em}.path{word-break:break-all;font-family:monospace}.right{text-align:right}@media(max-width:650px){.hide-small{display:none}td,th{padding:8px 4px}}
</style></head><body>{{end}}
{{define "control"}}{{template "head" .}}<header><h1>WiFiFiles</h1><strong>v{{.Version}}</strong></header>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<div class="card"><h2>Состояние</h2><p><strong>Wi‑Fi IP:</strong> {{if .IPs}}{{range .IPs}}<span class="path">{{.}}</span> {{end}}{{else}}не определён{{end}}</p>
<p><strong>Веб + WebDAV:</strong> {{if .HTTPRunning}}работает{{else}}выключен{{end}}{{if .HTTPError}} — {{.HTTPError}}{{end}}</p>
{{if .HTTPRunning}}<p><a class="button" href="http://{{.AccessHost}}:{{.HTTPPort}}/">Открыть файлы в браузере</a></p>{{range .IPs}}<p class="path">Веб: http://{{.}}:{{$.HTTPPort}}/<br>WebDAV internal: http://{{.}}:{{$.HTTPPort}}/dav/internal/<br>WebDAV SD: http://{{.}}:{{$.HTTPPort}}/dav/sd/<br>WebDAV root: http://{{.}}:{{$.HTTPPort}}/dav/</p>{{end}}{{end}}
<p><strong>FTP:</strong> {{if .FTPRunning}}работает{{else}}выключен{{end}}{{if .FTPError}} — {{.FTPError}}{{end}}</p>{{if .FTPRunning}}{{range .IPs}}<p class="path">ftp://{{$.Username}}@{{.}}:{{$.FTPPort}}/</p>{{end}}{{end}}
<p><strong>SMB2/3:</strong> {{if .SMBRunning}}работает{{else if .SMBEnabled}}не запущен{{else}}выключен{{end}}{{if .SMBError}} — {{.SMBError}}{{end}}</p>{{if .SMBRunning}}{{range .IPs}}{{if $.InternalEnabled}}<p class="path">smb://{{.}}:{{$.SMBPort}}/INTERNAL</p>{{end}}{{if $.SDEnabled}}<p class="path">smb://{{.}}:{{$.SMBPort}}/SDCARD</p>{{end}}{{end}}{{end}}<p class="muted">{{.SMBReason}}. UID процесса: {{.UID}}; порт {{.SMBPort}}: {{if .PortSMBAvailable}}доступен{{else}}недоступен{{end}} ({{.PortSMBReason}})</p></div>
<div class="card"><h2>Протоколы и память</h2><form method="post" action="/services">
<p><label><input type="checkbox" name="http_enabled" {{if .HTTPEnabled}}checked{{end}}> Веб-доступ HTTP/HTML + WebDAV</label><br><label>Порт HTTP: <input type="text" inputmode="numeric" name="http_port" value="{{.HTTPPort}}" size="6"></label></p>
<p><label><input type="checkbox" name="ftp_enabled" {{if .FTPEnabled}}checked{{end}}> FTP-доступ</label><br><label>Порт FTP: <input type="text" inputmode="numeric" name="ftp_port" value="{{.FTPPort}}" size="6"></label></p>
<p><label><input type="checkbox" name="smb_enabled" {{if .SMBEnabled}}checked{{end}}> SMB2 / SMB3</label><br><label>Порт SMB: <input type="text" inputmode="numeric" name="smb_port" value="{{.SMBPort}}" size="6"></label><br><span class="muted">По умолчанию 4445 — без root. Проводнику Windows для нестандартного порта нужна локальная переадресация 445 → 4445.</span></p>
<p><label><input type="checkbox" name="logging_enabled" {{if .LoggingEnabled}}checked{{end}}> Ведение логов</label><br><span class="muted">Все события записываются в единственный файл /WiFiFiles.log. При выключении файл удаляется.</span></p>
<hr><p><strong>Показывать:</strong></p><p><label><input type="checkbox" name="internal" {{if .InternalEnabled}}checked{{end}}> Внутренняя память</label><br><span class="muted">{{.InternalStatus}}</span></p>
<p><label><input type="checkbox" name="sd" {{if .SDEnabled}}checked{{end}}> Карта SD</label><br><span class="muted">{{.SDStatus}}</span></p>
<p><input type="submit" value="Сохранить и применить"></p></form></div>
<div class="card"><h2>Логин и пароль</h2><form method="post" action="/credentials"><p><label>Логин<br><input name="username" value="{{.Username}}" minlength="3" maxlength="32" required></label></p><p><label>Новый пароль<br><input type="password" name="password" minlength="6" maxlength="128" placeholder="Оставьте пустым, чтобы не менять"></label></p><p><input type="submit" value="Сохранить доступ"></p></form><p class="muted">Один логин и пароль используются для веб-доступа, FTP и SMB. После первого обновления со старой версии нестандартный пароль нужно ввести заново один раз.</p></div>
<div class="card"><h2>Завершение</h2><form method="post" action="/stop"><button class="danger" type="submit">Выключить все серверы</button></form></div>
<p class="muted">На самом ридере панель открывается без повторного входа. При доступе с другого устройства она запрашивает логин и пароль WiFiFiles. Передача идёт в локальной сети без шифрования.</p></body></html>{{end}}
{{define "login"}}{{template "head" .}}<h1>WiFiFiles</h1><div class="card"><h2>Вход</h2>{{if .Error}}<div class="err">{{.Error}}</div>{{end}}<form method="post" action="/login"><p><label>Логин<br><input name="username" autocomplete="username" required></label></p><p><label>Пароль<br><input type="password" name="password" autocomplete="current-password" required></label></p><input type="submit" value="Войти"></form><p class="muted">Используйте логин и пароль, заданные на ридере.</p></div><p class="muted">Версия {{.Version}}. Используйте только в доверенной локальной сети.</p></body></html>{{end}}
{{define "index"}}{{template "head" .}}<header><h1>WiFiFiles</h1><nav><a href="/settings">Логин и пароль</a> · <a href="/info">Диагностика</a> · <a href="/logout">Выйти</a></nav></header>{{if .Error}}<div class="err">{{.Error}}</div>{{end}}{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
<div class="card"><div class="toolbar"><strong>Память:</strong>{{range .Roots}}<a class="button" href="/?k={{pathkey .}}">{{if eq . "internal"}}Внутренняя{{else}}Карта SD{{end}}</a>{{end}}</div><p class="breadcrumbs">{{range $i,$b := .Breadcrumbs}}{{if $i}}<span>›</span>{{end}}<a href="/?k={{pathkey $b.Path}}">{{$b.Label}}</a>{{end}}</p>{{if .ParentPath}}<a class="button" href="/?k={{pathkey .ParentPath}}">← На уровень выше</a>{{end}}</div>
<div class="card"><h3>Загрузить файлы</h3><p class="upload-note"><strong>Папку можно выбрать прямо здесь.</strong> Сначала или после выбора файлов укажите место назначения — выбранные файлы не сбросятся.</p><p class="muted"><strong>Свободно в текущей памяти:</strong> {{.FreeSpace}}</p><form id="upload-form" method="post" enctype="multipart/form-data" action="/upload"><div class="upload-grid"><label><strong>1. Папка назначения</strong><br><select name="target" required>{{range .Destinations}}<option value="{{.Path}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}</select></label><label><input type="checkbox" name="overwrite" value="1"> Заменять файлы с совпадающим именем</label><label><strong>2. Выберите файлы</strong><br><input id="upload-files" type="file" name="files" multiple required><div id="file-summary" class="muted file-summary">Файлы ещё не выбраны</div></label></div><div class="upload-submit"><input id="upload-button" type="submit" value="3. Загрузить в выбранную папку" disabled></div><div id="upload-progress" class="upload-progress"><progress id="upload-progress-bar" max="100" value="0"></progress><div id="upload-progress-text" class="upload-progress-text"></div></div></form></div>
<div class="card"><h3>Создать папку здесь</h3><form method="post" action="/mkdir"><input type="hidden" name="p" value="{{.CurrentPath}}"><input type="text" name="name" placeholder="Название папки" required> <input type="submit" value="Создать"></form></div><table><thead><tr><th>Имя</th><th class="hide-small">Размер</th><th class="hide-small">Изменён</th><th></th></tr></thead><tbody>{{range .Entries}}<tr><td>{{if .IsDir}}[Папка] <a href="/?k={{pathkey .Path}}">{{.Name}}</a>{{else}}[Файл] <a href="/download?k={{pathkey .Path}}">{{.Name}}</a>{{end}}</td><td class="hide-small">{{if not .IsDir}}{{.Size}}{{end}}</td><td class="hide-small">{{.ModTime}}</td><td class="right"><form method="post" action="/delete" onsubmit="return confirm('Удалить {{.Name}}?')"><input type="hidden" name="p" value="{{.Path}}"><button class="danger" type="submit">Удалить</button></form></td></tr>{{else}}<tr><td colspan="4">Папка пуста</td></tr>{{end}}</tbody></table><p class="muted">Папки system и applications намеренно скрыты и защищены. WebDAV: /dav/. Версия {{.Version}}</p><script>(function(){var form=document.getElementById('upload-form'),f=document.getElementById('upload-files'),s=document.getElementById('file-summary'),b=document.getElementById('upload-button'),box=document.getElementById('upload-progress'),bar=document.getElementById('upload-progress-bar'),text=document.getElementById('upload-progress-text');if(!f)return;f.addEventListener('change',function(){var n=f.files?f.files.length:0;b.disabled=n===0;if(!n){s.textContent='Файлы ещё не выбраны';return}var names=[];for(var i=0;i<n&&i<4;i++)names.push(f.files[i].name);s.textContent=n===1?names[0]:(n+' файлов: '+names.join(', ')+(n>4?'…':''));});if(!form||!window.XMLHttpRequest)return;form.addEventListener('submit',function(e){e.preventDefault();b.disabled=true;box.className='upload-progress visible';bar.value=0;text.textContent='Подготовка передачи…';var xhr=new XMLHttpRequest();xhr.open('POST',form.action,true);xhr.upload.onprogress=function(ev){if(!ev.lengthComputable)return;var pct=Math.max(0,Math.min(100,Math.round(ev.loaded*100/ev.total)));bar.value=pct;text.textContent='Передача — '+pct+'%';};xhr.onerror=function(){b.disabled=false;text.textContent='Ошибка передачи. Проверьте Wi‑Fi и повторите попытку.';};xhr.onload=function(){if(xhr.status>=200&&xhr.status<400){window.location.href=xhr.responseURL||'/?msg='+encodeURIComponent('Загрузка завершена');}else{b.disabled=false;text.textContent=xhr.responseText||'Ошибка передачи';}};xhr.send(new FormData(form));});})();</script></body></html>{{end}}
{{define "settings"}}{{template "head" .}}<h1>Настройки WiFiFiles</h1><div class="card">{{if .Error}}<div class="err">{{.Error}}</div>{{end}}<form method="post" action="/settings"><p><label>Новый логин<br><input name="username" value="{{.Username}}" minlength="3" maxlength="32" required></label></p><p><label>Новый пароль<br><input type="password" name="password" minlength="6" maxlength="128" required></label></p><input type="submit" value="Сохранить"></form><p class="muted">После сохранения потребуется войти заново.</p></div><p><a href="/">← Вернуться к файлам</a></p></body></html>{{end}}
`

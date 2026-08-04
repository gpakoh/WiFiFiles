package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	smbntlm "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	smbserver "github.com/sonroyaalmerol/go-smb-server/smb/server"
)

const version = "0.7.23"

const controlPort = 8090

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
	nativeMobileDefaultPath = "/tmp/WiFiFiles/native_mobile_default.ini"
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

	InternalEnabled bool     `json:"internal_enabled"`
	SDEnabled       bool     `json:"sd_enabled"`
	DefaultTarget   string   `json:"default_target,omitempty"`
	RecentTargets   []string `json:"recent_targets,omitempty"`
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
	DefaultTarget string
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
		case "--native-mobile-default-save":
			nativeSaveDefaultTarget(appDir)
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
		text += "Open the browser on the reader and enter: " + target + "\n"
		text += "From another device the panel will ask for WiFiFiles credentials.\n"
		text += "browser error: " + err.Error() + "\n"
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
		return errors.New("browser executable not found")
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
		fmt.Fprintf(&b, "Control panel: http://%s:%d/\n", ips[0], controlPort)
	} else {
		fmt.Fprintf(&b, "Control panel listening on port %d; Wi-Fi IP not yet determined.\n", controlPort)
	}
	if len(ips) == 0 {
		b.WriteString("Wi-Fi IP пока не определён.\n")
	} else {
		for _, ip := range ips {
			if cfg.HTTPEnabled {
				fmt.Fprintf(&b, "Web files: http://%s:%d/\n", ip, cfg.HTTPPort)
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
	fmt.Fprintf(&b, "Username: %s\nPassword: set in the control panel.\n", cfg.Username)
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
		data.PortSMBReason = "port used by WiFiFiles server"
	} else {
		data.PortSMBAvailable, data.PortSMBReason = testListenPort(smbListenPort(cfg))
	}
	return data
}

func testListenPort(port int) (bool, string) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return false, err.Error()
	}
	_ = ln.Close()
	return true, "port available to application"
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
		http.Redirect(w, r, "/?err="+url.QueryEscape("failed to read settings"), http.StatusSeeOther)
		return
	}
	httpPort, err1 := strconv.Atoi(r.FormValue("http_port"))
	ftpPort, err2 := strconv.Atoi(r.FormValue("ftp_port"))
	smbPort, err3 := strconv.Atoi(r.FormValue("smb_port"))
	if err1 != nil || httpPort < 1024 || httpPort > 65535 || err2 != nil || ftpPort < 1024 || ftpPort > 65535 || err3 != nil || smbPort < 1024 || smbPort > 65535 || httpPort == ftpPort || httpPort == smbPort || ftpPort == smbPort || httpPort == controlPort || ftpPort == controlPort || smbPort == controlPort {
		http.Redirect(w, r, "/?err="+url.QueryEscape("ports must be different numbers 1024-65535 and not equal to 8090"), http.StatusSeeOther)
		return
	}
	internalEnabled := r.FormValue("internal") == "on"
	sdEnabled := r.FormValue("sd") == "on"
	if !internalEnabled && !sdEnabled {
		http.Redirect(w, r, "/?err="+url.QueryEscape("select at least one storage"), http.StatusSeeOther)
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
		http.Redirect(w, r, "/?err="+url.QueryEscape("Failed to save: "+err.Error()), http.StatusSeeOther)
		return
	}
	if !sm.app.configSnapshot().LoggingEnabled {
		_ = os.Remove(unifiedLogPath)
	}
	sm.app.resetSessions()
	sm.applyServices()
	http.Redirect(w, r, "/?msg="+url.QueryEscape("service settings saved"), http.StatusSeeOther)
}

func (sm *ServiceManager) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 {
		http.Redirect(w, r, "/?err="+url.QueryEscape("username must be 3-32 characters"), http.StatusSeeOther)
		return
	}
	if password != "" && (len(password) < 6 || len(password) > 128) {
		http.Redirect(w, r, "/?err="+url.QueryEscape("password must be 6-128 characters"), http.StatusSeeOther)
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
		http.Redirect(w, r, "/?err="+url.QueryEscape("Failed to save: "+err.Error()), http.StatusSeeOther)
		return
	}
	sm.app.resetSessions()
	sm.applyServices()
	http.Redirect(w, r, "/?msg="+url.QueryEscape("username and password saved"), http.StatusSeeOther)
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
	fmt.Fprintf(&b, "default_target=%s\n", cleanINIValue(cfg.DefaultTarget))
	for i, recent := range cfg.RecentTargets {
		if i >= maxRecentTargets {
			break
		}
		fmt.Fprintf(&b, "recent%d=%s\n", i+1, cleanINIValue(recent))
	}
	freeInternal := "—"
	freeSD := "—"
	if free, err := availableBytes(sm.app.roots["internal"]); err == nil {
		freeInternal = humanSize(int64(free))
	}
	if free, err := availableBytes(sm.app.roots["sd"]); err == nil {
		freeSD = humanSize(int64(free))
	}
	fmt.Fprintf(&b, "free_internal=%s\n", cleanINIValue(freeInternal))
	fmt.Fprintf(&b, "free_sd=%s\n", cleanINIValue(freeSD))
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
	fmt.Fprintf(&b, "default_target=%s\n", cleanINIValue(cfg.DefaultTarget))
	for i, recent := range cfg.RecentTargets {
		if i >= maxRecentTargets {
			break
		}
		fmt.Fprintf(&b, "recent%d=%s\n", i+1, cleanINIValue(recent))
	}
	freeInternal := "—"
	freeSD := "—"
	if free, err := availableBytes(app.roots["internal"]); err == nil {
		freeInternal = humanSize(int64(free))
	}
	if free, err := availableBytes(app.roots["sd"]); err == nil {
		freeSD = humanSize(int64(free))
	}
	fmt.Fprintf(&b, "free_internal=%s\n", cleanINIValue(freeInternal))
	fmt.Fprintf(&b, "free_sd=%s\n", cleanINIValue(freeSD))
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
		return errors.New("set a new password before first use")
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
	return errors.New("manager did not confirm launch")
}

func nativeStart(appDir string) {
	if err := startManagerDetached(appDir); err != nil {
		writeNativeStateStopped(appDir, "Launch error: "+err.Error())
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
			writeNativeStateStopped(appDir, "Server update error: "+err.Error())
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
			writeNativeStateStopped(appDir, "Server update error: "+err.Error())
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
		freeInternal := "—"
		freeSD := "—"
		if free, err := availableBytes("/mnt/ext1"); err == nil {
			freeInternal = humanSize(int64(free))
		}
		if free, err := availableBytes("/mnt/ext2"); err == nil {
			freeSD = humanSize(int64(free))
		}
		_ = os.WriteFile(statePath, refreshDynamicState(data, ip, freeInternal, freeSD), 0644)
	}
}

// refreshDynamicState returns the state file content with the dynamic
// fields (ip, free space) updated so the native panel sees current values
// without restarting the server.
func refreshDynamicState(data []byte, ip, freeInternal, freeSD string) []byte {
	lines := strings.Split(string(data), "\n")
	lines = setINILine(lines, "ip", ip)
	lines = setINILine(lines, "free_internal", freeInternal)
	lines = setINILine(lines, "free_sd", freeSD)
	return []byte(strings.Join(lines, "\n"))
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

func nativeSaveDefaultTarget(appDir string) {
	data, err := os.ReadFile(nativeMobileDefaultPath)
	if err != nil {
		writeNativeStateStopped(appDir, "Default target file not found")
		return
	}
	_ = os.Remove(nativeMobileDefaultPath)
	vals := parseNativeApply(data)
	target := strings.TrimSpace(vals["default_target"])
	app, err := newApp(persistentConfigPath)
	if err != nil {
		writeNativeStateStopped(appDir, err.Error())
		return
	}
	app.cfgMu.Lock()
	app.cfg.DefaultTarget = target
	app.cfg.ConfigVersion = 7
	app.cfgMu.Unlock()
	if err := app.saveConfig(); err != nil {
		writeNativeStateStopped(appDir, "Error saving default target: "+err.Error())
		return
	}
	nativeStateCommand(appDir)
	app.cfgMu.RLock()
	defaultTarget := app.cfg.DefaultTarget
	recent := append([]string(nil), app.cfg.RecentTargets...)
	app.cfgMu.RUnlock()
	syncStateTargets(appDir, defaultTarget, recent)
}

// syncStateTargets rewrites the default_target and recentN lines of the
// native state file from the given values. writeNativeState writes them only
// when the server starts or services change, so without this the panel would
// keep showing the previous values until the server restarts.
func syncStateTargets(appDir, defaultTarget string, recent []string) {
	statePath := nativeStatePath(appDir)
	data, err := os.ReadFile(statePath)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	lines = setINILine(lines, "default_target", defaultTarget)
	for i, r := range recent {
		if i >= maxRecentTargets {
			break
		}
		lines = setINILine(lines, fmt.Sprintf("recent%d", i+1), r)
	}
	_ = os.WriteFile(statePath, []byte(strings.Join(lines, "\n")), 0666)
	_ = os.Chmod(statePath, 0666)
}

func setINILine(lines []string, key, value string) []string {
	prefix := key + "="
	found := false
	for i := range lines {
		if strings.HasPrefix(lines[i], prefix) {
			lines[i] = prefix + cleanINIValue(value)
			found = true
		}
	}
	if !found {
		lines = append(lines, prefix+cleanINIValue(value))
	}
	return lines
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
	total := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") || isHiddenSystemPath(current, entry.Name()) {
			continue
		}
		child := current + "/" + entry.Name()
		if isProtectedVirtual(child) {
			continue
		}
		total++
	}
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
	lines = append(lines, fmt.Sprintf("count=%d", count), fmt.Sprintf("total=%d", total))
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
	if err := addMobileToken(record); err != nil {
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
		writeNativeStateStopped(appDir, "Username must be 3-32 characters")
		return
	}
	httpPort, err1 := strconv.Atoi(vals["http_port"])
	ftpPort, err2 := strconv.Atoi(vals["ftp_port"])
	smbPort, err3 := strconv.Atoi(vals["smb_port"])
	if err1 != nil || httpPort < 1024 || httpPort > 65535 || err2 != nil || ftpPort < 1024 || ftpPort > 65535 || err3 != nil || smbPort < 1024 || smbPort > 65535 || httpPort == ftpPort || httpPort == smbPort || ftpPort == smbPort || httpPort == controlPort || ftpPort == controlPort || smbPort == controlPort {
		writeNativeStateStopped(appDir, "Ports must be different numbers 1024-65535 and not equal to 8090")
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
			writeNativeStateStopped(appDir, "Password must be 6-128 characters")
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
		writeNativeStateStopped(appDir, "Launch error: "+err.Error())
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
		_ = a.tmpl.ExecuteTemplate(w, "login", PageData{Version: version, Error: "invalid username or password"})
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
		a.renderIndex(w, p, "folder not found", "")
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
		errMsg = "failed to read folder: " + err.Error()
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
				label = "internal storage"
			} else if parts[i] == "sd" {
				label = "SD card"
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
		walk(a.roots["internal"], "internal", "internal storage", 0)
	}
	if a.enabledRoot("sd") {
		if st, err := os.Stat(a.roots["sd"]); err == nil && st.IsDir() {
			walk(a.roots["sd"], "sd", "SD card", 0)
		}
	}
	if current != "" && !seenCurrent {
		out = append([]UploadDestination{{Path: current, Label: "/" + current, Selected: true}}, out...)
	}
	return out
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
		redirectMsg(w, r, parentV, "invalid folder name")
		return
	}
	if err := os.Mkdir(filepath.Join(parent, name), 0755); err != nil {
		redirectMsg(w, r, parentV, "failed to create folder: "+err.Error())
		return
	}
	redirectMsg(w, r, parentV, "folder created")
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
		redirectMsg(w, r, parentVirtual(cleanV), "failed to delete: "+err.Error())
		return
	}
	redirectMsg(w, r, parentVirtual(cleanV), "deleted")
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.cfgMu.RLock()
		u := a.cfg.Username
		def := a.cfg.DefaultTarget
		a.cfgMu.RUnlock()
		_ = a.tmpl.ExecuteTemplate(w, "settings", PageData{Version: version, Username: u, DefaultTarget: def, Message: r.URL.Query().Get("msg")})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("action") == "clear_default_target" {
		a.cfgMu.Lock()
		a.cfg.DefaultTarget = ""
		a.cfg.ConfigVersion = 7
		a.cfgMu.Unlock()
		if err := a.saveConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nativeStateCommand("")
		a.cfgMu.RLock()
		defaultTarget := a.cfg.DefaultTarget
		recent := append([]string(nil), a.cfg.RecentTargets...)
		a.cfgMu.RUnlock()
		syncStateTargets(runtimeDirPath, defaultTarget, recent)
		http.Redirect(w, r, "/settings?msg="+url.QueryEscape("default target cleared"), http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if len(username) < 3 || len(username) > 32 || len(password) < 6 || len(password) > 128 {
		w.WriteHeader(http.StatusBadRequest)
		_ = a.tmpl.ExecuteTemplate(w, "settings", PageData{Version: version, Username: username, Error: "username: 3-32 chars; password: 6-128 chars"})
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
body{font-family:Arial,sans-serif;max-width:980px;margin:0 auto;padding:16px;background:#f5f5f5;color:#111}header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}a{color:#0645ad;text-decoration:none}.card{background:#fff;border:1px solid #bbb;border-radius:8px;padding:14px;margin:12px 0}.path{font-weight:700;word-break:break-all;background:#f2f2f7;border-radius:6px;padding:8px;margin:6px 0}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}button,.button,input[type=submit]{font:inherit;padding:8px 12px;border:1px solid #555;border-radius:5px;background:#eee;color:#111}.danger{background:#fff;border-color:#900;color:#900}input[type=text],input[type=password],input[type=file],select{font:inherit;padding:8px;border:1px solid #777;border-radius:4px;max-width:100%;box-sizing:border-box}select{width:100%;background:#fff}.upload-grid{display:grid;grid-template-columns:minmax(220px,1fr) minmax(260px,1.4fr);gap:12px;align-items:end}.upload-note{padding:9px;border-left:4px solid #397;background:#f3f8f8}.breadcrumbs{display:flex;gap:5px;flex-wrap:wrap;align-items:center}.breadcrumbs a{font-weight:bold}.file-summary{margin-top:7px;word-break:break-word}.upload-submit{margin-top:12px}.upload-progress{display:none;margin-top:12px}.upload-progress.visible{display:block}.upload-progress progress{width:100%;height:20px}.upload-progress-text{margin-top:6px;font-weight:bold}@media(max-width:700px){.upload-grid{grid-template-columns:1fr}}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:9px;border-bottom:1px solid #ddd}tr:hover{background:#f0f0f0}.msg{padding:10px;border:1px solid #397;background:#eef}.err{padding:10px;border:1px solid #a00;background:#fee}.muted{color:#555;font-size:.9em}.path{word-break:break-all;font-family:monospace}.right{text-align:right}@media(max-width:650px){.hide-small{display:none}td,th{padding:8px 4px}}
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
{{define "settings"}}{{template "head" .}}<h1>Настройки WiFiFiles</h1><div class="card">{{if .Error}}<div class="err">{{.Error}}</div>{{end}}{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}<form method="post" action="/settings"><p><label>Новый логин<br><input name="username" value="{{.Username}}" minlength="3" maxlength="32" required></label></p><p><label>Новый пароль<br><input type="password" name="password" minlength="6" maxlength="128" required></label></p><input type="submit" value="Сохранить"></form><p class="muted">После сохранения потребуется войти заново.</p></div><div class="card"><h2>Папка по умолчанию</h2>{{if .DefaultTarget}}<p class="muted">QR-передача по умолчанию сохраняет книги в:</p><p class="path">{{.DefaultTarget}}</p><form method="post" action="/settings"><input type="hidden" name="action" value="clear_default_target"><input type="submit" value="Сбросить по умолчанию"></form>{{else}}<p class="muted">Папка по умолчанию не задана. Её можно выбрать на ридере в режиме передачи по QR-коду (кнопка «★ Запомнить»).</p>{{end}}</div><p><a href="/">← Вернуться к файлам</a></p></body></html>{{end}}
`

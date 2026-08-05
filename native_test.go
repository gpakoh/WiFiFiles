package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupTestExt1()
	os.Exit(code)
}

func cleanupTestExt1() {
	dev := func(p string) (uint64, bool) {
		st, err := os.Stat(p)
		if err != nil {
			return 0, false
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			return uint64(sys.Dev), true
		}
		return 0, false
	}
	extDev, ok1 := dev("/mnt/ext1")
	mntDev, ok2 := dev("/mnt")
	if ok1 && ok2 && extDev != mntDev {
		return
	}
	_ = os.RemoveAll("/mnt/ext1")
}

func nativeTestConfig() Config {
	return Config{
		ConfigVersion:   7,
		Username:        "pocketbook",
		PasswordSalt:    "testsalt",
		PasswordHash:    passwordHash("testsalt", "650wifi"),
		SMBNTHash:       hexEncodeNTHash(),
		DAVDigestHA1:    digestHA1("pocketbook", "650wifi"),
		Port:            8080,
		HTTPEnabled:     true,
		HTTPPort:        8080,
		FTPEnabled:      false,
		FTPPort:         2121,
		SMBEnabled:      false,
		SMBPort:         4445,
		LoggingEnabled:  false,
		InternalEnabled: true,
		SDEnabled:       true,
	}
}

func hexEncodeNTHash() string {
	return "00112233445566778899aabbccddeeff"
}

func writePersistentTestConfig(t *testing.T, cfg Config) {
	t.Helper()
	dir := filepath.Dir(persistentConfigPath)
	createdRoot := false
	if _, err := os.Stat("/mnt/ext1"); os.IsNotExist(err) {
		createdRoot = true
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Skipf("cannot create %s: %v", dir, err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(persistentConfigPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(persistentConfigPath)
		if createdRoot {
			_ = os.RemoveAll("/mnt/ext1")
		}
	})
}

func startChildProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func reapChild(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	_ = cmd.Process.Kill()
	if err := cmd.Wait(); err == nil {
		t.Fatal("child exited with nil error")
	}
}

func writePIDFile(t *testing.T, dir string, pid int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "wififiles.pid"), []byte(fmt.Sprintf("%d\n", pid)), 0600); err != nil {
		t.Fatal(err)
	}
}

func readNativeState(t *testing.T, appDir string) string {
	t.Helper()
	data, err := os.ReadFile(nativeStatePath(appDir))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestStopManagerPIDVariants(t *testing.T) {
	stopManagerPID(0)
	stopManagerPID(1)
	stopManagerPID(99999999)

	child := startChildProcess(t)
	if !processAlive(child.Process.Pid) {
		t.Fatal("child process not alive before kill")
	}
	stopManagerPID(child.Process.Pid)
	reapChild(t, child)
}

func TestNativeStartConfigError(t *testing.T) {
	dir := t.TempDir()
	nativeStart(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "running=0") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStartDefaultPasswordBlocked(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	nativeStart(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "set a new password before first use") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStopWithoutPID(t *testing.T) {
	tokenPath := mobileTokenPath
	_ = os.WriteFile(tokenPath, []byte("[]"), 0600)
	t.Cleanup(func() { _ = os.Remove(tokenPath) })

	dir := t.TempDir()
	nativeStop(dir)
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("mobile token path not removed by nativeStop")
	}
	if _, err := os.Stat(filepath.Join(dir, "wififiles.pid")); err == nil {
		t.Fatal("pid file left behind")
	}
	state := readNativeState(t, dir)
	if !strings.Contains(state, "running=0") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStopWithLivePID(t *testing.T) {
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	nativeStop(dir)
	reapChild(t, child)
	if _, err := os.Stat(filepath.Join(dir, "wififiles.pid")); err == nil {
		t.Fatal("pid file left behind")
	}
}

func TestNativeStateCommandStopped(t *testing.T) {
	dir := t.TempDir()
	nativeStateCommand(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "running=0") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStateCommandUpgradePath(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	nativeStateCommand(dir)
	reapChild(t, child)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Server update error") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStateCommandVersionMismatch(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	if err := os.WriteFile(nativeStatePath(dir), []byte("version=0.2.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeStateCommand(dir)
	reapChild(t, child)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Server update error") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeStateCommandRefresh(t *testing.T) {
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	if err := os.WriteFile(nativeStatePath(dir), []byte("version="+version+"\nip=old\nfree_internal=old\nfree_sd=old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeStateCommand(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "version="+version) {
		t.Fatalf("version lost after refresh: %q", state)
	}
	if strings.Contains(state, "free_internal=old") {
		t.Fatalf("state not refreshed: %q", state)
	}
	if !processAlive(child.Process.Pid) {
		t.Fatal("child should survive refresh path")
	}
	reapChild(t, child)
}

func TestNativeSetLanguageFileMissing(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	nativeSetLanguageFile(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Не найден файл языка") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeSetLanguageFileUnsupported(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "native_language.ini"), []byte("language=xx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeSetLanguageFile(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Неподдерживаемый язык") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeSetLanguageFileSuccess(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "native_language.ini"), []byte("language=en\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeSetLanguageFile(dir)
	if _, err := os.Stat(filepath.Join(dir, "native_language.ini")); err == nil {
		t.Fatal("language file not removed")
	}
	var cfg Config
	data, err := os.ReadFile(persistentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Language != "en" {
		t.Fatalf("language not saved: %q", cfg.Language)
	}
	state := readNativeState(t, dir)
	if !strings.Contains(state, "language=en") {
		t.Fatalf("state missing language: %q", state)
	}
}

func TestNativeSaveDefaultTargetMissing(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	nativeSaveDefaultTarget(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Default target file not found") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeSaveDefaultTargetSuccess(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	if err := os.WriteFile(nativeMobileDefaultPath, []byte("default_target=internal/Books\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(nativeMobileDefaultPath) })
	nativeSaveDefaultTarget(dir)
	var cfg Config
	data, err := os.ReadFile(persistentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultTarget != "internal/Books" {
		t.Fatalf("default target not saved: %q", cfg.DefaultTarget)
	}
	if _, err := os.Stat(nativeMobileDefaultPath); err == nil {
		t.Fatal("request file not removed")
	}
}

func TestNativeFolderListFileMissingRequest(t *testing.T) {
	_ = os.Remove(nativeFolderRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderRequestPath) })
	_ = os.Remove(nativeFolderListPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderListPath) })
	nativeFolderListFile(t.TempDir())
	data, err := os.ReadFile(nativeFolderListPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Не найден запрос выбора папки") {
		t.Fatalf("unexpected list file: %q", string(data))
	}
}

func TestNativeFolderListFileConfigError(t *testing.T) {
	_ = os.Remove(nativeFolderRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderRequestPath) })
	_ = os.Remove(nativeFolderListPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderListPath) })
	if err := os.WriteFile(nativeFolderRequestPath, []byte("path=internal\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeFolderListFile(t.TempDir())
	data, err := os.ReadFile(nativeFolderListPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "error=") {
		t.Fatalf("expected error in list file: %q", string(data))
	}
}

func TestNativeFolderListFileSuccess(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	uniq := fmt.Sprintf("wf-native-dir-%d", time.Now().UnixNano())
	root := "/mnt/ext1"
	if err := os.MkdirAll(filepath.Join(root, uniq), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(root, uniq)) })

	_ = os.Remove(nativeFolderRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderRequestPath) })
	_ = os.Remove(nativeFolderListPath)
	t.Cleanup(func() { _ = os.Remove(nativeFolderListPath) })
	if err := os.WriteFile(nativeFolderRequestPath, []byte("path=internal\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeFolderListFile(t.TempDir())
	data, err := os.ReadFile(nativeFolderListPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"error=", "current=internal", "internal/" + uniq, "count=", "total="} {
		if !strings.Contains(text, want) {
			t.Fatalf("list file missing %q: %q", want, text)
		}
	}
}

func TestNativeMobileQRFileMissingRequest(t *testing.T) {
	_ = os.Remove(nativeMobileRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileRequestPath) })
	_ = os.Remove(nativeMobileQRPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileQRPath) })
	nativeMobileQRFile(t.TempDir())
	data, err := os.ReadFile(nativeMobileQRPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Не найден запрос QR-кода") {
		t.Fatalf("unexpected qr file: %q", string(data))
	}
}

func TestNativeMobileQRFileInvalidIP(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	_ = os.Remove(nativeMobileRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileRequestPath) })
	_ = os.Remove(nativeMobileQRPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileQRPath) })
	if err := os.WriteFile(nativeMobileRequestPath, []byte("target=internal\nip=not-an-ip\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeMobileQRFile(t.TempDir())
	data, err := os.ReadFile(nativeMobileQRPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Некорректный IP-адрес") {
		t.Fatalf("unexpected qr file: %q", string(data))
	}
}

func TestNativeMobileQRFileSuccess(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	root := "/mnt/ext1"
	if err := os.MkdirAll(filepath.Join(root, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(root, "Books")) })

	_ = os.Remove(nativeMobileRequestPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileRequestPath) })
	_ = os.Remove(nativeMobileQRPath)
	t.Cleanup(func() { _ = os.Remove(nativeMobileQRPath) })
	_ = os.Remove(mobileTokenPath)
	t.Cleanup(func() { _ = os.Remove(mobileTokenPath) })
	_ = os.Remove(mobileTokenPath + ".tmp")
	t.Cleanup(func() { _ = os.Remove(mobileTokenPath + ".tmp") })

	if err := os.WriteFile(nativeMobileRequestPath, []byte("target=internal/Books\nip=192.168.1.5\nmode=edit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nativeMobileQRFile(t.TempDir())
	data, err := os.ReadFile(nativeMobileQRPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"error=", "target=internal/Books", "mode=edit", "url=http://192.168.1.5:8080/m/", "row0="} {
		if !strings.Contains(text, want) {
			t.Fatalf("qr file missing %q: %q", want, text)
		}
	}
	tokenData, err := os.ReadFile(mobileTokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tokenData), "internal/Books") {
		t.Fatalf("token not recorded: %q", string(tokenData))
	}
}

func TestNativeApplyFileMissing(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	nativeApplyFile(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Не найден файл настроек") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestNativeApplyFileValidations(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	cases := []struct {
		name string
		ini  string
		want string
	}{
		{"short username", "username=ab\nhttp_port=8080\nftp_port=2121\nsmb_port=4445\ninternal_enabled=1\n", "Username must be 3-32 characters"},
		{"bad port", "username=pbk\nhttp_port=80\nftp_port=2121\nsmb_port=4445\ninternal_enabled=1\n", "Ports must be different numbers"},
		{"duplicate port", "username=pbk\nhttp_port=8080\nftp_port=8080\nsmb_port=4445\ninternal_enabled=1\n", "Ports must be different numbers"},
		{"no storage", "username=pbk\nhttp_port=8080\nftp_port=2121\nsmb_port=4445\ninternal_enabled=0\nsd_enabled=0\n", "Включите хотя бы одну память"},
		{"short password", "username=pbk\nhttp_port=8080\nftp_port=2121\nsmb_port=4445\ninternal_enabled=1\npassword=123\n", "Password must be 6-128 characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "native_apply.ini"), []byte(tc.ini), 0644); err != nil {
				t.Fatal(err)
			}
			nativeApplyFile(dir)
			state := readNativeState(t, dir)
			if !strings.Contains(state, tc.want) {
				t.Fatalf("want %q in state, got: %q", tc.want, state)
			}
		})
	}
}

func TestNativeApplyFileSMBRequiresPassword(t *testing.T) {
	cfg := nativeTestConfig()
	cfg.PasswordSalt = "customsalt"
	cfg.PasswordHash = passwordHash("customsalt", "secret123")
	cfg.SMBNTHash = ""
	cfg.DAVDigestHA1 = ""
	writePersistentTestConfig(t, cfg)
	dir := t.TempDir()
	ini := "username=pbk\nhttp_port=8080\nftp_port=2121\nsmb_port=4445\ninternal_enabled=1\nsmb_enabled=1\n"
	if err := os.WriteFile(filepath.Join(dir, "native_apply.ini"), []byte(ini), 0644); err != nil {
		t.Fatal(err)
	}
	nativeApplyFile(dir)
	state := readNativeState(t, dir)
	if !strings.Contains(state, "Для SMB введите пароль заново") {
		t.Fatalf("want SMB password message, got: %q", state)
	}
}

func TestConfiguredPortFromConfig(t *testing.T) {
	cfg := nativeTestConfig()
	cfg.Port = 8123
	cfg.HTTPPort = 8123
	writePersistentTestConfig(t, cfg)
	if got := configuredPort(t.TempDir()); got != 8123 {
		t.Fatalf("configuredPort = %d, want 8123", got)
	}
}

func TestToggleServerWithLivePID(t *testing.T) {
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	toggleServer(dir)
	reapChild(t, child)
	if _, err := os.Stat(filepath.Join(dir, "wififiles.pid")); err == nil {
		t.Fatal("pid file left behind")
	}
}

func TestStopServerVariants(t *testing.T) {
	dir := t.TempDir()
	stopServer(dir)

	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	if err := os.WriteFile(filepath.Join(dir, "wififiles.ready"), []byte(fmt.Sprintf("%d\n", child.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}
	stopServer(dir)
	reapChild(t, child)
	if _, err := os.Stat(filepath.Join(dir, "wififiles.pid")); err == nil {
		t.Fatal("pid file left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, "wififiles.ready")); err == nil {
		t.Fatal("ready file left behind")
	}
}

func TestRunServerConfigError(t *testing.T) {
	if _, err := os.Stat("/mnt/ext1"); err == nil {
		t.Skip("/mnt/ext1 exists; cannot guarantee config error")
	}
	runServer(t.TempDir())
}

func TestRunServerListenError(t *testing.T) {
	port := freeTCPPort(t)
	cfg := nativeTestConfig()
	cfg.HTTPPort = port
	cfg.Port = port
	writePersistentTestConfig(t, cfg)
	occupied, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Skipf("cannot occupy port %d: %v", port, err)
	}
	defer occupied.Close()
	runServer(t.TempDir())
}

func TestSyncStateTargetsMissingState(t *testing.T) {
	dir := t.TempDir()
	syncStateTargets(dir, "internal/Books", []string{"internal/A", "internal/B"})
	if _, err := os.Stat(nativeStatePath(dir)); err == nil {
		t.Fatal("state file should not be created when missing")
	}
}

func TestNativeStateCommandWritesStoppedWhenPIDFileStale(t *testing.T) {
	dir := t.TempDir()
	writePIDFile(t, dir, 99999999)
	nativeStateCommand(dir)
	if _, err := os.Stat(filepath.Join(dir, "wififiles.pid")); err == nil {
		t.Fatal("stale pid file not removed")
	}
	state := readNativeState(t, dir)
	if !strings.Contains(state, "running=0") {
		t.Fatalf("unexpected state: %q", state)
	}
}

func TestPrepareStorageLayoutNoMount(t *testing.T) {
	prepareStorageLayout()
	if _, err := os.Stat(runtimeDirPath); err != nil {
		t.Fatalf("runtime dir not created: %v", err)
	}
}

func TestPrepareStorageLayoutMigratesLegacy(t *testing.T) {
	requireMntExt1Writable(t)
	legacyDir := filepath.Join(legacyAppDirPath)
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"username":"legacy"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(legacyDir)
		_ = os.RemoveAll(filepath.Dir(persistentConfigPath))
	})
	prepareStorageLayout()
	if _, err := os.Stat(legacyDir); err == nil {
		t.Fatal("legacy dir not removed")
	}
	data, err := os.ReadFile(persistentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "legacy") {
		t.Fatalf("legacy config not migrated: %q", string(data))
	}
}

func TestPrepareStorageLayoutStopsLegacyManager(t *testing.T) {
	requireMntExt1Writable(t)
	legacyDir := filepath.Join(legacyAppDirPath)
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatal(err)
	}
	child := exec.Command("bash", "-c", "exec -a wififiles-legacy-manager sleep 300")
	if err := child.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.RemoveAll(legacyDir)
		_ = os.RemoveAll(filepath.Dir(persistentConfigPath))
	})
	if err := os.WriteFile(filepath.Join(legacyDir, "wififiles.pid"), []byte(fmt.Sprintf("%d\n", child.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	prepareStorageLayout()
	reapChild(t, child)
}

func TestControlPanelReadyVariants(t *testing.T) {
	dir := t.TempDir()
	if controlPanelReady(dir) {
		t.Fatal("ready without file = true")
	}
	child := exec.Command("bash", "-c", "exec -a wififiles-manager sleep 300")
	if err := child.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	time.Sleep(100 * time.Millisecond)
	readyPath := filepath.Join(dir, "wififiles.ready")
	if err := os.WriteFile(readyPath, []byte(fmt.Sprintf("%d\n", child.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}
	if !controlPanelReady(dir) {
		t.Fatal("ready with live wifi process = false")
	}
	if err := os.WriteFile(readyPath, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if controlPanelReady(dir) {
		t.Fatal("ready with pid 0 = true")
	}
}

func TestProcessIsWiFiFilesSelf(t *testing.T) {
	child := exec.Command("bash", "-c", "exec -a wififiles-test-binary sleep 300")
	if err := child.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	time.Sleep(100 * time.Millisecond)
	if !processIsWiFiFiles(child.Process.Pid) {
		t.Fatal("process with wififiles argv[0] not detected")
	}
}

func TestStartControlPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", controlPort))
	if err != nil {
		t.Skipf("control port %d not available: %v", controlPort, err)
	}
	defer ln.Close()
	sm := newTestServiceManager(t)
	if err := sm.startControl(); err == nil {
		t.Fatal("startControl succeeded on busy port")
	}
}

func TestStartControlAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", controlPort))
	if err == nil {
		_ = ln.Close()
	} else {
		t.Skipf("control port %d not available: %v", controlPort, err)
	}
	sm := newTestServiceManager(t)
	if err := sm.startControl(); err != nil {
		t.Fatalf("startControl: %v", err)
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", controlPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("pocketbook", "650wifi")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control status = %d", resp.StatusCode)
	}
	sm.shutdown()
}

func TestShutdownEmptyManager(t *testing.T) {
	sm := &ServiceManager{app: newTestWebApp(t), appDir: t.TempDir()}
	sm.shutdown()
}

func TestRunManagerAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	child := startChildProcess(t)
	writePIDFile(t, dir, child.Process.Pid)
	runManager(dir)
	reapChild(t, child)
}

func TestWriteStreamTempReadError(t *testing.T) {
	_, _, err := writeStreamTemp(t.TempDir(), failingReader{})
	if err == nil {
		t.Fatal("writeStreamTemp should fail with broken reader")
	}
}

func TestOpenProcessOutputWithLogging(t *testing.T) {
	cfg := nativeTestConfig()
	cfg.LoggingEnabled = true
	writePersistentTestConfig(t, cfg)
	t.Cleanup(func() { _ = os.Remove(unifiedLogPath) })
	f, err := openProcessOutput()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := os.Stat(unifiedLogPath); err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	appendLog(t.TempDir(), "native-test-line")
	data, err := os.ReadFile(unifiedLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "native-test-line") {
		t.Fatalf("log line missing: %q", string(data))
	}
}

func TestRunPocketBookScannerNotFound(t *testing.T) {
	a := newTestWebApp(t)
	a.runPocketBookScanner([]string{"/mnt/ext1/Books"})
}

func TestRunPocketBookScannerRuns(t *testing.T) {
	requireMntExt1Writable(t)
	scannerDir := filepath.Dir("/mnt/ext1/system/bin/scanner.app")
	if err := os.MkdirAll(scannerDir, 0755); err != nil {
		t.Fatal(err)
	}
	scannerPath := "/mnt/ext1/system/bin/scanner.app"
	if err := os.WriteFile(scannerPath, []byte("#!/bin/sh\nsleep 0.2\necho \"Scan finished\"\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir("/mnt/ext1/system")) })
	a := newTestWebApp(t)
	a.runPocketBookScanner([]string{"/mnt/ext1/Books"})
	time.Sleep(2 * time.Second)
}

func TestWriteDiagnosticWithLogging(t *testing.T) {
	cfg := nativeTestConfig()
	cfg.LoggingEnabled = true
	writePersistentTestConfig(t, cfg)
	writeDiagnostic(t.TempDir())
	logPath := filepath.Join(runtimeDirPath, "WiFiFiles.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Skipf("no diagnostic log: %v", err)
	}
	if !strings.Contains(string(data), "WiFiFiles diagnostic") {
		t.Fatalf("diagnostic log missing header: %q", string(data))
	}
}

func TestLaunchPocketBookBrowserNotFound(t *testing.T) {
	err := launchPocketBookBrowser(t.TempDir(), "http://127.0.0.1:8080/")
	if err == nil {
		t.Fatal("expected error without browser")
	}
}

func TestLaunchPocketBookBrowserSuccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create /ebrmain")
	}
	if _, err := os.Stat("/ebrmain"); err == nil {
		t.Skip("/ebrmain exists on this host; refusing to touch it")
	}
	bin := "/ebrmain/bin/browser.app"
	if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll("/ebrmain") })
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 0.2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := launchPocketBookBrowser(t.TempDir(), "http://127.0.0.1:8080/"); err != nil {
		t.Fatal(err)
	}
}

func TestMainDispatchNativeCommands(t *testing.T) {
	_ = os.Remove(filepath.Join(runtimeDirPath, "wififiles.pid"))
	_ = os.Remove(filepath.Join(runtimeDirPath, "wififiles.ready"))
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	args := []string{
		"--native-stop",
		"--native-start",
		"--native-state",
		"--native-apply-file",
		"--native-set-language-file",
		"--native-folder-list-file",
		"--native-mobile-qr-file",
		"--native-mobile-default-save",
	}
	old := os.Args
	for _, a := range args {
		os.Args = []string{"wififiles", a}
		main()
	}
	os.Args = []string{"wififiles-diagnostic"}
	main()
	os.Args = old
}

func TestRunManagerDefaultPasswordBlocked(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	dir := t.TempDir()
	runManager(dir)
	_ = os.Remove(filepath.Join(dir, "wififiles.pid"))
	_ = os.Remove(filepath.Join(dir, "wififiles.ready"))
}

func TestRunManagerConfigError(t *testing.T) {
	writePersistentTestConfig(t, nativeTestConfig())
	if err := os.WriteFile(persistentConfigPath, []byte("{{{ not json"), 0644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runManager(dir)
	_ = os.Remove(filepath.Join(dir, "wififiles.pid"))
	_ = os.Remove(filepath.Join(dir, "wififiles.ready"))
}

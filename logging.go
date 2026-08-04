package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

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

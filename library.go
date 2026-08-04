package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

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

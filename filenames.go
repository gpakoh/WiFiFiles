package main

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

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
		return fmt.Errorf("failed to check disk space: %w", err)
	}
	if required+uploadSafetyReserve > free {
		return fmt.Errorf("insufficient disk space: need %s, available %s", humanSize(int64(required)), humanSize(int64(free)))
	}
	return nil
}

func freeSpaceText(path string) string {
	free, err := availableBytes(path)
	if err != nil {
		return "unknown"
	}
	return humanSize(int64(free))
}

func ensureRequestUploadSpace(dir string, contentLength int64) error {
	if contentLength <= 0 {
		return nil
	}
	free, err := availableBytes(dir)
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}
	required := uint64(contentLength)
	if required+uploadSafetyReserve > free {
		return fmt.Errorf("insufficient disk space: need ~%s, available %s", humanSize(contentLength), humanSize(int64(free)))
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

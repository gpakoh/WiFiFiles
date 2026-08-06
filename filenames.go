package main

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const uploadSafetyReserve = uint64(4 << 20)

// diskSpaceAvailable is a seam for tests that need to simulate a full disk.
var diskSpaceAvailable = availableBytes

func availableBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
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
// Free space is re-checked while writing so that chunked uploads (unknown
// Content-Length) cannot fill the storage.
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
	var written int64
	const spaceCheckInterval = 4 << 20
	nextCheck := int64(spaceCheckInterval)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				return "", written, werr
			}
			written += int64(n)
			if written >= nextCheck {
				if err := ensureFreeSpaceDuringWrite(dir, written); err != nil {
					return "", written, err
				}
				nextCheck = written + spaceCheckInterval
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", written, rerr
		}
	}
	if err := ensureFreeSpaceDuringWrite(dir, written); err != nil {
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

func ensureFreeSpaceDuringWrite(dir string, written int64) error {
	free, err := diskSpaceAvailable(dir)
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}
	if uint64(written)+uploadSafetyReserve > free {
		return fmt.Errorf("insufficient disk space: need ~%s, available %s", humanSize(written), humanSize(int64(free)))
	}
	return nil
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

// uploadCommitMu serializes the check-then-rename commit of uploads so that
// two concurrent uploads of the same name cannot both see a free path and then
// clobber each other (TOCTOU race).
var uploadCommitMu sync.Mutex

func commitTempAutoRename(dir, name, tmpPath string) (string, error) {
	uploadCommitMu.Lock()
	defer uploadCommitMu.Unlock()
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

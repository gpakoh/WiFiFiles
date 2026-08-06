package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxMobileTokens        = 8
	maxMobileFilesPerToken = 100
)

func readMobileTokens() ([]MobileTokenRecord, error) {
	data, err := os.ReadFile(mobileTokenPath)
	if err != nil {
		return nil, err
	}
	var records []MobileTokenRecord
	if err := json.Unmarshal(data, &records); err == nil {
		if len(records) > maxMobileTokens {
			records = records[len(records)-maxMobileTokens:]
		}
		return records, nil
	}
	var single MobileTokenRecord
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	return []MobileTokenRecord{single}, nil
}

func writeMobileTokens(records []MobileTokenRecord) error {
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(mobileTokenPath), 0700)
	tmp := mobileTokenPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, mobileTokenPath)
}

func addMobileToken(record MobileTokenRecord) error {
	records, _ := readMobileTokens()
	now := time.Now().Unix()
	kept := make([]MobileTokenRecord, 0, len(records)+1)
	for _, r := range records {
		if r.Token == record.Token {
			continue
		}
		if now > r.Expires {
			removeMobileReceipts(r.Token)
			continue
		}
		kept = append(kept, r)
	}
	kept = append(kept, record)
	if len(kept) > maxMobileTokens {
		excess := kept[:len(kept)-maxMobileTokens]
		kept = kept[len(kept)-maxMobileTokens:]
		for _, r := range excess {
			removeMobileReceipts(r.Token)
		}
	}
	return writeMobileTokens(kept)
}

func loadMobileToken(token string) (MobileTokenRecord, error) {
	var record MobileTokenRecord
	records, err := readMobileTokens()
	if err != nil {
		return record, errors.New("temporary link not found")
	}
	now := time.Now().Unix()
	kept := make([]MobileTokenRecord, 0, len(records))
	found, expired := false, false
	for _, r := range records {
		if r.Token != token {
			kept = append(kept, r)
			continue
		}
		found = true
		if now > r.Expires {
			expired = true
			removeMobileReceipts(r.Token)
			continue
		}
		record = r
		kept = append(kept, r)
	}
	if len(kept) != len(records) {
		_ = writeMobileTokens(kept)
	}
	if expired {
		return record, errors.New("temporary link has expired")
	}
	if !found {
		return record, errors.New("temporary link is invalid")
	}
	if subtle.ConstantTimeCompare([]byte(record.Token), []byte(token)) != 1 {
		return record, errors.New("temporary link is invalid")
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
	uploadCommitMu.Lock()
	if !overwrite {
		for _, item := range pending {
			key := strings.ToLower(item.name)
			if _, exists := seen[key]; exists {
				uploadCommitMu.Unlock()
				redirectMsg(w, r, targetVirtual, "Один файл выбран несколько раз: "+item.name)
				return
			}
			seen[key] = struct{}{}
			if _, statErr := os.Stat(filepath.Join(target, item.name)); statErr == nil {
				uploadCommitMu.Unlock()
				redirectMsg(w, r, targetVirtual, "Файл уже существует: "+item.name+". Для замены отметьте соответствующий пункт.")
				return
			} else if !errors.Is(statErr, os.ErrNotExist) {
				uploadCommitMu.Unlock()
				http.Error(w, "upload error: "+statErr.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	for i := range pending {
		item := &pending[i]
		finalPath := filepath.Join(target, item.name)
		if err := os.Rename(item.tmpPath, finalPath); err != nil {
			uploadCommitMu.Unlock()
			http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		item.tmpPath = ""
		a.scheduleLibraryRefresh(finalPath)
	}
	uploadCommitMu.Unlock()
	redirectMsg(w, r, targetVirtual, "Загрузка завершена")
}

func safeUploadName(filename string) (string, error) {
	name := filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	if name == "." || name == ".." || name == "" || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid filename")
	}
	return name, nil
}

func saveUpload(dir string, hdr *multipart.FileHeader, overwrite bool) error {
	name, err := safeUploadName(hdr.Filename)
	if err != nil {
		return err
	}
	tmpPath, err := writeMultipartTemp(dir, hdr)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	finalPath := filepath.Join(dir, name)
	uploadCommitMu.Lock()
	defer uploadCommitMu.Unlock()
	if !overwrite {
		if _, statErr := os.Stat(finalPath); statErr == nil {
			return os.ErrExist
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	return os.Rename(tmpPath, finalPath)
}

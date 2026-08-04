package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const mobileReceiptPath = "/tmp/WiFiFiles/mobile_receipts.json"

type MobileUploadResult struct {
	Status   string `json:"status"`
	Original string `json:"original"`
	StoredAs string `json:"stored_as"`
	Message  string `json:"message"`
}

type mobileReceiptStore struct {
	Receipts map[string]map[string]MobileUploadResult `json:"receipts"`
}

type mobileFolderEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    string `json:"size"`
	ModTime string `json:"mod_time"`
}

func normalizeMobileMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "edit") {
		return "edit"
	}
	return "safe"
}

func strictMobileName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid filename")
	}
	if strings.ContainsAny(name, "/\\") || filepath.Base(name) != name {
		return "", errors.New("filename must not contain a path")
	}
	return name, nil
}

func (a *App) mobileEntries(targetDir string) ([]mobileFolderEntry, error) {
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}
	out := make([]mobileFolderEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		item := mobileFolderEntry{Name: entry.Name(), IsDir: info.IsDir(), ModTime: info.ModTime().Format("02.01.2006 15:04")}
		if !info.IsDir() {
			item.Size = humanSize(info.Size())
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (a *App) getMobileReceipt(token, uploadID string) (MobileUploadResult, bool) {
	a.mobileMu.Lock()
	defer a.mobileMu.Unlock()
	if results := a.mobileReceipts[token]; results != nil {
		result, ok := results[uploadID]
		if ok {
			return result, true
		}
	}
	data, err := os.ReadFile(mobileReceiptPath)
	if err != nil {
		return MobileUploadResult{}, false
	}
	var store mobileReceiptStore
	if json.Unmarshal(data, &store) != nil || store.Receipts == nil {
		return MobileUploadResult{}, false
	}
	results, ok := store.Receipts[token]
	if !ok || results == nil {
		return MobileUploadResult{}, false
	}
	a.mobileReceipts[token] = results
	result, ok := results[uploadID]
	return result, ok
}

func (a *App) saveMobileReceipt(token, uploadID string, result MobileUploadResult) {
	a.mobileMu.Lock()
	defer a.mobileMu.Unlock()
	results := a.mobileReceipts[token]
	if results == nil {
		results = make(map[string]MobileUploadResult)
		a.mobileReceipts[token] = results
	}
	results[uploadID] = result
	store := mobileReceiptStore{Receipts: a.mobileReceipts}
	if data, err := os.ReadFile(mobileReceiptPath); err == nil {
		var onDisk mobileReceiptStore
		if json.Unmarshal(data, &onDisk) == nil && onDisk.Receipts != nil {
			for tok, tokResults := range onDisk.Receipts {
				if tokResults == nil {
					continue
				}
				existing := store.Receipts[tok]
				if existing == nil {
					store.Receipts[tok] = tokResults
				} else {
					for id, r := range tokResults {
						if _, ok := existing[id]; !ok {
							existing[id] = r
						}
					}
				}
			}
		}
	}
	if data, err := json.Marshal(store); err == nil {
		_ = os.MkdirAll(filepath.Dir(mobileReceiptPath), 0700)
		tmp := mobileReceiptPath + ".tmp"
		if os.WriteFile(tmp, data, 0600) == nil {
			_ = os.Rename(tmp, mobileReceiptPath)
		}
	}
}

func removeMobileReceipts(token string) {
	if token == "" {
		return
	}
	data, err := os.ReadFile(mobileReceiptPath)
	if err != nil {
		return
	}
	var store mobileReceiptStore
	if json.Unmarshal(data, &store) != nil || store.Receipts == nil {
		return
	}
	if _, ok := store.Receipts[token]; !ok {
		return
	}
	delete(store.Receipts, token)
	if data, err := json.Marshal(store); err == nil {
		tmp := mobileReceiptPath + ".tmp"
		if os.WriteFile(tmp, data, 0600) == nil {
			_ = os.Rename(tmp, mobileReceiptPath)
		}
	}
}

func (a *App) addMobilePending(token, path string) {
	a.mobileMu.Lock()
	set := a.mobilePending[token]
	if set == nil {
		set = make(map[string]struct{})
		a.mobilePending[token] = set
	}
	set[path] = struct{}{}
	if timer := a.mobileTimers[token]; timer != nil {
		timer.Stop()
	}
	a.mobileTimers[token] = time.AfterFunc(2*time.Minute, func() { a.flushMobilePending(token) })
	a.mobileMu.Unlock()
}

func (a *App) flushMobilePending(token string) int {
	a.mobileMu.Lock()
	set := a.mobilePending[token]
	delete(a.mobilePending, token)
	if timer := a.mobileTimers[token]; timer != nil {
		timer.Stop()
		delete(a.mobileTimers, token)
	}
	a.mobileMu.Unlock()
	count := 0
	for path := range set {
		a.scheduleLibraryRefresh(path)
		count++
	}
	return count
}

func mobileJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func mobileRedirect(w http.ResponseWriter, r *http.Request, token, key, message string) {
	q := url.Values{}
	q.Set(key, message)
	http.Redirect(w, r, "/m/"+url.PathEscape(token)+"?"+q.Encode(), http.StatusSeeOther)
}

func (a *App) handleMobile(w http.ResponseWriter, r *http.Request) {
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
	record.Mode = normalizeMobileMode(record.Mode)
	targetDir, target, err := a.resolvePath(record.Target, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := ""
	if len(parts) >= 3 {
		action = parts[2]
	}

	switch {
	case action == "" && r.Method == http.MethodGet:
		a.renderMobileV2(w, token, targetDir, target, record.Mode, r.URL.Query().Get("msg"), r.URL.Query().Get("err"))
	case action == "fragment" && r.Method == http.MethodGet:
		entries, err := a.mobileEntries(targetDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-WiFiFiles-Free-Space", freeSpaceText(targetDir))
		a.renderMobileRows(w, token, record.Mode, entries, a.configSnapshot().Language)
	case action == "list" && r.Method == http.MethodGet:
		entries, err := a.mobileEntries(targetDir)
		if err != nil {
			mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		mobileJSON(w, http.StatusOK, map[string]any{"entries": entries, "free_space": freeSpaceText(targetDir), "mode": record.Mode})
	case action == "upload" && r.Method == http.MethodPost:
		a.handleMobileUploadOne(w, r, token, targetDir)
	case action == "finish" && r.Method == http.MethodPost:
		count := a.flushMobilePending(token)
		mobileJSON(w, http.StatusOK, map[string]any{"ok": true, "indexed": count})
	case action == "download" && r.Method == http.MethodGet:
		if record.Mode != "edit" {
			http.Error(w, "upload only", http.StatusForbidden)
			return
		}
		a.handleMobileDownload(w, r, targetDir)
	case action == "download-all" && r.Method == http.MethodGet:
		if record.Mode != "edit" {
			http.Error(w, "upload only", http.StatusForbidden)
			return
		}
		a.handleMobileDownloadAll(w, r, targetDir)
	case action == "delete" && r.Method == http.MethodPost:
		if record.Mode != "edit" {
			http.Error(w, "upload only", http.StatusForbidden)
			return
		}
		name, err := strictMobileName(r.FormValue("name"))
		if err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		full := filepath.Join(targetDir, name)
		st, err := os.Lstat(full)
		if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			mobileRedirect(w, r, token, "err", "Файл не найден")
			return
		}
		if err := os.Remove(full); err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		a.scheduleLibraryRefresh(full)
		appendLog(runtimeDirPath, "Mobile edit deleted /"+target+"/"+name)
		mobileRedirect(w, r, token, "msg", "Удалено: "+name)
	case action == "delete-all" && r.Method == http.MethodPost:
		if record.Mode != "edit" {
			http.Error(w, "upload only", http.StatusForbidden)
			return
		}
		count, err := a.deleteAllMobileFiles(targetDir)
		if err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		appendLog(runtimeDirPath, fmt.Sprintf("Mobile edit deleted all files /%s count=%d", target, count))
		mobileRedirect(w, r, token, "msg", fmt.Sprintf("Удалено файлов: %d", count))
	case action == "rename" && r.Method == http.MethodPost:
		if record.Mode != "edit" {
			http.Error(w, "upload only", http.StatusForbidden)
			return
		}
		oldName, err := strictMobileName(r.FormValue("old"))
		if err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		newName, err := strictMobileName(r.FormValue("new"))
		if err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		if oldName == newName {
			mobileRedirect(w, r, token, "msg", "Имя не изменено")
			return
		}
		oldPath, newPath := filepath.Join(targetDir, oldName), filepath.Join(targetDir, newName)
		st, err := os.Lstat(oldPath)
		if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			mobileRedirect(w, r, token, "err", "Файл не найден")
			return
		}
		if newInfo, err := os.Lstat(newPath); err == nil {
			if !os.SameFile(st, newInfo) {
				mobileRedirect(w, r, token, "err", "Файл с таким именем уже существует")
				return
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			mobileRedirect(w, r, token, "err", err.Error())
			return
		}
		a.scheduleLibraryRefresh(oldPath)
		a.scheduleLibraryRefresh(newPath)
		appendLog(runtimeDirPath, "Mobile edit renamed /"+target+"/"+oldName+" -> "+newName)
		mobileRedirect(w, r, token, "msg", "Переименовано: "+newName)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func readMultipartText(part io.Reader, max int64) (string, error) {
	data, err := io.ReadAll(io.LimitReader(part, max+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > max {
		return "", errors.New("form field too large")
	}
	return string(data), nil
}

func (a *App) handleMobileRawUpload(w http.ResponseWriter, r *http.Request, token, targetDir string) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := ensureRequestUploadSpace(targetDir, r.ContentLength); err != nil {
		mobileJSON(w, 507, map[string]string{"error": err.Error()})
		return
	}

	uploadID := strings.TrimSpace(r.Header.Get("X-WiFiFiles-Upload-ID"))
	if uploadID == "" {
		uploadID = strings.TrimSpace(r.URL.Query().Get("upload_id"))
	}
	if uploadID == "" || len(uploadID) > 240 {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Некорректный идентификатор передачи"})
		return
	}
	if result, ok := a.getMobileReceipt(token, uploadID); ok {
		mobileJSON(w, http.StatusOK, result)
		return
	}

	name, err := safeUploadName(strings.TrimSpace(r.URL.Query().Get("name")))
	if err != nil || !isBookFile(name) {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Поддерживаются только файлы книг"})
		return
	}

	tmpPath, size, err := writeStreamTemp(targetDir, r.Body)
	if err != nil {
		mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": "Не удалось сохранить файл: " + err.Error()})
		return
	}
	defer os.Remove(tmpPath)
	if size <= 0 {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Получен пустой файл"})
		return
	}

	originalPath := filepath.Join(targetDir, name)
	if st, statErr := os.Stat(originalPath); statErr == nil && st.Mode().IsRegular() && st.Size() == size {
		result := MobileUploadResult{Status: "skipped", Original: name, StoredAs: name, Message: "Файл с таким именем и размером уже есть — пропущен"}
		a.saveMobileReceipt(token, uploadID, result)
		mobileJSON(w, http.StatusOK, result)
		return
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": statErr.Error()})
		return
	}

	stored, err := commitTempAutoRename(targetDir, name, tmpPath)
	if err != nil {
		mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tmpPath = ""
	status := "uploaded"
	message := "Передано"
	if stored != name {
		status = "renamed"
		message = "Имя уже занято — сохранено как " + stored
	}
	result := MobileUploadResult{Status: status, Original: name, StoredAs: stored, Message: message}
	a.saveMobileReceipt(token, uploadID, result)
	a.addMobilePending(token, filepath.Join(targetDir, stored))
	appendLog(runtimeDirPath, "Mobile QR raw upload: "+stored)
	mobileJSON(w, http.StatusOK, result)
}

func (a *App) handleMobileUploadOne(w http.ResponseWriter, r *http.Request, token, targetDir string) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.TrimSpace(r.URL.Query().Get("name")) != "" && !strings.HasPrefix(contentType, "multipart/form-data") {
		a.handleMobileRawUpload(w, r, token, targetDir)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := ensureRequestUploadSpace(targetDir, r.ContentLength); err != nil {
		mobileJSON(w, 507, map[string]string{"error": err.Error()})
		return
	}

	uploadID := strings.TrimSpace(r.Header.Get("X-WiFiFiles-Upload-ID"))
	if uploadID == "" {
		uploadID = strings.TrimSpace(r.URL.Query().Get("upload_id"))
	}
	if uploadID != "" {
		if len(uploadID) > 240 {
			mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Некорректный идентификатор передачи"})
			return
		}
		if result, ok := a.getMobileReceipt(token, uploadID); ok {
			mobileJSON(w, http.StatusOK, result)
			return
		}
	}

	reader, err := r.MultipartReader()
	if err != nil {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Не удалось прочитать файл: " + err.Error()})
		return
	}

	var name, tmpPath string
	var size int64
	fileSeen := false
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Не удалось прочитать файл: " + nextErr.Error()})
			return
		}

		field := part.FormName()
		switch field {
		case "upload_id":
			if uploadID == "" {
				value, readErr := readMultipartText(part, 240)
				_ = part.Close()
				if readErr != nil {
					mobileJSON(w, http.StatusBadRequest, map[string]string{"error": readErr.Error()})
					return
				}
				uploadID = strings.TrimSpace(value)
				if uploadID == "" || len(uploadID) > 240 {
					mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Некорректный идентификатор передачи"})
					return
				}
				if result, ok := a.getMobileReceipt(token, uploadID); ok {
					mobileJSON(w, http.StatusOK, result)
					return
				}
			} else {
				_ = part.Close()
			}
		case "file":
			if fileSeen {
				_ = part.Close()
				mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Передавайте по одному файлу"})
				return
			}
			fileSeen = true
			name, err = safeUploadName(part.FileName())
			if err != nil || !isBookFile(name) {
				_ = part.Close()
				mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Поддерживаются только файлы книг"})
				return
			}
			tmpPath, size, err = writeStreamTemp(targetDir, part)
			_ = part.Close()
			if err != nil {
				mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": "Не удалось сохранить файл: " + err.Error()})
				return
			}
		default:
			_ = part.Close()
		}
	}

	if uploadID == "" || len(uploadID) > 240 {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Некорректный идентификатор передачи"})
		return
	}
	if !fileSeen || tmpPath == "" {
		mobileJSON(w, http.StatusBadRequest, map[string]string{"error": "Файл не выбран"})
		return
	}

	originalPath := filepath.Join(targetDir, name)
	if st, statErr := os.Stat(originalPath); statErr == nil && st.Mode().IsRegular() && st.Size() == size {
		result := MobileUploadResult{Status: "skipped", Original: name, StoredAs: name, Message: "Файл с таким именем и размером уже есть — пропущен"}
		a.saveMobileReceipt(token, uploadID, result)
		mobileJSON(w, http.StatusOK, result)
		return
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": statErr.Error()})
		return
	}

	stored, err := commitTempAutoRename(targetDir, name, tmpPath)
	if err != nil {
		mobileJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tmpPath = ""
	status := "uploaded"
	message := "Передано"
	if stored != name {
		status = "renamed"
		message = "Имя уже занято — сохранено как " + stored
	}
	result := MobileUploadResult{Status: status, Original: name, StoredAs: stored, Message: message}
	a.saveMobileReceipt(token, uploadID, result)
	a.addMobilePending(token, filepath.Join(targetDir, stored))
	appendLog(runtimeDirPath, "Mobile QR upload: "+stored)
	mobileJSON(w, http.StatusOK, result)
}

func (a *App) handleMobileDownload(w http.ResponseWriter, r *http.Request, targetDir string) {
	name, err := strictMobileName(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	full := filepath.Join(targetDir, name)
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(name)))
	http.ServeFile(w, r, full)
}

type mobileArchiveFile struct {
	name string
	path string
	info os.FileInfo
}

func mobileVisibleFiles(targetDir string) ([]mobileArchiveFile, error) {
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, err
	}
	files := make([]mobileArchiveFile, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		full := filepath.Join(targetDir, entry.Name())
		info, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files = append(files, mobileArchiveFile{name: entry.Name(), path: full, info: info})
	}
	sort.Slice(files, func(i, j int) bool {
		return strings.ToLower(files[i].name) < strings.ToLower(files[j].name)
	})
	return files, nil
}

func (a *App) handleMobileDownloadAll(w http.ResponseWriter, r *http.Request, targetDir string) {
	files, err := mobileVisibleFiles(targetDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(files) == 0 {
		http.Error(w, "no files in selected folder", http.StatusNotFound)
		return
	}

	archiveName := "WiFiFiles-" + time.Now().Format("20060102-150405") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", archiveName))
	zw := zip.NewWriter(w)
	for _, item := range files {
		header, err := zip.FileInfoHeader(item.info)
		if err != nil {
			_ = zw.Close()
			return
		}
		header.Name = item.name
		header.Method = zip.Store
		dst, err := zw.CreateHeader(header)
		if err != nil {
			_ = zw.Close()
			return
		}
		src, err := os.Open(item.path)
		if err != nil {
			_ = zw.Close()
			return
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := src.Close()
		if copyErr != nil || closeErr != nil {
			_ = zw.Close()
			return
		}
	}
	_ = zw.Close()
	appendLog(runtimeDirPath, fmt.Sprintf("Mobile edit downloaded all files count=%d", len(files)))
}

func (a *App) deleteAllMobileFiles(targetDir string) (int, error) {
	files, err := mobileVisibleFiles(targetDir)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, item := range files {
		if err := os.Remove(item.path); err != nil {
			return deleted, fmt.Errorf("deleted %d, then error: %w", deleted, err)
		}
		a.scheduleLibraryRefresh(item.path)
		deleted++
	}
	return deleted, nil
}

func (a *App) renderMobileRows(w http.ResponseWriter, token, mode string, entries []mobileFolderEntry, lang string) {
	downloadText := mobileText(lang, "Скачать", "Download", "Télécharger", "Herunterladen")
	renameText := mobileText(lang, "Переименовать", "Rename", "Renommer", "Umbenennen")
	deleteText := mobileText(lang, "Удалить", "Delete", "Supprimer", "Löschen")
	confirmDelete := mobileText(lang, "Удалить этот файл?", "Delete this file?", "Supprimer ce fichier ?", "Diese Datei löschen?")
	for _, entry := range entries {
		fmt.Fprint(w, "<div class=\"file-row\">")
		prefix := ""
		if entry.IsDir {
			prefix = "[Папка] "
		}
		meta := entry.ModTime
		if entry.Size != "" {
			meta = entry.Size + " · " + entry.ModTime
		}
		fmt.Fprintf(w, "<div class=\"file-name\">%s%s</div><div class=\"file-meta\">%s</div>", template.HTMLEscapeString(prefix), template.HTMLEscapeString(entry.Name), template.HTMLEscapeString(meta))
		if mode == "edit" && !entry.IsDir {
			fmt.Fprintf(w, "<form class=\"edit-form\" method=\"post\" action=\"/m/%s/rename\"><a class=\"button download-action\" href=\"/m/%s/download?name=%s\">%s</a><input type=\"hidden\" name=\"old\" value=\"%s\"><input class=\"rename-input\" name=\"new\" value=\"%s\" required><div class=\"edit-buttons\"><button class=\"danger\" type=\"submit\" formnovalidate formaction=\"/m/%s/delete\" name=\"name\" value=\"%s\" onclick=\"return confirm(%s)\">%s</button><button type=\"submit\" formaction=\"/m/%s/rename\">%s</button></div></form>", template.HTMLEscapeString(token), template.HTMLEscapeString(token), url.QueryEscape(entry.Name), template.HTMLEscapeString(downloadText), template.HTMLEscapeString(entry.Name), template.HTMLEscapeString(entry.Name), template.HTMLEscapeString(token), template.HTMLEscapeString(entry.Name), template.HTMLEscapeString(strconv.Quote(confirmDelete)), template.HTMLEscapeString(deleteText), template.HTMLEscapeString(token), template.HTMLEscapeString(renameText))
		}
		fmt.Fprint(w, "</div>")
	}
}

func (a *App) renderMobileV2(w http.ResponseWriter, token, targetDir, target, mode, msg, pageErr string) {
	cfg := a.configSnapshot()
	lang := cfg.Language
	entries, listErr := a.mobileEntries(targetDir)
	if listErr != nil && pageErr == "" {
		pageErr = listErr.Error()
	}
	title := mobileText(lang, "Передача с телефона по QR-коду", "Phone transfer by QR code", "Transfert depuis un téléphone par code QR", "Übertragung vom Telefon per QR-Code")
	modeTitle := mobileText(lang, "Безопасный режим", "Safe mode", "Mode sécurisé", "Sicherer Modus")
	modeNote := mobileText(lang, "Можно просматривать список и отправлять книги. Скачивание, удаление и переименование отключены.", "You can view the list and send books. Download, delete and rename are disabled.", "Vous pouvez consulter la liste et envoyer des livres. Le téléchargement, la suppression et le renommage sont désactivés.", "Sie können die Liste ansehen und Bücher senden. Herunterladen, Löschen und Umbenennen sind deaktiviert.")
	if mode == "edit" {
		modeTitle = mobileText(lang, "Режим редактирования", "Edit mode", "Mode édition", "Bearbeitungsmodus")
		modeNote = mobileText(lang, "В выбранной папке можно отправлять, скачивать, переименовывать и удалять файлы. Выход за пределы этой папки запрещён.", "Inside the selected folder you can upload, download, rename and delete files. Access outside this folder is blocked.", "Dans le dossier sélectionné, vous pouvez envoyer, télécharger, renommer et supprimer des fichiers. L’accès en dehors de ce dossier est bloqué.", "Im ausgewählten Ordner können Dateien hochgeladen, heruntergeladen, umbenannt und gelöscht werden. Der Zugriff außerhalb dieses Ordners ist gesperrt.")
	}
	choose := mobileText(lang, "Выберите одну или несколько книг", "Choose one or more books", "Choisissez un ou plusieurs livres", "Wählen Sie ein oder mehrere Bücher")
	send := mobileText(lang, "Начать передачу", "Start transfer", "Démarrer le transfert", "Übertragung starten")
	destination := mobileText(lang, "Выбранная папка", "Selected folder", "Dossier sélectionné", "Ausgewählter Ordner")
	freeLabel := mobileText(lang, "Свободное место", "Free space", "Espace libre", "Freier Speicher")
	folderContents := mobileText(lang, "Что уже находится в папке", "Files already in the folder", "Contenu actuel du dossier", "Bereits im Ordner vorhanden")
	empty := mobileText(lang, "Папка пуста", "The folder is empty", "Le dossier est vide", "Der Ordner ist leer")
	reload := mobileText(lang, "Обновить список", "Refresh list", "Actualiser la liste", "Liste aktualisieren")
	currentProgress := mobileText(lang, "Текущий файл", "Current file", "Fichier actuel", "Aktuelle Datei")
	overallProgress := mobileText(lang, "Общий прогресс", "Overall progress", "Progression totale", "Gesamtfortschritt")
	preparing := mobileText(lang, "Подготовка…", "Preparing…", "Préparation…", "Vorbereitung…")
	networkError := mobileText(lang, "Передача не удалась. Проверьте Wi‑Fi.", "Transfer failed. Check Wi-Fi.", "Échec du transfert. Vérifiez le Wi-Fi.", "Übertragung fehlgeschlagen. Prüfen Sie das WLAN.")
	retryFailed := mobileText(lang, "Повторить неудавшиеся", "Retry failed files", "Réessayer les fichiers en échec", "Fehlgeschlagene erneut versuchen")
	completed := mobileText(lang, "Очередь завершена", "Queue complete", "File d’attente terminée", "Warteschlange abgeschlossen")
	transferred := mobileText(lang, "Передано", "Transferred", "Transférés", "Übertragen")
	skipped := mobileText(lang, "Уже было — пропущено", "Already present — skipped", "Déjà présent — ignoré", "Bereits vorhanden — übersprungen")
	failedText := mobileText(lang, "Не удалось", "Failed", "Échecs", "Fehlgeschlagen")
	downloadAll := mobileText(lang, "Скачать всё", "Download all", "Tout télécharger", "Alles herunterladen")
	deleteAll := mobileText(lang, "Удалить всё", "Delete all", "Tout supprimer", "Alles löschen")
	confirmDeleteAll := mobileText(lang, "Удалить все файлы в выбранной папке? Вложенные папки останутся.", "Delete all files in the selected folder? Subfolders will remain.", "Supprimer tous les fichiers du dossier sélectionné ? Les sous-dossiers resteront.", "Alle Dateien im ausgewählten Ordner löschen? Unterordner bleiben erhalten.")
	badgeClass := "badge"
	if mode == "edit" {
		badgeClass = "badge badge-edit"
	} else {
		badgeClass = "badge badge-safe"
	}
	free := freeSpaceText(targetDir)

	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>WiFiFiles</title><style>body{font-family:system-ui,"Segoe UI",sans-serif;margin:0;background:#f2f2f7;color:#111;padding:max(18px,env(safe-area-inset-top)) 14px max(24px,env(safe-area-inset-bottom))}.wrap{max-width:720px;margin:auto}.card{background:#fff;border-radius:16px;padding:18px;margin:13px 0;box-shadow:0 1px 4px #0002}h1{font-size:29px;line-height:1.15;margin:8px 0 15px}h2{font-size:21px;margin:0 0 12px}.path{font-weight:700;word-break:break-word;background:#f2f2f7;border-radius:10px;padding:12px}.badge{display:inline-block;padding:6px 10px;border-radius:999px;background:#e6eefc;font-weight:700}.badge-safe{background:#e9f8ed;color:#1d6b2c;border:1px solid #9fd8ab}.badge-edit{background:#fff4e0;color:#8a5a00;border:1px solid #ecc96a}.muted{color:#555;line-height:1.4}.ok{background:#e9f8ed;border-left:5px solid #248a3d;padding:13px;border-radius:10px}.err{background:#fff0f0;border-left:5px solid #b00020;padding:13px;border-radius:10px}input[type=file]{font-size:17px;width:100%;box-sizing:border-box;padding:13px;border:2px dashed #777;border-radius:12px;background:#fafafa}button,.button{display:inline-block;box-sizing:border-box;font:inherit;font-weight:700;padding:12px 14px;border:1px solid #555;border-radius:10px;background:#f5f5f5;color:#111;text-decoration:none;text-align:center}button.primary{width:100%;font-size:19px;padding:15px;background:#111;color:#fff;border:0;margin-top:14px}button.danger{color:#a00016;border-color:#a00016;background:#fff}.progressbox{display:none;margin-top:16px}.progressbox.visible{display:block}progress{width:100%;height:21px}.progress-label{display:flex;justify-content:space-between;gap:10px;margin:7px 0 4px;font-weight:700}.result-row,.file-row{border-top:1px solid #ddd;padding:11px 0}.file-row:first-child{border-top:0}.file-name{font-weight:700;word-break:break-word}.file-meta{font-size:.88em;color:#666;margin-top:3px}.edit-form{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}.download-action,.rename-input{grid-column:1/-1}.rename-input{min-width:0;width:100%;box-sizing:border-box;font:inherit;padding:11px;border:1px solid #888;border-radius:9px}.edit-buttons{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:8px}.edit-buttons button{width:100%;min-width:0}.bulk-actions{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:15px;padding-top:15px;border-top:1px solid #ddd}.bulk-actions form,.bulk-actions button,.bulk-actions .button{width:100%;margin:0;min-width:0}.summary{font-size:18px;line-height:1.55}.status-uploaded{color:#176c2f}.status-skipped{color:#7a5700}.status-failed{color:#a00016}</style></head><body><div class="wrap">`)
	fmt.Fprintf(w, "<h1>%s</h1>", template.HTMLEscapeString(title))
	if msg != "" {
		fmt.Fprintf(w, "<div class=\"ok\">%s</div>", template.HTMLEscapeString(msg))
	}
	if pageErr != "" {
		fmt.Fprintf(w, "<div class=\"err\">%s</div>", template.HTMLEscapeString(pageErr))
	}
	fmt.Fprintf(w, "<div class=\"card\"><span class=\"%s\">%s</span><p class=\"muted\">%s</p><div class=\"muted\">%s</div><div class=\"path\">%s</div><p><strong>%s:</strong> <span id=\"free-space\">%s</span></p></div>", template.HTMLEscapeString(badgeClass), template.HTMLEscapeString(modeTitle), template.HTMLEscapeString(modeNote), template.HTMLEscapeString(destination), template.HTMLEscapeString(mobileTargetLabel(lang, target)), template.HTMLEscapeString(freeLabel), template.HTMLEscapeString(free))
	fmt.Fprintf(w, "<form id=\"queue-form\" class=\"card\"><h2>%s</h2><input id=\"book-files\" type=\"file\" multiple accept=\".epub,.fb2,.fb2.zip,.pdf,.djvu,.djv,.mobi,.prc,.azw,.azw3,.txt,.rtf,.doc,.docx,.chm,.html,.htm,.cbz,.cbr,.tcr,.pdb\" required><button id=\"start-button\" class=\"primary\" type=\"submit\">%s</button><div id=\"progress-box\" class=\"progressbox\"><div class=\"progress-label\"><span>%s</span><span id=\"current-label\"></span></div><progress id=\"current-progress\" max=\"100\" value=\"0\"></progress><div class=\"progress-label\"><span>%s</span><span id=\"overall-label\"></span></div><progress id=\"overall-progress\" max=\"100\" value=\"0\"></progress></div><div id=\"results\"></div><div id=\"summary-box\"></div><button id=\"retry-button\" class=\"primary\" type=\"button\" style=\"display:none\">%s</button></form>", template.HTMLEscapeString(choose), template.HTMLEscapeString(send), template.HTMLEscapeString(currentProgress), template.HTMLEscapeString(overallProgress), template.HTMLEscapeString(retryFailed))
	fmt.Fprintf(w, "<div class=\"card\"><div style=\"display:flex;justify-content:space-between;gap:10px;align-items:center\"><h2>%s</h2><a class=\"button\" href=\"/m/%s\">%s</a></div>", template.HTMLEscapeString(folderContents), template.HTMLEscapeString(token), template.HTMLEscapeString(reload))
	fmt.Fprint(w, "<div id=\"folder-list\">")
	if len(entries) == 0 {
		fmt.Fprintf(w, "<p class=\"muted\">%s</p>", template.HTMLEscapeString(empty))
	} else {
		a.renderMobileRows(w, token, mode, entries, lang)
	}
	fmt.Fprint(w, "</div>")
	if mode == "edit" {
		fmt.Fprintf(w, "<div class=\"bulk-actions\"><a class=\"button\" href=\"/m/%s/download-all\">%s</a><form method=\"post\" action=\"/m/%s/delete-all\" onsubmit=\"return confirm(%s)\"><button class=\"danger\" type=\"submit\">%s</button></form></div>", template.HTMLEscapeString(token), template.HTMLEscapeString(downloadAll), template.HTMLEscapeString(token), template.HTMLEscapeString(strconv.Quote(confirmDeleteAll)), template.HTMLEscapeString(deleteAll))
	}
	fmt.Fprint(w, "</div>")

	js := fmt.Sprintf(`(function(){
var form=document.getElementById('queue-form'),input=document.getElementById('book-files'),start=document.getElementById('start-button'),retry=document.getElementById('retry-button'),box=document.getElementById('progress-box'),cp=document.getElementById('current-progress'),op=document.getElementById('overall-progress'),cl=document.getElementById('current-label'),ol=document.getElementById('overall-label'),results=document.getElementById('results'),summaryBox=document.getElementById('summary-box'),folderList=document.getElementById('folder-list'),freeSpace=document.getElementById('free-space');
var failed=[],stats={uploaded:0,skipped:0,failed:0};
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function setState(item,state,name,msg){if(item.state&&stats[item.state]>0)stats[item.state]--;item.state=state;stats[state]++;var id='result-'+item.domId,el=document.getElementById(id),html='<strong>'+esc(name)+'</strong><br>'+esc(msg);if(!el){results.insertAdjacentHTML('beforeend','<div id="'+id+'" class="result-row status-'+state+'">'+html+'</div>');}else{el.className='result-row status-'+state;el.innerHTML=html;}}
function refreshList(){var x=new XMLHttpRequest();x.open('GET','/m/%s/fragment',true);x.onload=function(){if(x.status>=200&&x.status<300){folderList.innerHTML=x.responseText;var f=x.getResponseHeader('X-WiFiFiles-Free-Space');if(f&&freeSpace)freeSpace.textContent=f;}};x.send();} function finishServer(cb){var x=new XMLHttpRequest();x.open('POST','/m/%s/finish',true);x.onload=function(){refreshList();cb&&cb();};x.onerror=function(){cb&&cb();};x.send('');}
function summary(){summaryBox.innerHTML='<div class="card summary"><strong>%s</strong><br>%s: '+stats.uploaded+'<br>%s: '+stats.skipped+'<br>%s: '+stats.failed+'</div>';retry.style.display=failed.length?'block':'none';start.disabled=false;}
function upload(item,index,total,done){var x=new XMLHttpRequest(),u='/m/%s/upload?upload_id='+encodeURIComponent(item.id)+'&name='+encodeURIComponent(item.file.name);x.open('POST',u,true);x.setRequestHeader('Content-Type','application/octet-stream');cl.textContent=item.file.name;cp.value=0;x.upload.onprogress=function(e){if(!e.lengthComputable)return;var p=Math.round(e.loaded*100/e.total);cp.value=p;op.value=Math.round(((index+p/100)/total)*100);ol.textContent=(index+1)+' / '+total;};x.onerror=function(){failed.push(item);setState(item,'failed',item.file.name,%s);done();};x.onload=function(){if(x.status>=200&&x.status<300){try{var r=JSON.parse(x.responseText);if(r.status==='skipped'){setState(item,'skipped',r.stored_as,r.message);}else{setState(item,'uploaded',r.stored_as,r.message);}done();}catch(e){failed.push(item);setState(item,'failed',item.file.name,%s);done();}}else{var m=%s;try{m=JSON.parse(x.responseText).error||m;}catch(e){}failed.push(item);setState(item,'failed',item.file.name,m);done();}};x.send(item.file);}
function run(items,reset){if(!items.length)return;if(reset){failed=[];stats={uploaded:0,skipped:0,failed:0};results.innerHTML='';}else{failed=[];}summaryBox.innerHTML='';retry.style.display='none';start.disabled=true;box.className='progressbox visible';cp.value=0;op.value=0;cl.textContent=%s;var i=0;function next(){if(i>=items.length){op.value=100;finishServer(summary);return;}var item=items[i],idx=i;i++;upload(item,idx,items.length,next);}next();}
form.addEventListener('submit',function(e){e.preventDefault();var fs=Array.prototype.slice.call(input.files||[]),batch=Date.now().toString(36)+'-'+Math.random().toString(36).slice(2),items=fs.map(function(f,i){return{file:f,id:batch+'-'+i+'-'+f.size+'-'+f.lastModified,domId:'q'+i,state:''};});run(items,true);});
retry.addEventListener('click',function(){var again=failed.slice();run(again,false);});
})();`, template.JSEscapeString(token), template.JSEscapeString(token), template.JSEscapeString(completed), template.JSEscapeString(transferred), template.JSEscapeString(skipped), template.JSEscapeString(failedText), template.JSEscapeString(token), strconv.Quote(networkError), strconv.Quote(networkError), strconv.Quote(networkError), strconv.Quote(preparing))
	fmt.Fprintf(w, "<script>%s</script></div></body></html>", js)
}

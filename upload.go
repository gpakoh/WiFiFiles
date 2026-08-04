package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
	note := mobileText(lang, "Ссылка действует 20 минут. Файл с совпадающим именем не заменяется: к новому имени добавляется номер.", "The link is valid for 20 minutes. An existing file is never replaced; a number is added to the new filename.", "Le lien reste valide pendant 20 minutes. Un fichier existant n'est jamais remplacé : un numéro est ajouté au nouveau nom.", "Der Link ist 20 Minuten gültig. Vorhandene Dateien werden nicht ersetzt; der neue Dateiname erhält eine Nummer.")
	done := mobileText(lang, "Передача завершена", "Transfer complete", "Transfert terminé", "Übertragung abgeschlossen")
	more := mobileText(lang, "Библиотека ридера обновляется. Через несколько секунд книга появится в разделе «Новые». Можно отправить ещё одну книгу.", "The reader library is updating. The book should appear under New in a few seconds. You can send another book.", "La bibliothèque du lecteur est en cours de mise à jour. Le livre devrait apparaître dans « Nouveaux » dans quelques secondes. Vous pouvez envoyer un autre livre.", "Die Bibliothek des Readers wird aktualisiert. Das Buch sollte in wenigen Sekunden unter „Neu“ erscheinen. Sie können ein weiteres Buch senden.")
	preparing := mobileText(lang, "Подготовка передачи…", "Preparing transfer…", "Préparation du transfert…", "Übertragung wird vorbereitet…")
	transferring := mobileText(lang, "Передача", "Transferring", "Transfert", "Übertragung")
	networkError := mobileText(lang, "Не удалось передать файл. Проверьте Wi‑Fi и повторите попытку.", "The file could not be transferred. Check Wi-Fi and try again.", "Le fichier n'a pas pu être transféré. Vérifiez le Wi-Fi et réessayez.", "Die Datei konnte nicht übertragen werden. Prüfen Sie das WLAN und versuchen Sie es erneut.")
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

package main

import (
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

type davBrowserCrumb struct {
	Name string
	Href string
}

type davBrowserEntry struct {
	Name      string
	Href      string
	Size      string
	ModTime   string
	IsDir     bool
	CanModify bool
	Download  string
	Virtual   string
}

type davBrowserView struct {
	Version        string
	Title          string
	Subtitle       string
	CurrentHref    string
	CurrentPath    string
	FreeSpace      string
	CanWriteHere   bool
	Entries        []davBrowserEntry
	Crumbs         []davBrowserCrumb
	Upload         string
	CreateFolder   string
	Refresh        string
	Download       string
	Rename         string
	Move           string
	Copy           string
	Delete         string
	NewName        string
	FolderEmpty    string
	FullAccess     string
	UploadHint     string
	NoFiles        string
	Progress       string
	CurrentFile    string
	Overall        string
	Done           string
	Failed         string
	PromptFolder   string
	PromptMove     string
	PromptCopy     string
	ConfirmDelete  string
	ConfirmReplace string
	NameUnchanged  string
}

var davBrowserPage = template.Must(template.New("dav-browser").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>{{.Title}}</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{font-family:system-ui,"Segoe UI",sans-serif;margin:0;background:#f2f2f7;color:#111;padding:max(18px,env(safe-area-inset-top)) 14px max(26px,env(safe-area-inset-bottom))}.wrap{max-width:920px;margin:auto}.card{background:#fff;border-radius:16px;padding:17px;margin:13px 0;box-shadow:0 1px 4px #0002}h1{font-size:28px;line-height:1.15;margin:5px 0 8px}h2{font-size:21px;margin:0 0 12px}.badge{display:inline-block;background:#e9f8ed;color:#176c2f;font-weight:800;border-radius:999px;padding:6px 10px}.muted{color:#5b5b63;line-height:1.42}.path{font-weight:750;word-break:break-word;background:#f2f2f7;border-radius:10px;padding:11px}.crumbs{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:10px 0}.crumbs a{text-decoration:none;color:#0645ad}.toolbar,.entry-actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.toolbar{margin-top:13px}.entry{border-top:1px solid #ddd;padding:14px 0}.entry:first-child{border-top:0}.entry-title{font-weight:800;word-break:break-word}.entry-title a{color:#111;text-decoration:none}.meta{font-size:.88em;color:#666;margin:4px 0 10px}.rename-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin:9px 0}.rename-input{width:100%;min-width:0;font:inherit;padding:11px;border:1px solid #888;border-radius:9px}button,.button{display:inline-block;width:100%;min-width:0;font:inherit;font-weight:750;padding:11px 12px;border:1px solid #555;border-radius:10px;background:#f7f7f8;color:#111;text-decoration:none;text-align:center}.primary{background:#111;color:#fff;border-color:#111}.danger{color:#a00016;border-color:#a00016;background:#fff}.progressbox{display:none}.progressbox.visible{display:block}.progress-label{display:flex;justify-content:space-between;gap:10px;margin:7px 0 4px;font-weight:750}progress{width:100%;height:21px}.status{white-space:pre-wrap;word-break:break-word;margin-top:10px}.ok{background:#e9f8ed;border-left:5px solid #248a3d;padding:12px;border-radius:10px}.err{background:#fff0f0;border-left:5px solid #b00020;padding:12px;border-radius:10px}input[type=file]{font-size:16px;width:100%;padding:12px;border:2px dashed #777;border-radius:12px;background:#fafafa}.hidden{display:none}@media(max-width:650px){.toolbar{grid-template-columns:1fr 1fr}.entry-actions{grid-template-columns:1fr 1fr}.toolbar .wide{grid-column:1/-1}.rename-row{grid-template-columns:1fr}.rename-row button{width:100%}}@media(max-width:390px){.entry-actions{grid-template-columns:1fr}}
</style></head>
<body><div class="wrap" id="dav-app" data-current="{{.CurrentHref}}" data-confirm-delete="{{.ConfirmDelete}}" data-confirm-replace="{{.ConfirmReplace}}" data-prompt-folder="{{.PromptFolder}}" data-prompt-move="{{.PromptMove}}" data-prompt-copy="{{.PromptCopy}}" data-name-unchanged="{{.NameUnchanged}}">
<div class="card"><span class="badge">{{.FullAccess}}</span><h1>{{.Title}}</h1><p class="muted">{{.Subtitle}}</p><div class="crumbs">{{range $i,$c:=.Crumbs}}{{if $i}}<span>›</span>{{end}}<a href="{{$c.Href}}">{{$c.Name}}</a>{{end}}</div><div class="path">{{.CurrentPath}}{{if .FreeSpace}}<br><span class="muted">{{.FreeSpace}}</span>{{end}}</div>
{{if .CanWriteHere}}<div class="toolbar"><button type="button" id="choose-files" class="primary wide">{{.Upload}}</button><button type="button" id="create-folder">{{.CreateFolder}}</button><button type="button" onclick="location.reload()">{{.Refresh}}</button></div><input id="files" class="hidden" type="file" multiple><p class="muted">{{.UploadHint}}</p>{{end}}</div>
<div id="progress" class="card progressbox"><h2>{{.Progress}}</h2><div class="progress-label"><span>{{.CurrentFile}}</span><span id="file-pct">0%</span></div><div id="file-name" class="muted">—</div><progress id="file-progress" max="100" value="0"></progress><div class="progress-label"><span>{{.Overall}}</span><span id="overall-count">0 / 0</span></div><progress id="overall-progress" max="100" value="0"></progress><div id="status" class="status"></div></div>
<div class="card"><h2>{{.CurrentPath}}</h2>{{range .Entries}}<div class="entry" data-href="{{.Href}}" data-name="{{.Name}}" data-dir="{{.IsDir}}"><div class="entry-title">{{if .IsDir}}📁 <a href="{{.Href}}">{{.Name}}</a>{{else}}📄 <a href="{{.Download}}">{{.Name}}</a>{{end}}</div><div class="meta">{{.Size}}{{if .Size}} · {{end}}{{.ModTime}}</div>{{if .CanModify}}<div class="rename-row"><input class="rename-input" value="{{.Name}}" aria-label="{{$.NewName}}"><button type="button" class="rename">{{$.Rename}}</button></div><div class="entry-actions">{{if not .IsDir}}<a class="button" href="{{.Download}}">{{$.Download}}</a>{{end}}<button type="button" class="move">{{$.Move}}</button><button type="button" class="copy">{{$.Copy}}</button><button type="button" class="delete danger">{{$.Delete}}</button></div>{{end}}</div>{{else}}<p class="muted">{{.FolderEmpty}}</p>{{end}}</div>
<p class="muted">WebDAV read/write · WiFiFiles {{.Version}}</p></div>
<script>
(function(){
const app=document.getElementById('dav-app'), current=app.dataset.current, files=document.getElementById('files'), choose=document.getElementById('choose-files'), progress=document.getElementById('progress'), fp=document.getElementById('file-progress'), op=document.getElementById('overall-progress'), fn=document.getElementById('file-name'), pc=document.getElementById('file-pct'), oc=document.getElementById('overall-count'), status=document.getElementById('status');
function text(r){return r.text().then(t=>{if(!r.ok)throw new Error(t.trim()||('HTTP '+r.status));return t})}
function join(base,name){if(!base.endsWith('/'))base+='/';return base+encodeURIComponent(name)}
function normalizeDestination(value){value=(value||'').trim();if(!value)return '';if(value.startsWith(location.origin))value=value.slice(location.origin.length);if(value.startsWith('/dav/'))return value;if(value==='/dav')return '/dav/';if(value.startsWith('/'))return '/dav'+value;let parts=value.split('/').filter(Boolean).map(encodeURIComponent);return current+parts.join('/')}
async function moveOrCopy(method,href,destination){let dest=normalizeDestination(destination);if(!dest)return;let send=overwrite=>fetch(href,{method,credentials:'same-origin',headers:{Destination:location.origin+dest,Overwrite:overwrite?'T':'F'}});let r=await send(false);if(r.status===412&&confirm(app.dataset.confirmReplace)){r=await send(true)}await text(r);location.reload()}
function xhrPut(file,href,overwrite,onprogress){return new Promise((resolve,reject)=>{let x=new XMLHttpRequest();x.open('PUT',href,true);x.withCredentials=true;if(!overwrite)x.setRequestHeader('If-None-Match','*');x.upload.onprogress=e=>{if(e.lengthComputable)onprogress(e.loaded,e.total)};x.onerror=()=>reject(new Error('Ошибка сети'));x.onload=()=>{if(x.status>=200&&x.status<300)resolve();else{let e=new Error((x.responseText||('HTTP '+x.status)).trim());e.status=x.status;reject(e)}};x.send(file)})}
async function uploadAll(list){progress.classList.add('visible');status.className='status';status.textContent='';let done=0,failed=0;op.value=0;oc.textContent='0 / '+list.length;for(let i=0;i<list.length;i++){let file=list[i],href=join(current,file.name);fn.textContent=file.name;fp.value=0;pc.textContent='0%';try{await xhrPut(file,href,false,(loaded,total)=>{let pct=total?Math.round(loaded*100/total):0;fp.value=pct;pc.textContent=pct+'%'});done++}catch(e){if(e.status===412&&confirm(app.dataset.confirmReplace+'\n'+file.name)){try{await xhrPut(file,href,true,(loaded,total)=>{let pct=total?Math.round(loaded*100/total):0;fp.value=pct;pc.textContent=pct+'%'});done++}catch(e2){failed++;status.textContent+=file.name+': '+e2.message+'\n'}}else{failed++;status.textContent+=file.name+': '+e.message+'\n'}}let count=i+1;oc.textContent=count+' / '+list.length;op.value=Math.round(count*100/list.length)}status.className='status '+(failed?'err':'ok');status.textContent=(status.textContent?status.textContent+'\n':'')+'{{.Done}}: '+done+'\n{{.Failed}}: '+failed;if(!failed)setTimeout(()=>location.reload(),700)}
if(choose&&files){choose.onclick=()=>files.click();files.onchange=()=>{if(files.files&&files.files.length)uploadAll(Array.from(files.files))}}
const create=document.getElementById('create-folder');if(create)create.onclick=async()=>{let name=prompt(app.dataset.promptFolder,'');if(!name)return;try{await text(await fetch(join(current,name),{method:'MKCOL',credentials:'same-origin'}));location.reload()}catch(e){alert(e.message)}};
document.querySelectorAll('.entry').forEach(row=>{let href=row.dataset.href,name=row.dataset.name,input=row.querySelector('.rename-input');let ren=row.querySelector('.rename');if(ren)ren.onclick=async()=>{let next=(input.value||'').trim();if(!next||next===name){alert(app.dataset.nameUnchanged);return}try{await moveOrCopy('MOVE',href,join(current,next))}catch(e){alert(e.message)}};let mv=row.querySelector('.move');if(mv)mv.onclick=async()=>{let dest=prompt(app.dataset.promptMove,name);if(!dest)return;try{await moveOrCopy('MOVE',href,dest)}catch(e){alert(e.message)}};let cp=row.querySelector('.copy');if(cp)cp.onclick=async()=>{let dest=prompt(app.dataset.promptCopy,name);if(!dest)return;try{await moveOrCopy('COPY',href,dest)}catch(e){alert(e.message)}};let del=row.querySelector('.delete');if(del)del.onclick=async()=>{if(!confirm(app.dataset.confirmDelete+'\n'+name))return;try{await text(await fetch(href,{method:'DELETE',credentials:'same-origin'}));location.reload()}catch(e){alert(e.message)}}})
})();
</script></body></html>`))

func davBrowserRequest(r *http.Request) bool {
	if r.URL.Query().Get("raw") == "1" {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(accept, "text/html") || strings.Contains(ua, "mozilla") || strings.Contains(ua, "safari") || strings.Contains(ua, "chrome")
}

func davDisplayPath(virtual string) string {
	if virtual == "/" {
		return "WiFiFiles"
	}
	parts := strings.Split(strings.TrimPrefix(virtual, "/"), "/")
	if len(parts) > 0 {
		switch parts[0] {
		case "internal":
			parts[0] = "INTERNAL"
		case "sd":
			parts[0] = "SDCARD"
		}
	}
	return "/" + strings.Join(parts, "/")
}

func davCrumbs(resource davResource) []davBrowserCrumb {
	out := []davBrowserCrumb{{Name: "WiFiFiles", Href: "/dav/"}}
	if resource.Virtual == "/" {
		return out
	}
	parts := strings.Split(strings.TrimPrefix(resource.Virtual, "/"), "/")
	for i := range parts {
		virtual := "/" + strings.Join(parts[:i+1], "/")
		name := parts[i]
		if i == 0 {
			if name == "internal" {
				name = "INTERNAL"
			} else if name == "sd" {
				name = "SDCARD"
			}
		}
		out = append(out, davBrowserCrumb{Name: name, Href: davHref(virtual, true)})
	}
	return out
}

func davProtectedResource(resource davResource) bool {
	return resource.Virtual == "/" || resource.Virtual == "/internal" || resource.Virtual == "/sd"
}

func (d *DAVServer) renderDAVBrowser(w http.ResponseWriter, resource davResource, children []davResource) {
	lang := d.app.configSnapshot().Language
	entries := make([]davBrowserEntry, 0, len(children))
	for _, child := range children {
		size := ""
		if !child.Info.IsDir() {
			size = humanSize(child.Info.Size())
		}
		href := davHref(child.Virtual, child.Info.IsDir())
		download := href
		if !child.Info.IsDir() {
			download += "?download=1"
		}
		entries = append(entries, davBrowserEntry{
			Name: child.Info.Name(), Href: href, Download: download, Size: size,
			ModTime: child.Info.ModTime().Format("02.01.2006 15:04"), IsDir: child.Info.IsDir(),
			CanModify: !davProtectedResource(child), Virtual: child.Virtual,
		})
	}
	free := ""
	if resource.Full != "" {
		free = mobileText(lang, "Свободно: ", "Free: ", "Libre : ", "Frei: ") + freeSpaceText(resource.Full)
	}
	view := davBrowserView{
		Version:     version,
		Title:       mobileText(lang, "Файлы WebDAV", "WebDAV files", "Fichiers WebDAV", "WebDAV-Dateien"),
		Subtitle:    mobileText(lang, "Полноценный режим управления: загружайте, скачивайте, создавайте папки, переименовывайте, перемещайте, копируйте и удаляйте файлы.", "Full management mode: upload, download, create folders, rename, move, copy and delete files.", "Mode de gestion complet : envoi, téléchargement, création de dossiers, renommage, déplacement, copie et suppression.", "Vollständige Verwaltung: Dateien hoch- und herunterladen, Ordner erstellen, umbenennen, verschieben, kopieren und löschen."),
		CurrentHref: davHref(resource.Virtual, true), CurrentPath: davDisplayPath(resource.Virtual), FreeSpace: free,
		CanWriteHere: resource.Info.IsDir() && !resource.Root,
		Entries:      entries, Crumbs: davCrumbs(resource),
		Upload:         mobileText(lang, "Загрузить файлы", "Upload files", "Envoyer des fichiers", "Dateien hochladen"),
		CreateFolder:   mobileText(lang, "Создать папку", "Create folder", "Créer un dossier", "Ordner erstellen"),
		Refresh:        mobileText(lang, "Обновить", "Refresh", "Actualiser", "Aktualisieren"),
		Download:       mobileText(lang, "Скачать", "Download", "Télécharger", "Herunterladen"),
		Rename:         mobileText(lang, "Переименовать", "Rename", "Renommer", "Umbenennen"),
		Move:           mobileText(lang, "Переместить", "Move", "Déplacer", "Verschieben"),
		Copy:           mobileText(lang, "Копировать", "Copy", "Copier", "Kopieren"),
		Delete:         mobileText(lang, "Удалить", "Delete", "Supprimer", "Löschen"),
		NewName:        mobileText(lang, "Новое имя", "New name", "Nouveau nom", "Neuer Name"),
		FolderEmpty:    mobileText(lang, "Папка пуста", "Folder is empty", "Le dossier est vide", "Ordner ist leer"),
		FullAccess:     mobileText(lang, "Полный доступ", "Full access", "Accès complet", "Vollzugriff"),
		UploadHint:     mobileText(lang, "Можно выбрать один файл или сразу несколько. Передача идёт напрямую в текущую папку без использования /tmp.", "Select one or multiple files. Data is streamed directly into the current folder without using /tmp.", "Sélectionnez un ou plusieurs fichiers. Les données sont écrites directement dans le dossier courant sans utiliser /tmp.", "Eine oder mehrere Dateien auswählen. Die Daten werden direkt in den aktuellen Ordner geschrieben, ohne /tmp zu verwenden."),
		Progress:       mobileText(lang, "Передача", "Transfer", "Transfert", "Übertragung"),
		CurrentFile:    mobileText(lang, "Текущий файл", "Current file", "Fichier actuel", "Aktuelle Datei"),
		Overall:        mobileText(lang, "Общий прогресс", "Overall progress", "Progression totale", "Gesamtfortschritt"),
		Done:           mobileText(lang, "Передано", "Transferred", "Transféré", "Übertragen"),
		Failed:         mobileText(lang, "Не удалось", "Failed", "Échec", "Fehlgeschlagen"),
		PromptFolder:   mobileText(lang, "Название новой папки", "New folder name", "Nom du nouveau dossier", "Name des neuen Ordners"),
		PromptMove:     mobileText(lang, "Путь назначения внутри WebDAV, например /internal/Books/книга.pdf", "Destination inside WebDAV, for example /internal/Books/book.pdf", "Destination dans WebDAV, par exemple /internal/Books/livre.pdf", "Ziel innerhalb von WebDAV, z. B. /internal/Books/buch.pdf"),
		PromptCopy:     mobileText(lang, "Куда скопировать? Укажите путь внутри WebDAV", "Where to copy? Enter a path inside WebDAV", "Où copier ? Indiquez un chemin dans WebDAV", "Wohin kopieren? Pfad innerhalb von WebDAV angeben"),
		ConfirmDelete:  mobileText(lang, "Удалить без возможности восстановления?", "Delete permanently?", "Supprimer définitivement ?", "Endgültig löschen?"),
		ConfirmReplace: mobileText(lang, "Объект с таким именем уже существует. Заменить его?", "An item with this name already exists. Replace it?", "Un élément portant ce nom existe déjà. Le remplacer ?", "Ein Objekt mit diesem Namen existiert bereits. Ersetzen?"),
		NameUnchanged:  mobileText(lang, "Имя не изменено", "Name is unchanged", "Le nom n’a pas changé", "Name wurde nicht geändert"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := davBrowserPage.Execute(w, view); err != nil {
		appendLog(runtimeDirPath, "WebDAV browser template: "+err.Error())
	}
}

func davAttachmentName(name string) string {
	name = filepath.Base(name)
	return "attachment; filename*=UTF-8''" + url.PathEscape(name)
}

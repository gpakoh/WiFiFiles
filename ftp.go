package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FTPServer struct {
	app    *App
	appDir string
	port   int
	ln     *net.TCPListener
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewFTPServer(app *App, appDir string, port int) *FTPServer {
	return &FTPServer{app: app, appDir: appDir, port: port, stopCh: make(chan struct{})}
}

func (s *FTPServer) Start() error {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *FTPServer) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (s *FTPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.AcceptTCP()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				appendLog(s.appDir, "ftp accept: "+err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		_ = conn.SetKeepAlive(true)
		_ = conn.SetKeepAlivePeriod(60 * time.Second)
		s.wg.Add(1)
		go func(c *net.TCPConn) {
			defer s.wg.Done()
			defer c.Close()
			(&ftpSession{server: s, conn: c, rw: bufio.NewReadWriter(bufio.NewReaderSize(c, 16*1024), bufio.NewWriterSize(c, 16*1024)), cwd: "/"}).run()
		}(conn)
	}
}

type ftpSession struct {
	server     *FTPServer
	conn       *net.TCPConn
	rw         *bufio.ReadWriter
	username   string
	authed     bool
	cwd        string
	pasv       *net.TCPListener
	renameFrom string
	rest       int64
}

func (s *ftpSession) run() {
	s.reply(220, "WiFiFiles FTP %s ready", version)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(strings.TrimSpace(cmd))
		arg = strings.TrimSpace(arg)
		if cmd == "QUIT" {
			s.reply(221, "Goodbye")
			return
		}
		if !s.authed && cmd != "USER" && cmd != "PASS" && cmd != "SYST" && cmd != "FEAT" && cmd != "OPTS" && cmd != "NOOP" && cmd != "CLNT" && cmd != "AUTH" {
			s.reply(530, "Please login first")
			continue
		}
		if !s.handle(cmd, arg) {
			return
		}
	}
}

func (s *ftpSession) handle(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.username = arg
		s.authed = false
		s.reply(331, "Password required")
	case "PASS":
		if s.server.app.checkCredentials(s.username, arg) {
			s.authed = true
			s.reply(230, "Login successful")
		} else {
			time.Sleep(350 * time.Millisecond)
			s.reply(530, "Invalid login or password")
		}
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		s.multiline(211, []string{"Features:", " UTF8", " EPSV", " PASV", " SIZE", " MDTM", " REST STREAM", " MLST type*;size*;modify*;", " MLSD", "End"})
	case "OPTS":
		if strings.EqualFold(arg, "UTF8 ON") {
			s.reply(200, "UTF8 enabled")
		} else {
			s.reply(200, "OK")
		}
	case "CLNT", "NOOP":
		s.reply(200, "OK")
	case "AUTH":
		s.reply(502, "TLS not supported; use a trusted local network only")
	case "PBSZ", "PROT":
		s.reply(502, "Command not supported")
	case "TYPE":
		s.reply(200, "Type set")
	case "MODE":
		if strings.EqualFold(arg, "S") {
			s.reply(200, "Stream mode")
		} else {
			s.reply(504, "Only stream mode is supported")
		}
	case "STRU":
		if strings.EqualFold(arg, "F") {
			s.reply(200, "File structure")
		} else {
			s.reply(504, "Only file structure is supported")
		}
	case "PWD", "XPWD":
		s.reply(257, "%q is current directory", s.cwd)
	case "CWD", "XCWD":
		s.changeDir(arg)
	case "CDUP":
		s.changeDir("..")
	case "PASV":
		s.enterPassive(false)
	case "EPSV":
		s.enterPassive(true)
	case "PORT", "EPRT":
		s.reply(502, "Active FTP not supported; use passive mode")
	case "LIST":
		s.sendList(arg, false, false)
	case "NLST":
		s.sendList(arg, true, false)
	case "MLSD":
		s.sendList(arg, false, true)
	case "MLST":
		s.sendMLST(arg)
	case "RETR":
		s.retrieve(arg)
	case "STOR":
		s.store(arg, false)
	case "APPE":
		s.store(arg, true)
	case "REST":
		n, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || n < 0 {
			s.reply(501, "Invalid position")
		} else {
			s.rest = n
			s.reply(350, "Position accepted")
		}
	case "SIZE":
		s.size(arg)
	case "MDTM":
		s.mdtm(arg)
	case "DELE":
		s.deleteFile(arg)
	case "MKD", "XMKD":
		s.makeDir(arg)
	case "RMD", "XRMD":
		s.removeDir(arg)
	case "RNFR":
		s.renameFromCmd(arg)
	case "RNTO":
		s.renameToCmd(arg)
	case "STAT":
		if arg == "" {
			s.reply(211, "WiFiFiles FTP работает; cwd=%s", s.cwd)
		} else {
			s.reply(502, "STAT для пути не поддерживается")
		}
	case "ABOR":
		s.closePassive()
		s.reply(226, "Transfer aborted")
	case "SITE", "ALLO", "LANG":
		s.reply(200, "OK")
	default:
		s.reply(502, "Command %s not supported", cmd)
	}
	return true
}

func (s *ftpSession) reply(code int, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(s.rw, "%d %s\r\n", code, fmt.Sprintf(format, args...))
	_ = s.rw.Flush()
}

func (s *ftpSession) multiline(code int, lines []string) {
	if len(lines) == 0 {
		s.reply(code, "")
		return
	}
	_, _ = fmt.Fprintf(s.rw, "%d-%s\r\n", code, lines[0])
	for _, line := range lines[1 : len(lines)-1] {
		_, _ = fmt.Fprintf(s.rw, "%s\r\n", line)
	}
	_, _ = fmt.Fprintf(s.rw, "%d %s\r\n", code, lines[len(lines)-1])
	_ = s.rw.Flush()
}

func (s *ftpSession) virtualPath(arg string) string {
	arg = strings.TrimSpace(strings.ReplaceAll(arg, "\\", "/"))
	if arg == "" {
		return s.cwd
	}
	if strings.HasPrefix(arg, "/") {
		return pathpkg.Clean(arg)
	}
	return pathpkg.Clean(pathpkg.Join(s.cwd, arg))
}

func (s *ftpSession) resolve(arg string, allowRoot bool) (string, string, error) {
	v := s.virtualPath(arg)
	if v == "/" || v == "." {
		if allowRoot {
			return "", "/", nil
		}
		return "", "", errors.New("root is protected")
	}
	clean := strings.TrimPrefix(v, "/")
	full, virtual, err := s.server.app.resolvePath(clean, allowRoot)
	if err != nil {
		return "", "", err
	}
	return full, "/" + virtual, nil
}

func (s *ftpSession) changeDir(arg string) {
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if virtual == "/" {
		s.cwd = "/"
		s.reply(250, "Directory changed")
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		s.reply(550, "Directory not found")
		return
	}
	s.cwd = virtual
	s.reply(250, "Directory changed")
}

func (s *ftpSession) enterPassive(epsv bool) {
	s.closePassive()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		s.reply(425, "Cannot open passive port")
		return
	}
	s.pasv = ln
	port := ln.Addr().(*net.TCPAddr).Port
	if epsv {
		s.reply(229, "Entering Extended Passive Mode (|||%d|)", port)
		return
	}
	ip := s.conn.LocalAddr().(*net.TCPAddr).IP.To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		ips := localIPv4s()
		if len(ips) > 0 {
			ip = net.ParseIP(ips[0]).To4()
		}
	}
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	s.reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], port/256, port%256)
}

func (s *ftpSession) closePassive() {
	if s.pasv != nil {
		_ = s.pasv.Close()
		s.pasv = nil
	}
}

func (s *ftpSession) acceptData() (net.Conn, error) {
	if s.pasv == nil {
		return nil, errors.New("passive mode not enabled")
	}
	ln := s.pasv
	s.pasv = nil
	_ = ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	return conn, nil
}

func stripListOptions(arg string) string {
	fields := strings.Fields(arg)
	for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		fields = fields[1:]
	}
	return strings.Join(fields, " ")
}

type ftpListItem struct {
	name string
	info os.FileInfo
}

func (s *ftpSession) listItems(arg string) ([]ftpListItem, error) {
	arg = stripListOptions(arg)
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		return nil, err
	}
	if virtual == "/" {
		var out []ftpListItem
		for _, name := range []string{"internal", "sd"} {
			if !s.server.app.enabledRoot(name) {
				continue
			}
			st, err := os.Stat(s.server.app.roots[name])
			if err == nil && st.IsDir() {
				out = append(out, ftpListItem{name: name, info: st})
			}
		}
		return out, nil
	}
	st, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []ftpListItem{{name: filepath.Base(full), info: st}}, nil
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := make([]ftpListItem, 0, len(entries))
	parent := strings.TrimPrefix(virtual, "/")
	for _, de := range entries {
		if isHiddenSystemPath(parent, de.Name()) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, ftpListItem{name: de.Name(), info: info})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].info.IsDir() != out[j].info.IsDir() {
			return out[i].info.IsDir()
		}
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	return out, nil
}

func (s *ftpSession) sendList(arg string, namesOnly, machine bool) {
	items, err := s.listItems(arg)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	data, err := s.acceptData()
	if err != nil {
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Opening data connection")
	bw := bufio.NewWriterSize(data, 16*1024)
	for _, item := range items {
		if namesOnly {
			_, _ = fmt.Fprintf(bw, "%s\r\n", item.name)
		} else if machine {
			typeName := "file"
			if item.info.IsDir() {
				typeName = "dir"
			}
			_, _ = fmt.Fprintf(bw, "type=%s;size=%d;modify=%s; %s\r\n", typeName, item.info.Size(), item.info.ModTime().UTC().Format("20060102150405"), item.name)
		} else {
			mode := item.info.Mode().String()
			_, _ = fmt.Fprintf(bw, "%s 1 pocketbook pocketbook %12d %s %s\r\n", mode, item.info.Size(), item.info.ModTime().Format("Jan _2 15:04"), item.name)
		}
	}
	_ = bw.Flush()
	_ = data.Close()
	s.reply(226, "Transfer complete")
}

func (s *ftpSession) sendMLST(arg string) {
	full, virtual, err := s.resolve(arg, true)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if virtual == "/" {
		s.multiline(250, []string{"Listing", " type=dir;size=0;modify=" + time.Now().UTC().Format("20060102150405") + "; /", "End"})
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		s.reply(550, "Not found")
		return
	}
	typeName := "file"
	if st.IsDir() {
		typeName = "dir"
	}
	s.multiline(250, []string{"Listing", fmt.Sprintf(" type=%s;size=%d;modify=%s; %s", typeName, st.Size(), st.ModTime().UTC().Format("20060102150405"), pathpkg.Base(virtual)), "End"})
}

func (s *ftpSession) retrieve(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	f, err := os.Open(full)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		s.reply(550, "Not a file")
		return
	}
	if s.rest > 0 {
		_, _ = f.Seek(s.rest, io.SeekStart)
		s.rest = 0
	}
	data, err := s.acceptData()
	if err != nil {
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Opening data connection (%d bytes)", st.Size())
	_, copyErr := io.Copy(data, f)
	_ = data.Close()
	if copyErr != nil {
		s.reply(426, "Transfer aborted: %s", copyErr.Error())
		return
	}
	s.reply(226, "Transfer complete")
}

func (s *ftpSession) store(arg string, appendMode bool) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	resumeOffset := s.rest
	s.rest = 0

	// A regular STOR is written to a temporary file and renamed only after a
	// successful fsync. APPE and REST keep their standard in-place semantics.
	atomicWrite := !appendMode && resumeOffset == 0
	writePath := full
	var tmpPath string
	if atomicWrite {
		tmp, createErr := os.CreateTemp(filepath.Dir(full), ".wififiles-ftp-*.part")
		if createErr != nil {
			s.reply(550, "%s", createErr.Error())
			return
		}
		writePath = tmp.Name()
		tmpPath = writePath
		chmodBestEffort(tmpPath, 0644)
		_ = tmp.Close()
		defer os.Remove(tmpPath)
	}

	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else if resumeOffset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(writePath, flags, 0644)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if resumeOffset > 0 {
		if _, err := f.Seek(resumeOffset, io.SeekStart); err != nil {
			_ = f.Close()
			s.reply(550, "%s", err.Error())
			return
		}
	}
	data, err := s.acceptData()
	if err != nil {
		_ = f.Close()
		s.reply(425, "%s", err.Error())
		return
	}
	s.reply(150, "Opening data connection")
	_, copyErr := io.Copy(f, data)
	_ = data.Close()
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		s.reply(426, "Transfer aborted: %s", copyErr.Error())
		return
	}
	if syncErr != nil {
		s.reply(451, "Write error: %s", syncErr.Error())
		return
	}
	if closeErr != nil {
		s.reply(451, "File close error: %s", closeErr.Error())
		return
	}
	if atomicWrite {
		if err := os.Rename(tmpPath, full); err != nil {
			s.reply(451, "Write finalization error: %s", err.Error())
			return
		}
	}
	s.server.app.scheduleLibraryRefresh(full)
	s.reply(226, "File saved")
}

func (s *ftpSession) size(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		s.reply(550, "File not found")
		return
	}
	s.reply(213, "%d", st.Size())
}

func (s *ftpSession) mdtm(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		s.reply(550, "Not found")
		return
	}
	s.reply(213, "%s", st.ModTime().UTC().Format("20060102150405"))
}

func (s *ftpSession) deleteFile(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		s.reply(550, "File not found")
		return
	}
	if err := os.Remove(full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "File deleted")
}

func (s *ftpSession) makeDir(arg string) {
	full, virtual, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if err := os.Mkdir(full, 0755); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(257, "%q created", virtual)
}

func (s *ftpSession) removeDir(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		s.reply(550, "Directory not found")
		return
	}
	if err := os.Remove(full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "Directory deleted")
}

func (s *ftpSession) renameFromCmd(arg string) {
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	if _, err := os.Stat(full); err != nil {
		s.reply(550, "Not found")
		return
	}
	s.renameFrom = full
	s.reply(350, "Ready for new name")
}

func (s *ftpSession) renameToCmd(arg string) {
	if s.renameFrom == "" {
		s.reply(503, "RNFR required first")
		return
	}
	full, _, err := s.resolve(arg, false)
	if err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	from := s.renameFrom
	s.renameFrom = ""
	if err := os.Rename(from, full); err != nil {
		s.reply(550, "%s", err.Error())
		return
	}
	s.reply(250, "Renamed")
}

func localIPv4s() []string {
	ifaces, _ := net.Interfaces()
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

func pathStatus(p string) string {
	st, err := os.Stat(p)
	if err != nil {
		return "unavailable (" + err.Error() + ")"
	}
	if !st.IsDir() {
		return "not a directory"
	}
	f, err := os.CreateTemp(p, ".pbwf-test-")
	if err != nil {
		return "read-only (" + err.Error() + ")"
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return "read-write"
}

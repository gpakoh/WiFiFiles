package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type ftpClient struct {
	conn net.Conn
	rw   *bufio.Reader
}

func ftpTestServer(t *testing.T) (*App, int) {
	t.Helper()
	root := t.TempDir()
	internal := filepath.Join(root, "internal")
	sd := filepath.Join(root, "sd")
	if err := os.MkdirAll(internal, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sd, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(internal, "Books"), 0755); err != nil {
		t.Fatal(err)
	}
	app, err := newApp(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	app.roots["internal"] = internal
	app.roots["sd"] = sd

	probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	srv := NewFTPServer(app, filepath.Join(root, "runtime"), port)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return app, port
}

func ftpConnect(t *testing.T, port int) *ftpClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &ftpClient{conn: conn, rw: bufio.NewReader(conn)}
	if line := c.reply(); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("banner: %q", line)
	}
	return c
}

func (c *ftpClient) cmd(command string) string {
	if _, err := fmt.Fprintf(c.conn, "%s\r\n", command); err != nil {
		return "ERR " + err.Error()
	}
	return c.reply()
}

func (c *ftpClient) reply() string {
	line, err := c.rw.ReadString('\n')
	if err != nil {
		return "ERR " + err.Error()
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *ftpClient) login(t *testing.T) {
	t.Helper()
	if got := c.cmd("USER pocketbook"); !strings.HasPrefix(got, "331 ") {
		t.Fatalf("USER: %q", got)
	}
	if got := c.cmd("PASS 650wifi"); !strings.HasPrefix(got, "230 ") {
		t.Fatalf("PASS: %q", got)
	}
}

func (c *ftpClient) passive(t *testing.T) net.Conn {
	t.Helper()
	reply := c.cmd("PASV")
	if !strings.HasPrefix(reply, "227 ") {
		t.Fatalf("PASV: %q", reply)
	}
	start := strings.Index(reply, "(")
	end := strings.Index(reply, ")")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("bad PASV reply: %q", reply)
	}
	var h1, h2, h3, h4, p1, p2 int
	if _, err := fmt.Sscanf(reply[start+1:end], "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2); err != nil {
		t.Fatalf("parse PASV %q: %v", reply, err)
	}
	addr := fmt.Sprintf("%d.%d.%d.%d:%d", h1, h2, h3, h4, p1*256+p2)
	conn, err := net.DialTimeout("tcp4", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("data connect %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func ftpDrain(t *testing.T, conn net.Conn) string {
	t.Helper()
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("drain data: %v", err)
	}
	_ = conn.Close()
	return string(data)
}

func TestFTPLoginAndBadCredentials(t *testing.T) {
	_, port := ftpTestServer(t)
	c := ftpConnect(t, port)

	if got := c.cmd("LIST"); !strings.HasPrefix(got, "530 ") {
		t.Fatalf("unauthenticated LIST: %q", got)
	}
	if got := c.cmd("USER pocketbook"); !strings.HasPrefix(got, "331 ") {
		t.Fatalf("USER: %q", got)
	}
	if got := c.cmd("PASS wrongpass"); !strings.HasPrefix(got, "530 ") {
		t.Fatalf("bad PASS: %q", got)
	}
	if got := c.cmd("USER pocketbook"); !strings.HasPrefix(got, "331 ") {
		t.Fatalf("USER retry: %q", got)
	}
	if got := c.cmd("PASS 650wifi"); !strings.HasPrefix(got, "230 ") {
		t.Fatalf("good PASS: %q", got)
	}
	if got := c.cmd("SYST"); !strings.HasPrefix(got, "215 ") {
		t.Fatalf("SYST: %q", got)
	}
	if got := c.cmd("QUIT"); !strings.HasPrefix(got, "221 ") {
		t.Fatalf("QUIT: %q", got)
	}
}

func TestFTPRootListingShowsOnlyEnabledVolumes(t *testing.T) {
	app, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	// Both volumes enabled.
	data := c.passive(t)
	got := c.cmd("LIST")
	if !strings.HasPrefix(got, "150 ") {
		t.Fatalf("LIST: %q", got)
	}
	listing := ftpDrain(t, data)
	if done := c.reply(); !strings.HasPrefix(done, "226 ") {
		t.Fatalf("LIST done: %q", done)
	}
	if !strings.Contains(listing, "internal") || !strings.Contains(listing, "sd") {
		t.Fatalf("root LIST should show both volumes:\n%s", listing)
	}

	// Disable SD, root listing must show only internal.
	app.cfgMu.Lock()
	cfg := app.cfg
	cfg.SDEnabled = false
	app.cfg = cfg
	app.cfgMu.Unlock()
	data = c.passive(t)
	if got := c.cmd("LIST"); !strings.HasPrefix(got, "150 ") {
		t.Fatalf("LIST after SD disabled: %q", got)
	}
	listing = ftpDrain(t, data)
	_ = c.reply()
	if strings.Contains(listing, "sd") {
		t.Fatalf("root LIST should hide disabled sd volume:\n%s", listing)
	}
	if !strings.Contains(listing, "internal") {
		t.Fatalf("root LIST should still show internal:\n%s", listing)
	}
}

func TestFTPStoreRetrieveSizeMdtm(t *testing.T) {
	app, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	if got := c.cmd("CWD internal/Books"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("CWD: %q", got)
	}
	if got := c.cmd("MKD test"); !strings.HasPrefix(got, "257 ") {
		t.Fatalf("MKD: %q", got)
	}
	if got := c.cmd("CWD test"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("CWD into new dir: %q", got)
	}
	if got := c.cmd("PWD"); !strings.Contains(got, "/internal/Books/test") {
		t.Fatalf("PWD: %q", got)
	}

	data := c.passive(t)
	if got := c.cmd("STOR hello.txt"); !strings.HasPrefix(got, "150 ") {
		t.Fatalf("STOR: %q", got)
	}
	if _, err := data.Write([]byte("hello ftp")); err != nil {
		t.Fatal(err)
	}
	_ = data.Close()
	if done := c.reply(); !strings.HasPrefix(done, "226 ") {
		t.Fatalf("STOR done: %q", done)
	}

	full := filepath.Join(app.roots["internal"], "Books", "test", "hello.txt")
	content, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello ftp" {
		t.Fatalf("stored content=%q", content)
	}
	parts, _ := filepath.Glob(filepath.Join(filepath.Dir(full), ".wififiles-ftp-*.part"))
	if len(parts) != 0 {
		t.Fatalf("atomic STOR left .part files: %v", parts)
	}

	if got := c.cmd("SIZE hello.txt"); got != "213 9" {
		t.Fatalf("SIZE: %q", got)
	}
	if got := c.cmd("MDTM hello.txt"); !strings.HasPrefix(got, "213 ") {
		t.Fatalf("MDTM: %q", got)
	}

	data = c.passive(t)
	if got := c.cmd("RETR hello.txt"); !strings.HasPrefix(got, "150 ") {
		t.Fatalf("RETR: %q", got)
	}
	if got := ftpDrain(t, data); got != "hello ftp" {
		t.Fatalf("RETR content=%q", got)
	}
	if done := c.reply(); !strings.HasPrefix(done, "226 ") {
		t.Fatalf("RETR done: %q", done)
	}

	if got := c.cmd("DELE hello.txt"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("DELE: %q", got)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("DELE left file, err=%v", err)
	}
}

func TestFTPRenameAndRemoveDir(t *testing.T) {
	app, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	if got := c.cmd("CWD internal/Books"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("CWD: %q", got)
	}
	if got := c.cmd("MKD alpha"); !strings.HasPrefix(got, "257 ") {
		t.Fatalf("MKD alpha: %q", got)
	}
	if got := c.cmd("RNFR alpha"); !strings.HasPrefix(got, "350 ") {
		t.Fatalf("RNFR: %q", got)
	}
	if got := c.cmd("RNTO beta"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RNTO: %q", got)
	}
	if _, err := os.Stat(filepath.Join(app.roots["internal"], "Books", "beta")); err != nil {
		t.Fatalf("renamed dir missing: %v", err)
	}
	if got := c.cmd("RMD beta"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RMD: %q", got)
	}
	if _, err := os.Stat(filepath.Join(app.roots["internal"], "Books", "beta")); !os.IsNotExist(err) {
		t.Fatalf("RMD left dir, err=%v", err)
	}
}

func TestFTPProtectsSystemPaths(t *testing.T) {
	_, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	for _, cmd := range []string{"LIST system", "CWD system", "RETR system/WiFiFiles.log", "DELE system/WiFiFiles.log"} {
		if got := c.cmd(cmd); !strings.HasPrefix(got, "550 ") {
			t.Fatalf("%q should be rejected with 550, got %q", cmd, got)
		}
	}
	if got := c.cmd("RETR internal"); !strings.HasPrefix(got, "550 ") {
		t.Fatalf("RETR of volume root should be rejected: %q", got)
	}
	if got := c.cmd("PORT 127,0,0,1,1,1"); !strings.HasPrefix(got, "502 ") {
		t.Fatalf("active mode should be rejected: %q", got)
	}
}

func TestFTPMLSDListing(t *testing.T) {
	_, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	data := c.passive(t)
	if got := c.cmd("MLSD"); !strings.HasPrefix(got, "150 ") {
		t.Fatalf("MLSD: %q", got)
	}
	listing := ftpDrain(t, data)
	_ = c.reply()
	if !strings.Contains(listing, "type=dir") || !strings.Contains(listing, " internal") {
		t.Fatalf("MLSD root should show typed entries:\n%s", listing)
	}
}

func TestFTPFeaturesAndMLST(t *testing.T) {
	app, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	featStart := c.cmd("FEAT")
	if !strings.HasPrefix(featStart, "211-") {
		t.Fatalf("FEAT start: %q", featStart)
	}
	var feat strings.Builder
	feat.WriteString(featStart + "\n")
	for {
		line := c.reply()
		feat.WriteString(line + "\n")
		if strings.HasPrefix(line, "211 ") {
			break
		}
	}
	if !strings.Contains(feat.String(), "MLSD") || !strings.Contains(feat.String(), "EPSV") {
		t.Fatalf("FEAT body:\n%s", feat.String())
	}

	if got := c.cmd("MLST"); !strings.HasPrefix(got, "250-") {
		t.Fatalf("MLST root: %q", got)
	}
	if got := c.reply(); !strings.Contains(got, "type=dir") {
		t.Fatalf("MLST root body: %q", got)
	}
	if got := c.reply(); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MLST root end: %q", got)
	}

	full := filepath.Join(app.roots["internal"], "Books", "mlst.txt")
	if err := os.WriteFile(full, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := c.cmd("MLST internal/Books/mlst.txt"); !strings.HasPrefix(got, "250-") {
		t.Fatalf("MLST file: %q", got)
	}
	body := c.reply()
	if !strings.Contains(body, "type=file") || !strings.Contains(body, "size=4") {
		t.Fatalf("MLST file body: %q", body)
	}
	_ = c.reply()
}

func TestFTPResumeRetrieve(t *testing.T) {
	app, port := ftpTestServer(t)
	c := ftpConnect(t, port)
	c.login(t)

	full := filepath.Join(app.roots["internal"], "Books", "resume.txt")
	if err := os.WriteFile(full, []byte("0123456789"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := c.cmd("CWD internal/Books"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("CWD: %q", got)
	}
	if got := c.cmd("REST 5"); !strings.HasPrefix(got, "350 ") {
		t.Fatalf("REST: %q", got)
	}
	data := c.passive(t)
	if got := c.cmd("RETR resume.txt"); !strings.HasPrefix(got, "150 ") {
		t.Fatalf("RETR after REST: %q", got)
	}
	if got := ftpDrain(t, data); got != "56789" {
		t.Fatalf("REST+RETR content=%q", got)
	}
	_ = c.reply()
}

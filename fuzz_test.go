package main

import (
	"strings"
	"testing"
)

func FuzzParseDigestHeader(f *testing.F) {
	f.Add("Digest username=\"admin\", realm=\"WiFiFiles\", nonce=\"abc123\", uri=\"/\", response=\"def456\"")
	f.Add("Digest username=admin")
	f.Add("Digest ")
	f.Add("")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("Digest username=\"es\\\"caped\", realm=\"test\"")
	f.Add("Digest a=b, c=d, e=f")
	f.Add("Digest " + strings.Repeat("x=", 1000))
	f.Fuzz(func(t *testing.T, input string) {
		result := parseDigestHeader(input)
		_ = result
	})
}

func FuzzParseNativeApply(f *testing.F) {
	f.Add([]byte("username=admin\npassword=secret\nport=8080\n"))
	f.Add([]byte("=value\nkey=\n"))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("key with spaces=value with spaces\n"))
	f.Add([]byte(strings.Repeat("k=v\n", 1000)))
	f.Add([]byte{0x00, 0xff, 0xfe})
	f.Fuzz(func(t *testing.T, input []byte) {
		result := parseNativeApply(input)
		_ = result
	})
}

func FuzzFTPCommandParsing(f *testing.F) {
	f.Add("USER admin\r\n")
	f.Add("PASS secret\r\n")
	f.Add("LIST /\r\n")
	f.Add("RETR /path/to/file.txt\r\n")
	f.Add("STOR /path/to/file.txt\r\n")
	f.Add("CWD /some/dir\r\n")
	f.Add("PWD\r\n")
	f.Add("QUIT\r\n")
	f.Add("MKD /new/dir\r\n")
	f.Add("DELE /file/to/delete\r\n")
	f.Add("RNFR /old\r\nRNTO /new\r\n")
	f.Add("SIZE /file\r\n")
	f.Add("MDTM /file\r\n")
	f.Add("NOOP\r\n")
	f.Add("FEAT\r\n")
	f.Add("SYST\r\n")
	f.Add("OPTS UTF8 ON\r\n")
	f.Add("PASV\r\n")
	f.Add("\r\n")
	f.Add(strings.Repeat("A", 10000) + "\r\n")
	f.Add("\x00\x01\x02\r\n")
	f.Fuzz(func(t *testing.T, line string) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(strings.TrimSpace(cmd))
		arg = strings.TrimSpace(arg)
		_ = cmd
		_ = arg
	})
}

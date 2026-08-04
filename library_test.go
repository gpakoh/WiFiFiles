package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBookFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/mnt/ext1/Books/novel.fb2", true},
		{"/mnt/ext1/Books/novel.fb2.zip", true},
		{"/mnt/ext1/Books/novel.epub", true},
		{"/mnt/ext1/Books/novel.txt", true},
		{"/mnt/ext1/Books/novel.FB2", true},
		{"/mnt/ext1/Books/notes.md", false},
	}
	for _, c := range cases {
		if got := isBookFile(c.path); got != c.want {
			t.Errorf("isBookFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestLibraryScanTarget(t *testing.T) {
	cases := []struct {
		path    string
		wantDir string
		wantOK  bool
	}{
		{"/mnt/ext1/Books/novel.fb2", "/mnt/ext1/Books", true},
		{"/mnt/ext2/Fiction/novel.epub", "/mnt/ext2/Fiction", true},
		{"/mnt/ext1/system/secret.fb2", "", false},
		{"/mnt/ext1/applications/app.fb2", "", false},
		{"/mnt/ext1/Books/notes.md", "", false},
		{"/mnt/ext1/Books", "", false},
		{"/mnt/ext1", "", false},
		{"/var/tmp/novel.fb2", "", false},
		{"/mnt/ext1/.wififiles/stash.fb2", "", false},
		{"/mnt/ext1/lost.dir/novel.fb2", "", false},
		{"/mnt/ext1/Books/Deep/Nested/novel.fb2", "/mnt/ext1/Books/Deep/Nested", true},
	}
	for _, c := range cases {
		dir, ok := libraryScanTarget(c.path)
		if dir != c.wantDir || ok != c.wantOK {
			t.Errorf("libraryScanTarget(%q) = (%q, %v), want (%q, %v)", c.path, dir, ok, c.wantDir, c.wantOK)
		}
	}
}

func TestFindPocketBookExecutable(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "scanner.app")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "readme.txt")
	if err := os.WriteFile(plain, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := findPocketBookExecutable("", executable, plain); got != executable {
		t.Fatalf("findPocketBookExecutable = %q, want %q", got, executable)
	}
	if got := findPocketBookExecutable(plain); got != "" {
		t.Fatalf("non-executable accepted: %q", got)
	}
	if got := findPocketBookExecutable("definitely-not-a-real-cmd-xyz"); got != "" {
		t.Fatalf("unknown bare name resolved to %q", got)
	}
	if got := findPocketBookExecutable(filepath.Join(root, "missing.app")); got != "" {
		t.Fatalf("missing path resolved to %q", got)
	}
}

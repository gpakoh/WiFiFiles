package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

func TestDAVAttachmentName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"book.pdf", "attachment; filename*=UTF-8''book.pdf"},
		{"/internal/Books/книга.pdf", "attachment; filename*=UTF-8''" + url.PathEscape("книга.pdf")},
		{filepath.Join("dir", "my book.txt"), "attachment; filename*=UTF-8''" + url.PathEscape("my book.txt")},
	}
	for _, tc := range cases {
		if got := davAttachmentName(tc.in); got != tc.want {
			t.Errorf("davAttachmentName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDAVDisplayPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/", "WiFiFiles"},
		{"/internal", "/INTERNAL"},
		{"/internal/Books", "/INTERNAL/Books"},
		{"/sd/Books", "/SDCARD/Books"},
		{"/sd", "/SDCARD"},
	}
	for _, tc := range cases {
		if got := davDisplayPath(tc.in); got != tc.want {
			t.Errorf("davDisplayPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDAVCrumbs(t *testing.T) {
	root := davCrumbs(davResource{Virtual: "/"})
	if len(root) != 1 || root[0].Name != "WiFiFiles" || root[0].Href != "/dav/" {
		t.Fatalf("root crumbs: %+v", root)
	}

	inner := davCrumbs(davResource{Virtual: "/internal/Books"})
	if len(inner) != 3 {
		t.Fatalf("crumbs length: %+v", inner)
	}
	want := []davBrowserCrumb{
		{Name: "WiFiFiles", Href: "/dav/"},
		{Name: "INTERNAL", Href: "/dav/internal/"},
		{Name: "Books", Href: "/dav/internal/Books/"},
	}
	for i := range want {
		if inner[i].Name != want[i].Name || inner[i].Href != want[i].Href {
			t.Fatalf("crumb %d = %+v, want %+v", i, inner[i], want[i])
		}
	}

	sd := davCrumbs(davResource{Virtual: "/sd/lost"})
	if sd[1].Name != "SDCARD" || sd[1].Href != "/dav/sd/" {
		t.Fatalf("sd crumb: %+v", sd[1])
	}
}

func TestDAVBrowserRequestDetection(t *testing.T) {
	plain := httptest.NewRequest("GET", "http://pb/dav/internal/Books/file.pdf", nil)
	plain.Header.Set("Accept", "application/xml")
	plain.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19041")
	if davBrowserRequest(plain) {
		t.Fatal("WebDAV client should get raw file, not the browser")
	}

	raw := httptest.NewRequest("GET", "http://pb/dav/internal/Books/file.pdf?raw=1", nil)
	raw.Header.Set("Accept", "text/html")
	if davBrowserRequest(raw) {
		t.Fatal("?raw=1 should force raw download")
	}

	browser := httptest.NewRequest("GET", "http://pb/dav/internal/Books/", nil)
	browser.Header.Set("Accept", "text/html")
	if !davBrowserRequest(browser) {
		t.Fatal("text/html Accept should show the browser")
	}

	ua := httptest.NewRequest("GET", "http://pb/dav/internal/Books/", nil)
	ua.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	if !davBrowserRequest(ua) {
		t.Fatal("Mozilla User-Agent should show the browser")
	}

	_ = http.StatusOK
}

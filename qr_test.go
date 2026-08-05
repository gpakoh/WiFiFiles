package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestQRVersion5L(t *testing.T) {
	rows, err := qrVersion5L("http://192.168.1.25:8080/m/0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 37 {
		t.Fatalf("rows=%d", len(rows))
	}
	for i, row := range rows {
		if len(row) != 37 {
			t.Fatalf("row %d width=%d", i, len(row))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	if got := fmt.Sprintf("%x", sum); got != "9420d971cde397a44af2e2733e80fe0e89adb2b13dcfb27c2a4b4fa915814851" {
		t.Fatalf("unexpected matrix hash: %s", got)
	}
}

func TestQRVersion5LTooLong(t *testing.T) {
	if rows, err := qrVersion5L(strings.Repeat("a", 107)); err == nil {
		t.Fatalf("107-byte payload accepted, rows=%d", len(rows))
	}
	if rows, err := qrVersion5L(strings.Repeat("a", 106)); err != nil {
		t.Fatalf("106-byte payload rejected: %v", err)
	} else if len(rows) != 37 {
		t.Fatalf("106-byte payload rows=%d, want 37", len(rows))
	}
}

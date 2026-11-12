package main

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestSanitizeGmailMessageID(t *testing.T) {
	id := func(n int) string { return "<" + strings.Repeat("a", n-len("<@example.com>")) + "@example.com>" }
	generated := regexp.MustCompile(`^ <[0-9a-f]{32}@imapforward\.invalid>$`)
	for _, tc := range []struct {
		name, field, eol string
		changed          bool
	}{
		{"short", "Message-ID: " + id(40), "\r\n", false},
		{"499 bytes", "Message-ID: " + id(499), "\r\n", false},
		{"500 bytes", "Message-ID: " + id(500), "\r\n", false},
		{"501 bytes", "Message-ID: " + id(501), "\r\n", true},
		{"539 bytes", "Message-ID: " + id(539), "\r\n", true},
		{"557 bytes", "Message-ID: " + id(557), "\r\n", true},
		{"folded short", "Message-ID:\r\n\t" + id(40), "\r\n", false},
		{"folded boundary", "Message-ID:\r\n\t" + id(500), "\r\n", false},
		{"folded long", "Message-ID: " + id(280) + "\r\n\t" + id(280), "\r\n", true},
		{"case insensitive", "mEsSaGe-iD:\t" + id(539), "\r\n", true},
		{"LF", "Message-ID: " + id(539), "\n", true},
		{"no Message-ID", "X-Message-ID: " + id(539), "\r\n", false},
		{"byte count", "Message-ID: <" + strings.Repeat("é", 260) + "@example.com>", "\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "From: sender@example.com" + tc.eol + "X-Folded: original" + tc.eol + "\twhitespace" + tc.eol
			suffix := tc.eol + "Subject: untouched" + tc.eol + "Content-Type: multipart/mixed; boundary=test" + tc.eol + tc.eol +
				"--test\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xffattachment\r\nMessage-ID: " + id(600) + "\r\n--test--\r\n"
			raw := []byte(prefix + tc.field + suffix)
			original := bytes.Clone(raw)
			got, changed, err := sanitizeGmailMessageID(raw)
			if err != nil || changed != tc.changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("mutated caller's message")
			}
			if !changed {
				if !bytes.Equal(got, original) {
					t.Fatal("changed an unaffected message")
				}
				return
			}
			unchangedPrefix := prefix + tc.field[:strings.IndexByte(tc.field, ':')+1]
			if !bytes.HasPrefix(got, []byte(unchangedPrefix)) || !bytes.HasSuffix(got, []byte(suffix)) {
				t.Fatal("changed bytes outside Message-ID value")
			}
			value := got[len(unchangedPrefix) : len(got)-len(suffix)]
			if !generated.Match(value) {
				t.Fatalf("invalid generated ID: %q", value)
			}
			again, changed, err := sanitizeGmailMessageID(got)
			if err != nil || changed || !bytes.Equal(got, again) {
				t.Fatal("sanitization is not idempotent")
			}
		})
	}
}

func TestSanitizeGmailMessageIDUniqueAndDuplicateFields(t *testing.T) {
	raw := []byte("Message-ID: <" + strings.Repeat("a", 520) + "@example.com>\r\nMessage-ID: <" + strings.Repeat("b", 520) + "@example.com>\r\n\r\nbody")
	ids := regexp.MustCompile(`<([0-9a-f]{32})@imapforward\.invalid>`)
	seen := make(map[string]bool)
	for i := 0; i < 2; i++ {
		got, changed, err := sanitizeGmailMessageID(raw)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		matches := ids.FindAll(got, -1)
		if len(matches) != 2 {
			t.Fatal("did not replace both oversized fields")
		}
		for _, id := range matches {
			if seen[string(id)] {
				t.Fatal("reused a generated ID")
			}
			seen[string(id)] = true
		}
	}
}

func TestSanitizeGmailMessageIDWithoutHeaders(t *testing.T) {
	longField := "Message-ID: <" + strings.Repeat("a", 520) + "@example.com>"
	for _, raw := range []string{"", "test", longField, "\r\n" + longField + "\r\n\r\nbody", "\n" + longField + "\n\nbody"} {
		got, changed, err := sanitizeGmailMessageID([]byte(raw))
		if err != nil || changed || string(got) != raw {
			t.Fatal("modified a message without a header section")
		}
	}
}

func TestGmailAPISenderImportsSanitizedMessage(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenHandler(w, r)
			return
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				break
			}
			if part.Header.Get("Content-Type") == "message/rfc822" {
				received, err = io.ReadAll(part)
				if err != nil {
					t.Error(err)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sender := newTestGmailSender(server)
	suffix := "\r\nSubject: original\r\n\r\nbody\x00\xff\r\n"
	raw := []byte("Message-ID: <" + strings.Repeat("a", 520) + "@example.com>" + suffix)
	if err := sender.Send(context.Background(), raw, ""); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^Message-ID: <[0-9a-f]{32}@imapforward\.invalid>`).Match(received) || !bytes.HasSuffix(received, []byte(suffix)) {
		t.Fatal("Gmail import did not receive precisely sanitized raw message")
	}
}

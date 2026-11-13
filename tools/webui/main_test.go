package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name, body string
	typ        byte
	link       string
}

func mk(t *testing.T, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range ents {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestParseLock(t *testing.T) {
	good := "# c\nrepo=o/r\nversion=1.2.3\nsha256=" + strings.Repeat("a", 64) + "\n"
	if _, err := ParseLock(strings.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"short sha":   strings.Replace(good, strings.Repeat("a", 64), "abc", 1),
		"upper sha":   strings.Replace(good, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"bad version": strings.Replace(good, "1.2.3", "1.2", 1),
		"bad repo":    strings.Replace(good, "o/r", "../x", 1),
		"unknown key": good + "x=y\n",
		"dup":         good + "version=1.2.4\n",
		"missing":     "repo=o/r\n",
	} {
		if _, err := ParseLock(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if u := (Lock{Repo: "o/r", Version: "1.2.3"}).TarballURL(""); u != "https://github.com/o/r/releases/download/v1.2.3/clearance-ui-web-1.2.3.tar.gz" {
		t.Error(u)
	}
}

func TestExtractGood(t *testing.T) {
	d := filepath.Join(t.TempDir(), "static")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "index.html"), []byte("placeholder"), 0o644)
	os.WriteFile(filepath.Join(d, "stale.txt"), []byte("x"), 0o644)
	tgz := mk(t, ent{name: "./", typ: tar.TypeDir}, ent{name: "./index.html", body: "<ui>"}, ent{name: "./assets/", typ: tar.TypeDir}, ent{name: "./assets/a-1.js", body: "js"})
	if err := Extract(tgz, d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "index.html")); string(b) != "<ui>" {
		t.Errorf("index: %q", b)
	}
	if _, err := os.Stat(filepath.Join(d, "assets", "a-1.js")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(d, "stale.txt")); err == nil {
		t.Error("stale file kept")
	}
	// no stage directories left beside dest
	if es, _ := os.ReadDir(filepath.Dir(d)); len(es) != 1 {
		t.Errorf("leftovers: %v", es)
	}
}

func TestExtractRefuses(t *testing.T) {
	cases := map[string][]ent{
		"traversal":      {{name: "index.html", body: "x"}, {name: "../evil", body: "x"}},
		"nested ..":      {{name: "index.html", body: "x"}, {name: "a/../../evil", body: "x"}},
		"absolute":       {{name: "index.html", body: "x"}, {name: "/etc/evil", body: "x"}},
		"backslash":      {{name: "index.html", body: "x"}, {name: `a\b`, body: "x"}},
		"symlink":        {{name: "index.html", body: "x"}, {name: "assets", typ: tar.TypeSymlink, link: "/etc"}},
		"hardlink":       {{name: "index.html", body: "x"}, {name: "h", typ: tar.TypeLink, link: "index.html"}},
		"duplicate":      {{name: "index.html", body: "x"}, {name: "index.html", body: "y"}},
		"no index":       {{name: "assets/a.js", body: "x"}},
		"index is dir":   {{name: "index.html", typ: tar.TypeDir}},
		"fifo":           {{name: "index.html", body: "x"}, {name: "p", typ: tar.TypeFifo}},
		"through a link": {{name: "index.html", body: "x"}, {name: "l", typ: tar.TypeSymlink, link: "/tmp"}, {name: "l/evil", body: "x"}},
	}
	for name, ents := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			d := filepath.Join(root, "static")
			os.MkdirAll(d, 0o755)
			os.WriteFile(filepath.Join(d, "index.html"), []byte("placeholder"), 0o644)
			if err := Extract(mk(t, ents...), d); err == nil {
				t.Fatal("accepted")
			}
			// the destination is untouched and nothing escaped
			if b, _ := os.ReadFile(filepath.Join(d, "index.html")); string(b) != "placeholder" {
				t.Errorf("dest changed: %q", b)
			}
			if es, _ := os.ReadDir(root); len(es) != 1 {
				t.Errorf("leftovers: %v", es)
			}
			if _, err := os.Stat(filepath.Join(root, "evil")); err == nil {
				t.Error("escaped the stage")
			}
		})
	}
	if err := Extract([]byte("not gzip"), t.TempDir()+"/s"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestFetchChecksPinNotServer(t *testing.T) {
	body := mk(t, ent{name: "index.html", body: "x"})
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.HasSuffix(r.URL.Path, ".sha256") { // never asked for
			t.Error("fetched the .sha256 asset")
		}
		w.Write(body)
	}))
	defer srv.Close()
	l := Lock{Repo: "o/r", Version: "1.0.0", SHA256: sum(body)}
	cache := t.TempDir()
	if _, err := Fetch(l, srv.URL, cache, true); err != nil || hits != 1 {
		t.Fatalf("fetch: %v hits=%d", err, hits)
	}
	if _, err := Fetch(l, srv.URL, cache, true); err != nil || hits != 1 {
		t.Fatalf("cache miss: %v hits=%d", err, hits)
	}
	// a wrong pin refuses, and caches nothing
	bad := Lock{Repo: "o/r", Version: "1.0.0", SHA256: strings.Repeat("0", 64)}
	c2 := t.TempDir()
	if _, err := Fetch(bad, srv.URL, c2, true); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	if es, _ := os.ReadDir(c2); len(es) != 0 {
		t.Error("cached a refused download")
	}
	// a poisoned cache entry is not trusted
	os.WriteFile(filepath.Join(cache, l.SHA256+".tar.gz"), []byte("poison"), 0o644)
	if b, err := Fetch(l, srv.URL, cache, true); err != nil || sum(b) != l.SHA256 {
		t.Fatalf("poisoned cache used: %v", err)
	}
	// plain http is refused unless the test allows it
	if _, err := Fetch(l, srv.URL, "", false); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("http allowed: %v", err)
	}
	// 404
	nf := httptest.NewServer(http.NotFoundHandler())
	defer nf.Close()
	if _, err := Fetch(l, nf.URL, "", true); err == nil {
		t.Fatal("404 accepted")
	}
}

func TestCommittedLockParses(t *testing.T) {
	f, err := os.Open("../../web-ui.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ParseLock(f); err != nil {
		t.Fatal(err)
	}
}

// The EXDEV fallback (a Docker build's overlayfs directory cannot be renamed) replaces the contents in place.
func TestReplaceContents(t *testing.T) {
	root := t.TempDir()
	d, s := filepath.Join(root, "static"), filepath.Join(root, "stage")
	os.MkdirAll(filepath.Join(d, "old"), 0o755)
	os.WriteFile(filepath.Join(d, "index.html"), []byte("placeholder"), 0o644)
	os.MkdirAll(filepath.Join(s, "assets"), 0o755)
	os.WriteFile(filepath.Join(s, "index.html"), []byte("ui"), 0o644)
	os.WriteFile(filepath.Join(s, "assets", "a.js"), []byte("js"), 0o644)
	if err := replaceContents(s, d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "index.html")); string(b) != "ui" {
		t.Errorf("index: %q", b)
	}
	if _, err := os.Stat(filepath.Join(d, "old")); err == nil {
		t.Error("old entry kept")
	}
	if _, err := os.Stat(filepath.Join(d, "assets", "a.js")); err != nil {
		t.Error(err)
	}
}

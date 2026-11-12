package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.2.0", "v1.1.9", true},
		{"v1.2.0", "v1.2.0", false},
		{"v1.2.0", "v1.3.0", false},
		{"v2.0.0", "v1.99.99", true},
		{"v0.1.0", "dev", true},
		{"v0.1.1", "0.1.0-rc1", true},
		{"garbage", "v1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestLatestTagFollowsRedirectHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/v1.4.2", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tag, err := LatestTag(context.Background(), srv.URL)
	if err != nil || tag != "v1.4.2" {
		t.Fatalf("tag=%q err=%v", tag, err)
	}
	if _, err := LatestTag(context.Background(), srv.URL+"/missing"); err == nil {
		t.Error("expected error when there is no redirect")
	}
}

func TestAssetAndBinaryNames(t *testing.T) {
	if AssetName("windows", "amd64") != "agentruntime_windows_amd64.zip" {
		t.Error(AssetName("windows", "amd64"))
	}
	if AssetName("linux", "arm64") != "agentruntime_linux_arm64.tar.gz" {
		t.Error(AssetName("linux", "arm64"))
	}
	if BinaryName("windows") != "agentruntime.exe" || BinaryName("darwin") != "agentruntime" {
		t.Error("binary names")
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("payload")
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])
	sums := []byte(good + "  agentruntime_linux_amd64.tar.gz\n" +
		strings.Repeat("0", 64) + "  other.tar.gz\n")

	if err := VerifyChecksum(sums, "agentruntime_linux_amd64.tar.gz", data); err != nil {
		t.Errorf("valid checksum rejected: %v", err)
	}
	if err := VerifyChecksum(sums, "other.tar.gz", data); err == nil {
		t.Error("mismatched checksum accepted")
	}
	if err := VerifyChecksum(sums, "missing.tar.gz", data); err == nil {
		t.Error("missing entry accepted")
	}
	if err := VerifyChecksum(sums, "agentruntime_linux_amd64.tar.gz", []byte("tampered")); err == nil {
		t.Error("tampered data accepted")
	}
}

func TestExtractTarGzAndZip(t *testing.T) {
	want := []byte("binary-bytes")

	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	for name, body := range map[string][]byte{"README.md": []byte("hi"), "agentruntime": want} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}
	tw.Close()
	gz.Close()
	got, err := Extract(tgz.Bytes(), "x.tar.gz", "agentruntime")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("tar.gz: %q %v", got, err)
	}
	if _, err := Extract(tgz.Bytes(), "x.tar.gz", "nope"); err == nil {
		t.Error("missing binary in tar should error")
	}

	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("dist/agentruntime.exe")
	_, _ = w.Write(want)
	zw.Close()
	got, err = Extract(zb.Bytes(), "x.zip", "agentruntime.exe")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("zip: %q %v", got, err)
	}
}

func TestRefreshSiblingsOnlyTouchesOurOwnCopies(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, BinaryName(runtime.GOOS))
	alias := filepath.Join(dir, AliasBinaryName(runtime.GOOS))
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	// Alias is an identical copy of the main binary: it must follow the update.
	write(main, "v1")
	write(alias, "v1")
	sum, _ := fileSHA256(main)
	if err := Replace(main, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	refreshSiblings(main, sum, []byte("v2"))
	if read(alias) != "v2" {
		t.Errorf("alias not refreshed: %q", read(alias))
	}

	// Alias is someone else's program: it must be left alone.
	write(main, "v1")
	write(alias, "a completely different agent")
	sum, _ = fileSHA256(main)
	_ = Replace(main, []byte("v2"))
	refreshSiblings(main, sum, []byte("v2"))
	if read(alias) != "a completely different agent" {
		t.Errorf("foreign binary was overwritten: %q", read(alias))
	}

	// Running as the alias: the main binary must be refreshed instead.
	write(main, "v1")
	write(alias, "v1")
	sum, _ = fileSHA256(alias)
	_ = Replace(alias, []byte("v2"))
	refreshSiblings(alias, sum, []byte("v2"))
	if read(main) != "v2" {
		t.Errorf("main not refreshed when run via alias: %q", read(main))
	}
}

func TestReplaceSwapsBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agentruntime")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Replace(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "new" {
		t.Fatalf("exe content = %q", got)
	}
	if runtime.GOOS == "windows" {
		if old, err := os.ReadFile(exe + ".old"); err != nil || string(old) != "old" {
			t.Errorf("old binary should be kept aside on Windows: %q %v", old, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".agentruntime-new-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

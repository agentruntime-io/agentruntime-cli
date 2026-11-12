// Package update implements self-update from release archives.
//
// Release layout (GitHub Releases or any static host via AGENTRUNTIME_CLI_BASE_URL):
//
//	<base>/latest/download/agentruntime_<os>_<arch>.tar.gz   (.zip on Windows)
//	<base>/latest/download/checksums.txt                     (sha256, "<hex>  <file>")
//	<base>/download/<tag>/...                                (pinned versions)
//	<base>/latest                                            (redirects to .../tag/<tag>)
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

// DefaultBaseURL is where releases are published.
const DefaultBaseURL = "https://github.com/agentruntime-io/agentruntime-cli/releases"

const maxDownload = 200 << 20 // 200 MiB safety cap

// BaseURL returns the release base URL (AGENTRUNTIME_CLI_BASE_URL overrides).
func BaseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("AGENTRUNTIME_CLI_BASE_URL")), "/"); v != "" {
		return v
	}
	return DefaultBaseURL
}

// AliasName is the short command the installers place next to the main binary.
const AliasName = "agent"

// BinaryName is the executable file name for goos.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "agentruntime.exe"
	}
	return "agentruntime"
}

// AliasBinaryName is the alias executable file name for goos.
func AliasBinaryName(goos string) string {
	if goos == "windows" {
		return AliasName + ".exe"
	}
	return AliasName
}

// AssetName is the release archive name for a platform.
func AssetName(goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("agentruntime_%s_%s%s", goos, goarch, ext)
}

func client() *http.Client { return &http.Client{Timeout: 5 * time.Minute} }

func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s (is there a published release for this platform?)", url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownload {
		return nil, errors.New("download exceeds size limit")
	}
	return data, nil
}

// LatestTag resolves the newest release tag by following the /latest redirect.
func LatestTag(ctx context.Context, base string) (string, error) {
	c := client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("cannot determine latest version from %s/latest (status %s)", base, resp.Status)
	}
	tag := path.Base(strings.TrimRight(loc, "/"))
	if tag == "" || tag == "." || tag == "/" {
		return "", fmt.Errorf("unexpected redirect %q", loc)
	}
	return tag, nil
}

// Newer reports whether latest is a higher version than current.
// Unparseable current versions (e.g. "dev") are always considered older.
func Newer(latest, current string) bool {
	l, lok := parseVersion(latest)
	c, cok := parseVersion(current)
	if !lok {
		return false
	}
	if !cok {
		return true
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 || parts[0] == "" {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Result describes a completed or skipped update.
type Result struct {
	From, To string
	Path     string
	Updated  bool
}

// Options configures Run.
type Options struct {
	Current string // current version
	Target  string // tag to install; empty = latest
	Check   bool   // only report, never install
}

// Run checks for (and optionally installs) a release of this platform.
func Run(ctx context.Context, opt Options) (*Result, error) {
	base := BaseURL()
	target := strings.TrimSpace(opt.Target)
	latest := target == ""
	if latest {
		tag, err := LatestTag(ctx, base)
		if err != nil {
			return nil, err
		}
		target = tag
	}
	res := &Result{From: opt.Current, To: target}
	if latest && !Newer(target, opt.Current) {
		return res, nil
	}
	if opt.Check {
		return res, nil
	}

	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	prefix := base + "/download/" + target + "/"
	archive, err := get(ctx, prefix+asset)
	if err != nil {
		return nil, err
	}
	sums, err := get(ctx, prefix+"checksums.txt")
	if err != nil {
		return nil, fmt.Errorf("checksums unavailable, refusing to install unverified binary: %w", err)
	}
	if err := VerifyChecksum(sums, asset, archive); err != nil {
		return nil, err
	}
	bin, err := Extract(archive, asset, BinaryName(runtime.GOOS))
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	oldSum, _ := fileSHA256(exe)
	if err := Replace(exe, bin); err != nil {
		return nil, err
	}
	refreshSiblings(exe, oldSum, bin)
	res.Path, res.Updated = exe, true
	return res, nil
}

func fileSHA256(p string) (string, bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// refreshSiblings updates the other name (agentruntime <-> agent) installed next to
// exe, but only when it is a regular-file copy identical to the version that was just
// replaced (oldSum). Symlinks follow the main binary on their own, and any file with
// different contents is somebody else's program and is never touched.
func refreshSiblings(exe, oldSum string, newBin []byte) {
	if oldSum == "" {
		return
	}
	self, err := os.Stat(exe)
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	for _, name := range []string{BinaryName(runtime.GOOS), AliasBinaryName(runtime.GOOS)} {
		p := filepath.Join(dir, name)
		li, err := os.Lstat(p)
		if err != nil || !li.Mode().IsRegular() {
			continue // missing, or a symlink
		}
		if os.SameFile(li, self) {
			continue // already replaced
		}
		if sum, ok := fileSHA256(p); !ok || sum != oldSum {
			continue
		}
		_ = Replace(p, newBin)
	}
}

// VerifyChecksum checks data against the entry for name in a checksums.txt body.
func VerifyChecksum(checksums []byte, name string, data []byte) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(string(checksums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if strings.TrimPrefix(f[1], "*") == name {
			if strings.EqualFold(f[0], got) {
				return nil
			}
			return fmt.Errorf("checksum mismatch for %s (expected %s, got %s)", name, f[0], got)
		}
	}
	return fmt.Errorf("no checksum listed for %s", name)
}

// Extract returns the binary named bin from a .tar.gz or .zip archive.
func Extract(archive []byte, assetName, bin string) ([]byte, error) {
	if strings.HasSuffix(assetName, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if path.Base(f.Name) == bin && !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, maxDownload))
			}
		}
		return nil, fmt.Errorf("%s not found in archive", bin)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s not found in archive", bin)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == bin {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

// Replace atomically swaps the executable at exe with newBin.
// Windows cannot overwrite a running exe but can rename it, so the old file is
// moved aside to <exe>.old first (and removed on the next run).
func Replace(exe string, newBin []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".agentruntime-new-*")
	if err != nil {
		return fmt.Errorf("cannot write next to %s (try running with elevated permissions, or reinstall): %w", exe, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(newBin); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		cleanup()
		return err
	}

	if runtime.GOOS != "windows" {
		if err := os.Rename(tmpPath, exe); err != nil {
			cleanup()
			return err
		}
		return nil
	}

	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		_ = os.Rename(old, exe) // roll back
		cleanup()
		return err
	}
	return nil
}

// CleanupOld removes leftover *.old files from a previous Windows update.
func CleanupOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	_ = os.Remove(exe + ".old")
	_ = os.Remove(filepath.Join(dir, BinaryName(runtime.GOOS)+".old"))
	_ = os.Remove(filepath.Join(dir, AliasBinaryName(runtime.GOOS)+".old"))
}

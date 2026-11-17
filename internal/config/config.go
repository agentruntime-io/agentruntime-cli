// Package config stores CLI profiles (MCP URL + PAT) and resolves effective
// settings from flags, environment and the saved profile.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultURL is the hosted Platform MCP endpoint.
	DefaultURL = "https://mcp.agentruntime.io/mcp"
	// DefaultProfile is used when no profile has been chosen.
	DefaultProfile = "default"
)

// Profile is one saved connection.
type Profile struct {
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
	// ExpiresAt is when a short-lived key stored in Token stops working (RFC 3339). It is empty for a key that
	// does not expire. Whoever saves a short-lived key writes it, and whoever replaces or removes the key clears it.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// File is the on-disk config document.
type File struct {
	Current  string              `json:"current,omitempty"`
	Profiles map[string]*Profile `json:"profiles,omitempty"`
}

// Path returns the config file location.
// Override with AGENTRUNTIME_CONFIG; otherwise <user config dir>/agentruntime/config.json.
func Path() (string, error) {
	if p := strings.TrimSpace(os.Getenv("AGENTRUNTIME_CONFIG")); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("cannot locate config dir: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "agentruntime", "config.json"), nil
}

// Load reads the config file. A missing file yields an empty config.
func Load() (*File, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	f := &File{Profiles: map[string]*Profile{}}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return f, nil
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	return f, nil
}

// Save writes the config file with owner-only permissions (0600 on Unix).
func (f *File) Save() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Names returns the saved profile names, sorted.
func (f *File) Names() []string {
	names := make([]string, 0, len(f.Profiles))
	for n := range f.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Overrides carries values from command-line flags.
type Overrides struct {
	Profile string
	URL     string
	Token   string
}

// Resolved is the effective connection setting.
type Resolved struct {
	Profile     string
	URL         string
	Token       string
	URLSource   string
	TokenSource string
	// TokenExpiresAt is the expiry stored with the profile's key. It is set only when the key in use comes from
	// the saved profile: a key given by flag or environment is not the one the profile's expiry belongs to.
	TokenExpiresAt time.Time
}

func firstEnv(keys ...string) (string, string) {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, "env " + k
		}
	}
	return "", ""
}

// ProfileName picks the active profile: flag > env > saved current > "default".
func (f *File) ProfileName(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AGENTRUNTIME_PROFILE")); v != "" {
		return v
	}
	if f.Current != "" {
		return f.Current
	}
	return DefaultProfile
}

// Resolve combines flags, environment and the saved profile.
// Precedence for URL and token: flag > environment > profile > default.
func (f *File) Resolve(o Overrides) Resolved {
	r := Resolved{Profile: f.ProfileName(o.Profile)}
	prof := f.Profiles[r.Profile]

	switch {
	case strings.TrimSpace(o.URL) != "":
		r.URL, r.URLSource = strings.TrimSpace(o.URL), "flag --url"
	default:
		if v, src := firstEnv("AGENTRUNTIME_MCP_URL", "PLATFORM_MCP_URL"); v != "" {
			r.URL, r.URLSource = v, src
		} else if prof != nil && strings.TrimSpace(prof.URL) != "" {
			r.URL, r.URLSource = strings.TrimSpace(prof.URL), "profile "+r.Profile
		} else {
			r.URL, r.URLSource = DefaultURL, "default"
		}
	}

	switch {
	case strings.TrimSpace(o.Token) != "":
		r.Token, r.TokenSource = strings.TrimSpace(o.Token), "flag --pat"
	default:
		if v, src := firstEnv("AGENTRUNTIME_PAT"); v != "" {
			r.Token, r.TokenSource = v, src
		} else if prof != nil && strings.TrimSpace(prof.Token) != "" {
			r.Token, r.TokenSource = strings.TrimSpace(prof.Token), "profile "+r.Profile
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(prof.ExpiresAt)); err == nil {
				r.TokenExpiresAt = t
			}
		}
	}
	return r
}

// MaskToken shortens a secret for display, e.g. "pat_ab…wxyz".
func MaskToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if len(t) <= 10 {
		return strings.Repeat("*", len(t))
	}
	return t[:6] + "…" + t[len(t)-4:]
}

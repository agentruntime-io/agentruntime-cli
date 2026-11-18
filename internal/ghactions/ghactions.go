// Package ghactions asks GitHub Actions for the identity token (an OIDC token) of the job that is running.
//
// GitHub gives a job that has `permissions: id-token: write` two values in its environment: the address to ask
// (ACTIONS_ID_TOKEN_REQUEST_URL) and a request token that proves the job is entitled to ask
// (ACTIONS_ID_TOKEN_REQUEST_TOKEN). The request token is a credential, so it is sent only to an address that is
// GitHub's: https, on github.com or actions.githubusercontent.com or a host under it, or one of the exact loopback
// hosts (which is what lets a test stand in for GitHub). A redirect is never followed, since it would carry the
// request token to wherever it points. Nothing this package returns or prints holds the request token or the
// identity token it was given: errors are fixed sentences, never a body, a header or a part of the address.
package ghactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

const (
	// EnvRequestURL and EnvRequestToken are the variables GitHub sets for a job that has id-token: write.
	EnvRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// Timeout is how long the request for the identity token may take.
	Timeout = 30 * time.Second

	// maxAnswerBytes bounds what is read from GitHub: the answer is one identity token (a few kilobytes) in a small
	// JSON object.
	maxAnswerBytes = 64 * 1024
	// MaxTokenBytes is the longest identity token accepted.
	MaxTokenBytes        = 16 * 1024
	maxRequestTokenBytes = 8 * 1024
	// MaxAudienceBytes is the longest audience that may be asked for.
	MaxAudienceBytes = 256
)

// Errors a caller can tell apart. Every message is fixed text.
var (
	// ErrBadRequestURL is returned for an address the request token must not be sent to.
	ErrBadRequestURL = errors.New("the identity-token address is not one the CLI will send the job's request token to: it must be an https address on github.com or actions.githubusercontent.com (or a host under actions.githubusercontent.com)")
	// ErrBadRequestToken is returned for a request token that is not plain header text.
	ErrBadRequestToken = errors.New("the job's request token is not in a usable form")
	// ErrBadAnswer is returned when GitHub's answer holds no usable identity token.
	ErrBadAnswer = errors.New("GitHub's answer holds no usable identity token")
)

// StatusError is GitHub answering with a status other than 200. It holds the status and nothing else.
type StatusError struct{ Status int }

func (e *StatusError) Error() string {
	switch {
	case e.Status >= 300 && e.Status < 400:
		return fmt.Sprintf("GitHub answered the identity-token request with a redirect (HTTP %d). The CLI never follows redirects, because the request carries the job's request token", e.Status)
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return fmt.Sprintf("GitHub refused to give an identity token (HTTP %d). Check that the job has permissions: id-token: write", e.Status)
	case e.Status >= 500 || e.Status == http.StatusTooManyRequests || e.Status == http.StatusRequestTimeout:
		return fmt.Sprintf("GitHub could not give an identity token right now (HTTP %d). Run the step again", e.Status)
	}
	return fmt.Sprintf("GitHub did not give an identity token (HTTP %d)", e.Status)
}

// githubHost reports whether host (no port) is GitHub's: github.com, actions.githubusercontent.com or a host under
// it. The check is made on the host exactly as the client will dial it: ASCII letters only (any other character, a
// trailing dot or an empty label makes it not GitHub's), folded to lower case with the one fold the CLI uses for hosts.
// A host that only ends the same way (evilgithub.com, notactions.githubusercontent.com) is not.
func githubHost(host string) bool {
	return apihost.Clean(host) && apihost.Fold(host) == "github.com" || apihost.Under(host, "actions.githubusercontent.com")
}

// authorityText is the part of an address between "://" and the first "/", "?" or "#", exactly as it was written.
func authorityText(raw string) (string, bool) {
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

// ValidateRequestURL checks the address the job's request token will be sent to and returns it parsed. It is
// accepted only if it is https on a GitHub host, with no user name, no fragment and the default port; or a loopback
// host (http or https, any port), for tests. Nothing about a refused address is put in the error.
//
// The host that is checked is the host that is dialled. The address is refused if its host is written with a percent
// escape (url.Parse decodes one, and what it decodes to is not what was checked: %C4%B0 is a capital I with a dot, which
// a Unicode case mapping turns into a plain i), if any byte of the address is not printable ASCII, and unless every
// byte of the parsed host is a letter, digit, dot or hyphen (a colon too, for the loopback address ::1). Case is
// folded for the ASCII letters only, and the returned address carries the folded host, so the request goes to
// exactly the name that was checked.
func ValidateRequestURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] >= 0x7f || raw[i] == 0x5c {
			return nil, ErrBadRequestURL
		}
	}
	authority, ok := authorityText(raw)
	if !ok || strings.ContainsAny(authority, "%@") {
		return nil, ErrBadRequestURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrBadRequestURL
	}
	host := u.Hostname()
	if !apihost.ASCII(host) || !apihost.Clean(host) {
		return nil, ErrBadRequestURL
	}
	switch {
	case apihost.Loopback(host) && (u.Scheme == "http" || u.Scheme == "https"):
	case u.Scheme != "https" || !githubHost(host):
		return nil, ErrBadRequestURL
	case u.Port() != "" && u.Port() != "443":
		return nil, ErrBadRequestURL
	}
	u.Host = apihost.Fold(u.Host)
	return u, nil
}

// Requester asks GitHub for identity tokens. It holds the job's request token and never shows it.
type Requester struct {
	u     *url.URL
	token string
	http  *http.Client
}

// Authority is the host the request goes to, as it was checked and as it is dialled (see package apihost).
func (r *Requester) Authority() string { return apihost.Authority(r.u) }

// String and GoString keep the request token out of %v, %+v, %s and %#v.
func (r Requester) String() string   { return "ghactions.Requester{token: <hidden>}" }
func (r Requester) GoString() string { return r.String() }

// New checks the two values GitHub put in the environment and builds a Requester.
func New(requestURL, requestToken string) (*Requester, error) {
	u, err := ValidateRequestURL(requestURL)
	if err != nil {
		return nil, err
	}
	requestToken = strings.TrimSpace(requestToken)
	if requestToken == "" || len(requestToken) > maxRequestTokenBytes {
		return nil, ErrBadRequestToken
	}
	for i := 0; i < len(requestToken); i++ {
		if requestToken[i] <= 0x20 || requestToken[i] >= 0x7f {
			return nil, ErrBadRequestToken
		}
	}
	return &Requester{
		u:     u,
		token: requestToken,
		http: &http.Client{
			Timeout: Timeout,
			// Never follow a redirect: it would carry the request token to wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ValidateAudience checks an audience: printable ASCII with no spaces, 1 to MaxAudienceBytes. The audience is what
// the server checks the identity token was made for; it is sent to GitHub in the query of the request.
func ValidateAudience(a string) error {
	if a == "" || len(a) > MaxAudienceBytes {
		return fmt.Errorf("the audience must be 1 to %d characters", MaxAudienceBytes)
	}
	for i := 0; i < len(a); i++ {
		if a[i] <= 0x20 || a[i] >= 0x7f {
			return errors.New("the audience may only hold printable characters, with no spaces")
		}
	}
	return nil
}

// IDToken asks GitHub for the job's identity token with the given audience.
func (r *Requester) IDToken(ctx context.Context, audience string) (string, error) {
	if err := ValidateAudience(audience); err != nil {
		return "", err
	}
	u := *r.u
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", errors.New("could not build the identity-token request")
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Accept", "application/json; api-version=2.0")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := r.http.Do(req)
	if err != nil {
		// url.Error would print the address, which the caller does not need; the cause is enough.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("cannot reach GitHub for the identity token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &StatusError{Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return "", errors.New("could not read GitHub's answer")
	}
	if len(raw) > maxAnswerBytes {
		return "", ErrBadAnswer
	}
	var ans struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &ans) != nil || !plausibleJWT(ans.Value) {
		return "", ErrBadAnswer
	}
	return ans.Value, nil
}

// plausibleJWT accepts an identity token as GitHub writes it, a JWT (three non-empty parts of URL-safe base64 joined
// by dots), and nothing else.
func plausibleJWT(t string) bool {
	if len(t) < 16 || len(t) > MaxTokenBytes {
		return false
	}
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

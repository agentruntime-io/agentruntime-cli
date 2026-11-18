package bffclient

// CI sign-in: a CI job gives the API the identity token its platform issued to it (for GitHub Actions, an OIDC
// token that says which repository, branch and workflow is running) and gets a short-lived access key back, for the
// one CI trust it names.
//
// The route is public: it is called before there is any key, so this client holds none and sends no Authorization
// header. It follows the rules of the other pre-sign-in client (https, plain http only for the exact loopback hosts,
// a redirect is never followed, answers are size-capped, every request has a timeout; see newPublicClient).
//
// Two values here are secrets and are kept out of everything this package can print: the identity token (a bearer
// credential for the exchange for as long as it lives) and the access key in the answer. WorkloadGrant hides the key
// from %v, %+v, %#v and from JSON, and no error built here contains a body, a header or either secret.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
)

const (
	workloadExchangePath = "/v1/auth/workload/exchange"

	// maxWorkloadAnswerBytes bounds what the client reads from the exchange route: its answer is a few hundred bytes.
	maxWorkloadAnswerBytes = 64 * 1024
	// WorkloadHTTPTimeout is how long the exchange request may take.
	WorkloadHTTPTimeout = 30 * time.Second

	// MaxIDTokenBytes is the longest identity token the client will send. A GitHub Actions token is a few kilobytes.
	MaxIDTokenBytes = 16 * 1024
)

// ProviderGitHub is the one identity provider the exchange knows: GitHub Actions.
const ProviderGitHub = "github"

// WorkloadClient calls the public CI sign-in route. It holds no access key.
type WorkloadClient struct {
	base *url.URL
	http *http.Client
}

// NewWorkloadClient validates the API address (https, or http for the exact hosts localhost, 127.0.0.1 and ::1) and
// builds a client with no key, a request timeout, and no redirect following.
func NewWorkloadClient(base string) (*WorkloadClient, error) {
	u, hc, err := newPublicClient(base, "refusing to sign in over plain http: the identity token and the access key would travel unencrypted. Use an https API address (http is allowed only for localhost, 127.0.0.1 and ::1)", WorkloadHTTPTimeout)
	if err != nil {
		return nil, err
	}
	return &WorkloadClient{base: u, http: hc}, nil
}

// BaseURL is the API address the client calls, without a trailing slash.
func (c *WorkloadClient) BaseURL() string { return c.base.String() }

// Host is the host name of the API address, without a port.
func (c *WorkloadClient) Host() string { return c.base.Hostname() }

// WorkloadGrant is the short-lived access key the server made for a CI job.
type WorkloadGrant struct {
	Token     string    // secret: the access key, delivered once
	ExpiresAt time.Time // when the key stops working
	Scopes    []string  // what the key may do
	Trust     string    // the CI trust the key was made for, as the server wrote it (may be empty)
}

// String shows everything but the key.
func (g WorkloadGrant) String() string {
	return fmt.Sprintf("workloadgrant{expires_at: %s, scopes: %q, trust: %q, token: <hidden>}",
		g.ExpiresAt.Format(time.RFC3339), g.Scopes, g.Trust)
}

// GoString keeps %#v from printing the key.
func (g WorkloadGrant) GoString() string { return g.String() }

// MarshalJSON leaves the key out.
func (g WorkloadGrant) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExpiresAt string   `json:"expires_at"`
		Scopes    []string `json:"scopes"`
		Trust     string   `json:"trust,omitempty"`
	}{g.ExpiresAt.Format(time.RFC3339), g.Scopes, g.Trust})
}

// Fixed sentences, used when the server sent none of its own. They use the server's code and never contain a
// token, a key or text from the answer.
var workloadMessages = map[string]string{
	"invalid_workload_token": "The server did not accept this job's identity token for that CI trust.",
}

var workloadFallbacks = fallbackSet{byCode: workloadMessages, byStatus: func(status int) string {
	switch {
	case status >= 300 && status < 400:
		return fmt.Sprintf("The API address answered with a redirect (HTTP %d). The CLI never follows redirects: use the final https address as --api-url.", status)
	case status == http.StatusBadRequest:
		return "The server did not accept the sign-in request (HTTP 400). Check --trust."
	case status == http.StatusMethodNotAllowed || status == http.StatusNotFound || status == http.StatusNotImplemented:
		return fmt.Sprintf("The server does not offer CI sign-in at this address (HTTP %d). It may not be turned on yet, or --api-url is wrong.", status)
	case status == http.StatusTooManyRequests:
		return "Too many sign-in attempts (HTTP 429). Wait a minute and try again."
	case status == http.StatusServiceUnavailable:
		return "The service could not do this right now (HTTP 503). Try again in a moment."
	case status >= 500:
		return fmt.Sprintf("The server could not do this right now (HTTP %d). Try again in a moment.", status)
	}
	return fmt.Sprintf("The server refused the request (HTTP %d).", status)
}}

// NormalizeTrustID returns the canonical form of a CI trust id, a UUID in lower case with its hyphens, and whether s
// is one. A trust id is made by the server, so anything else is a typo (or a pasted secret) and is never sent.
func NormalizeTrustID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "", false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return "", false
		}
	}
	return strings.ToLower(s), true
}

// Exchange gives the server the job's identity token and asks for an access key for the CI trust named by trust (a
// trust id as NormalizeTrustID reads it). The token works once. A refusal is an *APIError; the server says nothing
// about why (the code is invalid_workload_token for every reason). An answer that arrived but cannot be used is an
// ErrUnexpectedAnswer: the identity token may be spent by then, so nothing is retried here.
func (c *WorkloadClient) Exchange(ctx context.Context, provider, trust, idToken string) (*WorkloadGrant, error) {
	if provider != ProviderGitHub {
		return nil, fmt.Errorf("unknown identity provider %q", provider)
	}
	trust, ok := NormalizeTrustID(trust)
	if !ok {
		return nil, fmt.Errorf("the CI trust id is not a valid id; nothing was sent")
	}
	if !plausibleIDToken(idToken) {
		return nil, fmt.Errorf("the identity token is not in a usable form; nothing was sent")
	}
	payload, err := json.Marshal(struct {
		Provider string `json:"provider"`
		Trust    string `json:"trust"`
		Token    string `json:"token"`
	}{provider, trust, idToken})
	if err != nil {
		return nil, err
	}
	r, err := doRequest(ctx, c.http, c.base, "", maxWorkloadAnswerBytes, http.MethodPost, workloadExchangePath, nil, payload)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusOK {
		// The server's own words are never passed on: it refuses with one fixed code for every reason and no text of
		// its own is needed, so the sentence comes from here, and only a code this client knows is kept.
		e := apiError(r.Status, r.Header, r.Body, workloadFallbacks)
		if _, known := workloadMessages[e.Code]; !known {
			e.Code = ""
		}
		e.Message = workloadFallbacks.message(e.Code, e.Status)
		e.Rooms = nil
		return nil, e
	}
	g, err := decodeWorkloadGrant(r.Body)
	if err != nil {
		return nil, err
	}
	if g.Trust != "" && !strings.EqualFold(g.Trust, trust) {
		return nil, unexpected("the access key is for another trust")
	}
	return g, nil
}

func decodeWorkloadGrant(body []byte) (*WorkloadGrant, error) {
	var ans struct {
		Token     string   `json:"token"`
		ExpiresAt string   `json:"expires_at"`
		Scopes    []string `json:"scopes"`
		Trust     string   `json:"trust"`
	}
	if err := json.Unmarshal(body, &ans); err != nil {
		return nil, unexpected("the access key is not readable")
	}
	if !plausibleToken(ans.Token) {
		return nil, unexpected("no usable access key")
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(ans.ExpiresAt))
	if err != nil {
		return nil, unexpected("the access key came without a readable expiry")
	}
	if len(ans.Scopes) > 16 {
		return nil, unexpected("the access key came with too many scopes")
	}
	g := &WorkloadGrant{Token: ans.Token, ExpiresAt: exp, Trust: cleanText(ans.Trust, 64)}
	for _, s := range ans.Scopes {
		g.Scopes = append(g.Scopes, cleanText(s, 64))
	}
	return g, nil
}

// plausibleIDToken accepts an identity token as a CI platform writes it, a JWT (three parts of URL-safe base64
// joined by dots), and nothing else, so the request holds no text that is not a token.
func plausibleIDToken(t string) bool {
	if len(t) < 16 || len(t) > MaxIDTokenBytes {
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

// Authority is the host the client dials, as it is shown, stored and compared (see package apihost).
func (c *WorkloadClient) Authority() string { return apihost.Authority(c.base) }

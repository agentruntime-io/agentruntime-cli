package bffclient

// Device sign-in (RFC 8628 style): the CLI asks for a code, a person approves it in the Console, and the CLI polls
// until the server hands over a short-lived access key, exactly once.
//
// These two routes are public: they are called before there is any key, so this client holds none and sends no
// Authorization header. It follows the same rules as the client that does hold a key: https (plain http only for
// the exact loopback hosts), a redirect is never followed, answers are size-capped, and every request has a timeout.
//
// Two values here are secrets and are kept out of everything this package can print: the device code (the poll's
// proof that this terminal started the request) and the access key in the final answer. DeviceCode and DeviceGrant
// hide them from %v, %+v, %#v and from JSON, and no error built here contains a body or a header.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
)

const (
	deviceCodePath  = "/v1/auth/device/code"
	deviceTokenPath = "/v1/auth/device/token"

	// maxDeviceAnswerBytes bounds what the client reads from the two device routes: their answers are a few hundred
	// bytes.
	maxDeviceAnswerBytes = 64 * 1024
	// DeviceHTTPTimeout is how long one request to either route may take.
	DeviceHTTPTimeout = 30 * time.Second

	// DeviceClientName is the client name sent with a request, so the person approving it sees what asked.
	DeviceClientName = "agentruntime-cli"

	// Bounds the server applies to a device request.
	MinDeviceTTLSeconds = 60
	MaxDeviceTTLSeconds = 28800
	MaxDeviceRefs       = 100

	defaultDeviceInterval = 5
	maxDeviceInterval     = 60
	defaultDeviceLifetime = 600
	maxDeviceLifetime     = 1800
)

// The two scopes a device key may carry.
const (
	ScopeFetch    = "secrets:fetch"
	ScopeListName = "vault:read"
)

// ErrUnexpectedAnswer marks an answer the client cannot use (not JSON, a field missing or malformed). It is never
// retried: an answer that arrived but cannot be read may already have used up the one-time delivery.
var ErrUnexpectedAnswer = errors.New("unexpected answer from the server")

func unexpected(what string) error { return fmt.Errorf("%w (%s)", ErrUnexpectedAnswer, what) }

// DeviceClient calls the public device sign-in routes. It holds no access key.
type DeviceClient struct {
	base *url.URL
	http *http.Client
}

// NewDeviceClient validates the API address (https, or http for the exact hosts localhost, 127.0.0.1 and ::1) and
// builds a client with no key, a request timeout, and no redirect following.
func NewDeviceClient(base string) (*DeviceClient, error) {
	u, err := parseBase(base, "refusing to sign in over plain http: the code and the access key would travel unencrypted. Use an https API address (http is allowed only for localhost, 127.0.0.1 and ::1)")
	if err != nil {
		return nil, err
	}
	return &DeviceClient{
		base: u,
		http: &http.Client{
			Timeout: DeviceHTTPTimeout,
			// Never follow a redirect: the answers carry codes that must stay between this terminal and this server.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// BaseURL is the API address the client calls, without a trailing slash.
func (c *DeviceClient) BaseURL() string { return c.base.String() }

// Host is the host name of the API address, without a port.
func (c *DeviceClient) Host() string { return c.base.Hostname() }

// Authority is the host the client dials, as it is shown, stored and compared (see package apihost). It is the same
// value as Host plus the port when it is not the default one.
func (c *DeviceClient) Authority() string { return apihost.Authority(c.base) }

// DeviceRequest is what the CLI asks the person to approve.
type DeviceRequest struct {
	Name       string   // the device's name, shown to the approver
	Scopes     []string // a subset of ScopeFetch and ScopeListName
	Refs       []string // the secrets the key may fetch (patterns allowed); empty when AllowAll
	AllowAll   bool     // ask for every secret the approver may view; never together with Refs
	TTLSeconds int      // how long the key should last, MinDeviceTTLSeconds to MaxDeviceTTLSeconds
}

// DeviceCode is the server's answer to a request.
type DeviceCode struct {
	DeviceCode              string // secret: sent back with every poll, never shown
	UserCode                string // shown to the person, who types it in the Console
	VerificationURI         string
	VerificationURIComplete string // the same address with the code in it; may be empty
	ExpiresIn               int    // seconds the code works, from when it was made
	Interval                int    // seconds between polls
}

// String shows everything but the device code.
func (d DeviceCode) String() string {
	return fmt.Sprintf("devicecode{user_code: %q, verification_uri: %q, expires_in: %d, interval: %d, device_code: <hidden>}",
		d.UserCode, d.VerificationURI, d.ExpiresIn, d.Interval)
}

// GoString keeps %#v from printing the device code.
func (d DeviceCode) GoString() string { return d.String() }

// MarshalJSON leaves the device code out, so no code path can print it by marshalling the answer.
func (d DeviceCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}{d.UserCode, d.VerificationURI, d.VerificationURIComplete, d.ExpiresIn, d.Interval})
}

// DeviceGrant is the short-lived access key the server hands over once the person approved.
type DeviceGrant struct {
	Token     string    // secret: the access key, delivered once
	ExpiresAt time.Time // when the key stops working
	TenantID  string
	// TenantName is the workspace's name and ApprovedBy the person who approved, masked by the server (t***@example.com).
	// Both are optional in the server's answer and are empty when it did not send them.
	TenantName string
	ApprovedBy string
	Scopes     []string // what the key may do, as approved (the person may have narrowed the request)
	Refs       []string // which secrets it may fetch, as approved
	AllowAll   bool     // it may fetch everything its owner may view (the approver chose that)
}

// String shows everything but the key.
func (g DeviceGrant) String() string {
	return fmt.Sprintf("devicegrant{expires_at: %s, tenant_id: %q, tenant_name: %q, approved_by: %q, scopes: %q, refs: %q, allow_all: %t, token: <hidden>}",
		g.ExpiresAt.Format(time.RFC3339), g.TenantID, g.TenantName, g.ApprovedBy, g.Scopes, g.Refs, g.AllowAll)
}

// GoString keeps %#v from printing the key.
func (g DeviceGrant) GoString() string { return g.String() }

// MarshalJSON leaves the key out.
func (g DeviceGrant) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExpiresAt  string   `json:"expires_at"`
		TenantID   string   `json:"tenant_id,omitempty"`
		TenantName string   `json:"tenant_name,omitempty"`
		ApprovedBy string   `json:"approved_by,omitempty"`
		Scopes     []string `json:"scopes"`
		Refs       []string `json:"refs"`
		AllowAll   bool     `json:"allow_all"`
	}{g.ExpiresAt.Format(time.RFC3339), g.TenantID, g.TenantName, g.ApprovedBy, g.Scopes, g.Refs, g.AllowAll})
}

// PollState is what one poll found out.
type PollState int

const (
	PollPending  PollState = iota + 1 // keep waiting
	PollSlowDown                      // keep waiting, and wait longer between polls
	PollDenied                        // the person said no
	PollExpired                       // the code ran out, or it was already used
	PollGranted                       // the key is in PollResult.Grant
)

// PollResult is the answer to one poll.
type PollResult struct {
	State PollState
	Grant *DeviceGrant // set only when State is PollGranted
}

// Fixed sentences, used when the server sent none of its own. They use the server's codes and never contain a code
// or a key.
var deviceMessages = map[string]string{
	"invalid_request":       "The sign-in request is not valid. Check --ref, --scope and --ttl.",
	"invalid_scope":         "The server does not allow one of the requested scopes.",
	"bad_ref":               "The server does not accept one of the --ref values.",
	"rate_limited":          "Too many sign-in attempts from this network. Wait a minute and try again.",
	"authorization_pending": "The sign-in has not been approved yet.",
	"slow_down":             "Polling too fast.",
	"access_denied":         "The sign-in was denied in the Console.",
	"expired_token":         "The sign-in code expired, or it was already used.",
}

var deviceFallbacks = fallbackSet{byCode: deviceMessages, byStatus: func(status int) string {
	switch {
	case status >= 300 && status < 400:
		return fmt.Sprintf("The API address answered with a redirect (HTTP %d). The CLI never follows redirects: use the final https address as --api-url.", status)
	case status == http.StatusMethodNotAllowed || status == http.StatusNotFound || status == http.StatusNotImplemented:
		return fmt.Sprintf("The server does not offer device sign-in at this address (HTTP %d). It may not be turned on yet, or --api-url is wrong.", status)
	case status == http.StatusTooManyRequests:
		return "Too many sign-in attempts from this network (HTTP 429). Wait a minute and try again."
	case status == http.StatusServiceUnavailable:
		return "The service could not do this right now (HTTP 503). Try again in a moment."
	case status >= 500:
		return fmt.Sprintf("The server could not do this right now (HTTP %d). Try again in a moment.", status)
	}
	return fmt.Sprintf("The server refused the request (HTTP %d).", status)
}}

// Start asks the server for a device code and a user code.
func (c *DeviceClient) Start(ctx context.Context, req DeviceRequest) (*DeviceCode, error) {
	body := struct {
		Client     string   `json:"client"`
		DeviceName string   `json:"device_name"`
		Scopes     []string `json:"scopes"`
		Refs       []string `json:"refs,omitempty"`
		AllowAll   bool     `json:"allow_all"`
		TTLSeconds int      `json:"ttl_seconds"`
	}{DeviceClientName, req.Name, req.Scopes, req.Refs, req.AllowAll, req.TTLSeconds}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r, err := doRequest(ctx, c.http, c.base, "", maxDeviceAnswerBytes, http.MethodPost, deviceCodePath, nil, payload)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusOK && r.Status != http.StatusCreated {
		return nil, apiError(r.Status, r.Header, r.Body, deviceFallbacks)
	}
	var ans struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(r.Body, &ans); err != nil {
		return nil, unexpected("the sign-in code is not readable")
	}
	switch {
	case !plausibleDeviceCode(ans.DeviceCode):
		return nil, unexpected("no usable device code")
	case !plausibleUserCode(ans.UserCode):
		return nil, unexpected("no usable user code")
	case ans.VerificationURI == "" || len(ans.VerificationURI) > 2048 || len(ans.VerificationURIComplete) > 2048:
		return nil, unexpected("no usable verification address")
	}
	if ans.ExpiresIn <= 0 {
		ans.ExpiresIn = defaultDeviceLifetime
	}
	ans.ExpiresIn = min(ans.ExpiresIn, maxDeviceLifetime)
	if ans.Interval <= 0 {
		ans.Interval = defaultDeviceInterval
	}
	ans.Interval = min(ans.Interval, maxDeviceInterval)
	return &DeviceCode{
		DeviceCode:              ans.DeviceCode,
		UserCode:                ans.UserCode,
		VerificationURI:         ans.VerificationURI,
		VerificationURIComplete: ans.VerificationURIComplete,
		ExpiresIn:               ans.ExpiresIn,
		Interval:                ans.Interval,
	}, nil
}

// Poll asks whether the person has approved. A protocol answer (pending, slow down, denied, expired) is a
// PollResult with no error. A key in the answer is delivered once: the server answers every later poll as expired.
// Anything else is an error: an *APIError for a status the protocol does not use, ErrUnexpectedAnswer for a body
// that cannot be read, or a network error. IsTransient says whether trying again can help.
func (c *DeviceClient) Poll(ctx context.Context, deviceCode string) (PollResult, error) {
	payload, err := json.Marshal(struct {
		DeviceCode string `json:"device_code"`
	}{deviceCode})
	if err != nil {
		return PollResult{}, err
	}
	r, err := doRequest(ctx, c.http, c.base, "", maxDeviceAnswerBytes, http.MethodPost, deviceTokenPath, nil, payload)
	if err != nil {
		return PollResult{}, err
	}
	if r.Status == http.StatusOK {
		g, err := decodeGrant(r.Body)
		if err != nil {
			return PollResult{}, err
		}
		return PollResult{State: PollGranted, Grant: g}, nil
	}
	e := apiError(r.Status, r.Header, r.Body, deviceFallbacks)
	if r.Status >= 400 && r.Status < 500 && r.Status != http.StatusTooManyRequests {
		// The protocol's answers. A refusal relayed from a service behind the API can arrive with the code in the
		// message field and none of its own, so both are read.
		code := e.Code
		if code == "" {
			if _, known := deviceMessages[e.Message]; known {
				code = e.Message
			}
		}
		switch code {
		case "authorization_pending":
			return PollResult{State: PollPending}, nil
		case "slow_down":
			return PollResult{State: PollSlowDown}, nil
		case "access_denied":
			return PollResult{State: PollDenied}, nil
		case "expired_token":
			return PollResult{State: PollExpired}, nil
		}
	}
	return PollResult{}, e
}

// IsTransient reports whether a failed poll may succeed if tried again later: the network failed, the server is
// busy or broken (429, 5xx), or the request timed out. An answer that arrived but cannot be used is never transient.
func IsTransient(err error) bool {
	if err == nil || errors.Is(err, ErrUnexpectedAnswer) {
		return false
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status == http.StatusTooManyRequests || ae.Status == http.StatusRequestTimeout || ae.Status >= 500
	}
	return true
}

func decodeGrant(body []byte) (*DeviceGrant, error) {
	var ans struct {
		Token      string   `json:"token"`
		ExpiresAt  string   `json:"expires_at"`
		TenantID   string   `json:"tenant_id"`
		TenantName string   `json:"tenant_name"`
		ApprovedBy string   `json:"approved_by"`
		Scopes     []string `json:"scopes"`
		Refs       []string `json:"refs"`
		AllowAll   bool     `json:"allow_all"`
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
	if len(ans.Scopes) > 16 || len(ans.Refs) > 1000 {
		return nil, unexpected("the access key came with too many scopes or secrets")
	}
	g := &DeviceGrant{Token: ans.Token, ExpiresAt: exp, TenantID: cleanText(ans.TenantID, 64), TenantName: cleanText(ans.TenantName, 100),
		ApprovedBy: cleanText(ans.ApprovedBy, 100), AllowAll: ans.AllowAll}
	for _, s := range ans.Scopes {
		g.Scopes = append(g.Scopes, cleanText(s, 64))
	}
	for _, s := range ans.Refs {
		g.Refs = append(g.Refs, cleanText(s, 256))
	}
	return g, nil
}

// plausibleDeviceCode accepts the device code as the server writes it, URL-safe base64, and nothing else.
func plausibleDeviceCode(s string) bool {
	if len(s) < 16 || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '=':
		default:
			return false
		}
	}
	return true
}

// plausibleUserCode accepts the short code a person types: letters, digits and dashes, 4 to 16 characters. It is
// printed on a terminal, so nothing else gets through.
func plausibleUserCode(s string) bool {
	if len(s) < 4 || len(s) > 16 {
		return false
	}
	alnum := 0
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			alnum++
		case r == '-':
		default:
			return false
		}
	}
	return alnum >= 4
}

// Package bffclient is the small HTTPS client for the AgentRuntime API routes
// the CLI needs beyond Platform MCP: POST /v1/secrets/fetch (the only call that
// returns secret values) and the secret history, restore, Recently-deleted and
// settings routes (vault.go), which never carry a value.
//
// Secret values must never reach an LLM, so this is plain REST and not an MCP
// tool. Nothing in this package logs or formats a response body.
package bffclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/agentruntime-io/agentruntime-cli/internal/apihost"
	"github.com/agentruntime-io/agentruntime-cli/internal/version"
)

const (
	// EnvAPIURL overrides the API address derived from the MCP URL.
	EnvAPIURL = "AGENTRUNTIME_API_URL"

	// MaxRequestBytes is the server's request body cap for the fetch route.
	MaxRequestBytes = 8 * 1024
	// maxAnswerBytes bounds what the client will read: the server caps answers
	// at 64 KB, this leaves room for JSON overhead and still stops a runaway.
	maxAnswerBytes = 256 * 1024

	fetchPath = "/v1/secrets/fetch"

	// KeyExpiresHeader is the response header on the fetch route (check mode included) that carries the moment the
	// access key stops working, in RFC 3339. The server sends it only for a key that has an expiry.
	KeyExpiresHeader = "X-Key-Expires"
)

// DeriveAPIURL turns the Platform MCP URL into the API base URL: the "mcp."
// host becomes "api." (https://mcp.agentruntime.io/mcp becomes
// https://api.agentruntime.io). Any other host cannot be derived.
func DeriveAPIURL(mcpURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(mcpURL))
	if err != nil || u.Host == "" || u.Scheme == "" {
		return "", errors.New("the Platform MCP URL is not a valid URL")
	}
	rest, ok := strings.CutPrefix(u.Hostname(), "mcp.")
	if !ok || rest == "" {
		return "", fmt.Errorf("cannot derive the API address from the Platform MCP host %q (it does not start with \"mcp.\")", u.Hostname())
	}
	host := "api." + rest
	if p := u.Port(); p != "" {
		host = net.JoinHostPort(host, p)
	}
	return u.Scheme + "://" + host, nil
}

// Value is one fetched answer: a string for a ref with #field, an object of
// fields for a whole-secret ref.
type Value struct {
	String   string
	Fields   map[string]string
	IsObject bool
}

// CheckItem is the answer to one reference in a check call.
type CheckItem struct {
	Ref      string `json:"ref"`
	Resolves bool   `json:"resolves"`
}

// APIError is an error answer from the server: a fixed code and a fixed
// sentence, never a value.
type APIError struct {
	Status     int
	Code       string
	Message    string
	Rooms      []string // for ambiguous_ref: the rooms that hold the name
	RetryAfter string   // seconds, from the Retry-After header, when sent
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (%s)", e.Message, e.Code)
	}
	return e.Message
}

// Client calls the API with one access key.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client

	mu         sync.Mutex
	keyExpires time.Time // from the last fetch or check answer that carried KeyExpiresHeader
}

// BaseURL is the API address the client calls, without a trailing slash.
func (c *Client) BaseURL() string { return c.base.String() }

// Authority is the host the client dials, as it is shown, stored and compared (see package apihost).
func (c *Client) Authority() string { return apihost.Authority(c.base) }

// KeyExpires returns when the access key stops working, as reported by the last fetch or check answer. ok is false
// when no answer carried an expiry (the key does not expire, or the server did not say).
func (c *Client) KeyExpires() (t time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keyExpires, !c.keyExpires.IsZero()
}

// noteKeyExpiry remembers the expiry a fetch or check answer reports. An unreadable value is ignored.
func (c *Client) noteKeyExpiry(h http.Header) {
	v := strings.TrimSpace(h.Get(KeyExpiresHeader))
	if v == "" {
		return
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.keyExpires = t
	c.mu.Unlock()
}

// New validates the base URL and builds a client. The access key travels in a
// header and the answer carries secret values, so the address must be https
// (plain http is accepted only for the exact hosts localhost, 127.0.0.1 and ::1,
// for local testing).
func New(base, token string) (*Client, error) {
	u, err := parseBase(base, "refusing to send an access key over plain http: use an https API address (http is allowed only for localhost, 127.0.0.1 and ::1)")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("no access key configured")
	}
	return &Client{
		base:  u,
		token: strings.TrimSpace(token),
		http: &http.Client{
			// Never follow a redirect: it could carry the key somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// parseBase validates an API address for every client in this package: https, or plain http only for the exact
// loopback hosts; no credentials, query or fragment. plainHTTP is the sentence used for a refused http address.
func parseBase(base, plainHTTP string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" {
		return nil, errors.New("the API address is not a valid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("the API address must not carry credentials, a query or a fragment")
	}
	// The name that is dialled must be the name that is shown, stored and compared. A host with characters outside
	// ASCII is dialled in another form (its punycode), and some of those characters look like, or case-fold to, ASCII
	// letters, so it is refused: write an international name in its xn-- form.
	if !apihost.ASCII(u.Hostname()) {
		return nil, errors.New("the API address must use a plain ASCII host name (write an international name in its xn-- form), so that the name shown is the name dialled")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New(plainHTTP)
		}
	default:
		return nil, errors.New("the API address must start with https://")
	}
	// One lower-case ASCII form of the host, used for the request and for everything that is shown or compared.
	u.Host = apihost.Fold(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// isLoopback reports whether host is exactly one of the three loopback names that
// may be used over plain http. It is deliberately not "anything that resolves to
// the local machine": a name ending in .localhost, or another 127.x.y.z address,
// is not a promise that the traffic stays on this machine. The rule is shared with the
// Platform MCP client (apihost.ExactLoopback), so that no client accepts more than another.
func isLoopback(host string) bool { return apihost.ExactLoopback(host) }

// Fetch asks for the values of refs in one call. It is all or nothing: on any
// error no value is returned. The map is keyed by the refs as sent.
func (c *Client) Fetch(ctx context.Context, refs []string) (map[string]Value, error) {
	body, err := c.post(ctx, refs, false)
	if err != nil {
		return nil, err
	}
	var ans struct {
		Values map[string]json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(body, &ans); err != nil || ans.Values == nil {
		return nil, errors.New("unexpected answer from the server (no values)")
	}
	out := make(map[string]Value, len(refs))
	for _, ref := range refs {
		raw, ok := ans.Values[ref]
		if !ok {
			return nil, errors.New("the server did not answer for every reference; nothing was used")
		}
		v, err := decodeValue(raw)
		if err != nil {
			return nil, err
		}
		out[ref] = v
	}
	return out, nil
}

func decodeValue(raw json.RawMessage) (Value, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return Value{}, errors.New("unexpected answer from the server (empty value)")
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return Value{}, errors.New("unexpected answer from the server (bad string)")
		}
		return Value{String: s}, nil
	case '{':
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			return Value{}, errors.New("unexpected answer from the server (bad object)")
		}
		if m == nil {
			m = map[string]string{}
		}
		return Value{Fields: m, IsObject: true}, nil
	}
	return Value{}, errors.New("unexpected answer from the server (a value is neither text nor an object)")
}

// Check asks whether each ref would resolve for this key. No value comes back
// and no use of the key is consumed.
func (c *Client) Check(ctx context.Context, refs []string) ([]CheckItem, error) {
	body, err := c.post(ctx, refs, true)
	if err != nil {
		return nil, err
	}
	var ans struct {
		Items []CheckItem `json:"items"`
	}
	if err := json.Unmarshal(body, &ans); err != nil || ans.Items == nil {
		return nil, errors.New("unexpected answer from the server (no items)")
	}
	return ans.Items, nil
}

func (c *Client) post(ctx context.Context, refs []string, check bool) ([]byte, error) {
	payload, err := json.Marshal(struct {
		Refs  []string `json:"refs"`
		Check bool     `json:"check"`
	}{Refs: refs, Check: check})
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxRequestBytes {
		return nil, fmt.Errorf("the request is larger than the server accepts (%d bytes): use fewer or shorter references", MaxRequestBytes)
	}

	reply, err := c.send(ctx, http.MethodPost, fetchPath, nil, payload)
	if err != nil {
		return nil, err
	}
	if reply.Status == http.StatusOK {
		c.noteKeyExpiry(reply.Header)
		return reply.Body, nil
	}
	return nil, apiError(reply.Status, reply.Header, reply.Body, fetchFallbacks)
}

// reply is one answer from the API: status, headers and the (size-capped) body.
type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

// send makes one authenticated request and reads the answer. A JSON payload is sent when it is not nil; query
// is added to the URL. Redirects are never followed. Errors carry the address, never a header or a body.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, payload []byte) (*reply, error) {
	return doRequest(ctx, c.http, c.base, c.token, maxAnswerBytes, method, path, query, payload)
}

// doRequest is the one place a request is made and its answer read, for the client that holds an access key and the
// one that does not. bearer is sent as the Authorization header unless it is empty. The answer is read up to
// maxBytes and no further.
func doRequest(ctx context.Context, hc *http.Client, base *url.URL, bearer string, maxBytes int, method, path string, query url.Values, payload []byte) (*reply, error) {
	u := *base
	u.Path += path
	u.RawQuery = query.Encode()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := hc.Do(req)
	if err != nil {
		// url.Error prints the URL, never a header or a body.
		return nil, fmt.Errorf("cannot reach the API at %s: %w", base.Redacted(), unwrapURLError(err))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, errors.New("could not read the answer from the server")
	}
	if len(raw) > maxBytes {
		return nil, errors.New("the answer from the server is larger than expected; nothing was used")
	}
	return &reply{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// apiError builds the error for a non-success answer. fallbacks supplies the sentence for a code or a status when
// the server sent none of its own.
func apiError(status int, header http.Header, body []byte, fallbacks fallbackSet) *APIError {
	e := &APIError{Status: status}
	var ans struct {
		Error       string   `json:"error"`
		Message     string   `json:"message"`
		Description string   `json:"error_description"` // the RFC 8628 spelling, used by the device routes
		Rooms       []string `json:"rooms"`
	}
	if json.Unmarshal(body, &ans) == nil {
		e.Code = cleanText(ans.Error, 40)
		e.Message = cleanText(ans.Message, 300)
		if e.Message == "" {
			e.Message = cleanText(ans.Description, 300)
		}
		for _, r := range ans.Rooms {
			switch r {
			case "my", "project", "workspace":
				e.Rooms = append(e.Rooms, r)
			}
		}
	}
	if ra := strings.TrimSpace(header.Get("Retry-After")); ra != "" && len(ra) <= 6 && isDigits(ra) {
		e.RetryAfter = ra
	}
	if e.Message == "" {
		e.Message = fallbacks.message(e.Code, e.Status)
	}
	return e
}

// fallbackMessages are used only when the server sent no sentence of its own
// (an old server, a proxy error page). They use the same fixed codes as the
// server and, like the server's, never say why a secret was not found.
var fetchMessages = map[string]string{
	"fetch_key_required": "Only an access key can fetch secret values. Sign in with an access key (agentruntime login), not a browser or OAuth session.",
	"missing_scope":      "This access key does not carry the \"Fetch secret values\" scope (secrets:fetch).",
	"fetch_disabled":     "Fetching secret values with access keys is turned off for this workspace.",
	"view_disabled":      "This workspace does not allow secret values to be viewed.",
	"not_found":          "A secret was not found, is not on this key's list, or you may not view it.",
	"ambiguous_ref":      "A name without a room matches more than one room.",
	"uses_exhausted":     "This access key has no uses left.",
	"rate_limited":       "Too many requests for this access key.",
	"bad_ref":            "A secret reference is not valid.",
	"too_large":          "The answer is larger than the 64 KB limit.",
	"audit_failed":       "The request could not be recorded, so nothing was returned. Try again later.",
}

// fallbackSet is the sentences used for one family of routes when the server sent none.
type fallbackSet struct {
	byCode   map[string]string
	byStatus func(status int) string
}

func (f fallbackSet) message(code string, status int) string {
	if m, ok := f.byCode[code]; ok {
		return m
	}
	return f.byStatus(status)
}

var fetchFallbacks = fallbackSet{byCode: fetchMessages, byStatus: fetchStatusMessage}

func fetchStatusMessage(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "The server did not accept the access key (HTTP 401): it may be invalid, expired or revoked. Run `agentruntime login`."
	case http.StatusForbidden:
		return "The access key may not fetch secret values (HTTP 403)."
	case http.StatusMethodNotAllowed, http.StatusNotFound:
		return fmt.Sprintf("The server does not offer secret fetch at this address (HTTP %d): check --api-url.", status)
	}
	return fmt.Sprintf("The server refused the request (HTTP %d).", status)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// cleanText keeps server text short and printable before it is shown.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

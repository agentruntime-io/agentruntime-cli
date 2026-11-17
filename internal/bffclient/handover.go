package bffclient

// One-time hand-over: POST /v1/secrets/handover makes an access key that can fetch ONE secret exactly once and
// expires within 24 hours. The answer carries that key's token. It is the only place the token is ever shown, so it
// is kept out of every string this package can print: HandoverResult hides it from %v, %+v, %#v and from JSON, and
// nothing here puts a token into an error.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const handoverPath = "/v1/secrets/handover"

// Bounds the server applies to a hand-over's lifetime.
const (
	MinHandoverTTLSeconds     = 60
	MaxHandoverTTLSeconds     = 86400
	DefaultHandoverTTLSeconds = 3600
)

// HandoverResult is the one-time key the server made.
type HandoverResult struct {
	Token     string // shown once: only the command that asked for it prints it, and only to a terminal
	ExpiresAt string // RFC 3339, as the server wrote it
	Ref       string // the secret the key can fetch, as the server stored it
	Uses      int    // always 1 for a hand-over
}

// String shows everything but the token.
func (h HandoverResult) String() string {
	return fmt.Sprintf("handover{ref: %q, expires_at: %q, uses: %d, token: <hidden>}", h.Ref, h.ExpiresAt, h.Uses)
}

// GoString keeps %#v from printing the token.
func (h HandoverResult) GoString() string { return h.String() }

// MarshalJSON leaves the token out, so no code path can print it by marshalling the result.
func (h HandoverResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExpiresAt string `json:"expires_at"`
		Ref       string `json:"ref"`
		Uses      int    `json:"uses"`
	}{h.ExpiresAt, h.Ref, h.Uses})
}

// handoverMessages are the sentences used when the server sent none of its own. They use the server's fixed codes.
var handoverMessages = func() map[string]string {
	m := map[string]string{}
	for k, v := range fetchMessages {
		m[k] = v
	}
	m["handover_not_for_ai_clients"] = "A one-time hand-over cannot be made through an AI client. Use the Console, or an access key that may fetch this secret."
	m["not_found"] = "The secret was not found, is not on this key's list, or you may not view it."
	m["bad_ref"] = "The secret reference is not valid. A hand-over needs the room in the name (my/, project/ or workspace/)."
	m["invalid_request"] = "The request is not valid. Check the reference and the lifetime (1 minute to 24 hours)."
	m["issuance_invalid"] = "The server could not make a one-time key for this request."
	m["issuance_expiry_out_of_bounds"] = "The lifetime must be between 1 minute and 24 hours."
	m["rate_limited"] = "Too many hand-overs from this access key. Try again in a minute."
	m["audit_failed"] = "The hand-over could not be recorded, so no key was made. Try again later."
	return m
}()

var handoverFallbacks = fallbackSet{byCode: handoverMessages, byStatus: func(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "The server did not accept the access key (HTTP 401): it may be invalid, expired or revoked. Run `agentruntime login`."
	case http.StatusForbidden:
		return "The access key may not make a one-time hand-over (HTTP 403)."
	case http.StatusMethodNotAllowed, http.StatusNotFound:
		return fmt.Sprintf("The server does not offer one-time hand-over at this address (HTTP %d): check --api-url.", status)
	case http.StatusTooManyRequests:
		return "Too many hand-overs from this access key (HTTP 429). Try again in a minute."
	case http.StatusServiceUnavailable:
		return "The service could not do this right now (HTTP 503); no key was made."
	}
	return fmt.Sprintf("The server refused the request (HTTP %d).", status)
}}

// Handover asks for a key that can fetch ref exactly once and stops working after ttlSeconds. ref must name its
// room (my/, project/ or workspace/); #field is optional.
func (c *Client) Handover(ctx context.Context, ref string, ttlSeconds int) (*HandoverResult, error) {
	payload, err := json.Marshal(struct {
		Ref        string `json:"ref"`
		TTLSeconds int    `json:"ttl_seconds"`
	}{ref, ttlSeconds})
	if err != nil {
		return nil, err
	}
	r, err := c.send(ctx, http.MethodPost, handoverPath, nil, payload)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusCreated && r.Status != http.StatusOK {
		e := apiError(r.Status, r.Header, r.Body, handoverFallbacks)
		// A refusal relayed from a service behind the API can arrive as {"message":"issuance_invalid"} with no code of its own.
		if e.Code == "" {
			if sentence, known := handoverMessages[e.Message]; known {
				e.Code, e.Message = e.Message, sentence
			}
		}
		return nil, e
	}
	var ans struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Ref       string `json:"ref"`
		Uses      int    `json:"uses"`
	}
	if err := json.Unmarshal(r.Body, &ans); err != nil {
		return nil, errors.New("unexpected answer from the server (the hand-over is not readable)")
	}
	if !plausibleToken(ans.Token) {
		return nil, errors.New("unexpected answer from the server (no usable one-time key)")
	}
	return &HandoverResult{Token: ans.Token, ExpiresAt: ans.ExpiresAt, Ref: ans.Ref, Uses: ans.Uses}, nil
}

// plausibleToken accepts an access key as the server writes it, "pat_" and URL-safe base64, and nothing else, so
// text that is not a key (and could carry terminal control codes) is never printed as one.
func plausibleToken(t string) bool {
	const prefix = "pat_"
	if !strings.HasPrefix(t, prefix) || len(t) == len(prefix) || len(t) > 256 {
		return false
	}
	for _, r := range t[len(prefix):] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '=':
		default:
			return false
		}
	}
	return true
}

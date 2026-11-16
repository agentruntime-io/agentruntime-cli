package bffclient

// Secret history, restore, Recently deleted, undelete, delete and settings: the API routes under /v1/vault.
//
// None of these routes returns a secret's value and none of the types below has a place for one: a field the
// server should not send (data, value, previous value) is dropped when the answer is read, so it can neither be
// printed nor returned as JSON. Like the rest of this package, nothing here logs or formats a response body.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	vaultVersionsPath = "/v1/vault/secret/versions"
	vaultRestorePath  = "/v1/vault/secret/restore"
	vaultDeletedPath  = "/v1/vault/secrets/deleted"
	vaultUndeletePath = "/v1/vault/secret/undelete"
	vaultDestroyPath  = "/v1/vault/secret/destroy"
	vaultSettingsPath = "/v1/vault/secret/settings"
	vaultSecretsPath  = "/v1/vault/secrets"
)

// Rights is what the caller may do with one secret.
type Rights struct {
	CanRestore     bool `json:"can_restore"`
	CanEditDetails bool `json:"can_edit_details"`
	CanEditLimits  bool `json:"can_edit_limits"`
}

// Version is one row of a secret's history. Kind is create, update, restore, settings, or unknown for a version
// saved before history was recorded (no author, no key names). The key lists are NAMES compared with the previous
// version, never values. State is current, available, deleted or destroyed.
type Version struct {
	Version         int      `json:"version"`
	WrittenAt       string   `json:"written_at,omitempty"`
	WrittenByUserID string   `json:"written_by_user_id,omitempty"`
	WrittenByName   string   `json:"written_by_name,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	RestoredFrom    int      `json:"restored_from,omitempty"`
	KeysAdded       []string `json:"keys_added,omitempty"`
	KeysChanged     []string `json:"keys_changed,omitempty"`
	KeysRemoved     []string `json:"keys_removed,omitempty"`
	State           string   `json:"state,omitempty"`
}

// Details is a secret's description, labels and keeping rules. KeepVersions nil is the workspace default;
// ExpireAfterSeconds nil is "never".
type Details struct {
	CurrentVersion     int               `json:"current_version"`
	KeepVersions       *int              `json:"keep_versions"`
	ExpireAfterSeconds *int              `json:"expire_after_seconds"`
	ExpiresAt          *string           `json:"expires_at"`
	Description        string            `json:"description,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	Rights             *Rights           `json:"rights,omitempty"`
}

// History is Details plus one row per version still kept, as the API answers it.
type History struct {
	Details
	Versions []Version `json:"versions"`
}

// Restored is the new version a restore wrote.
type Restored struct {
	Path    string `json:"path,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Version int    `json:"version,omitempty"`
}

// Count is a number of versions. The API answers a count; a list of version numbers is read as its length.
type Count int

func (c *Count) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch x := raw.(type) {
	case nil:
		*c = 0
	case float64:
		*c = Count(int(x))
	case []any:
		*c = Count(len(x))
	default:
		return errors.New("versions must be a number")
	}
	return nil
}

// DeletedSecret is one row of Recently deleted. Reason is deleted or expired.
type DeletedSecret struct {
	Path            string `json:"path"`
	DeletedAt       string `json:"deleted_at,omitempty"`
	DeletedByUserID string `json:"deleted_by_user_id,omitempty"`
	DeletedByName   string `json:"deleted_by_name,omitempty"`
	Reason          string `json:"reason,omitempty"`
	OwnerUserID     string `json:"owner_user_id,omitempty"`
	Versions        Count  `json:"versions,omitempty"`
	CanUndelete     bool   `json:"can_undelete"`
	CanDestroy      bool   `json:"can_destroy"`
}

// OptInt is an optional whole-number setting that tells three things apart: left out (keep what is stored), null
// (back to the default, or "never") and a number.
type OptInt struct {
	Set   bool
	Null  bool
	Value int
}

// Number is a setting given as a number.
func Number(n int) OptInt { return OptInt{Set: true, Value: n} }

// Reset is a setting put back to its default (keep-N) or to "never" (auto-expire): sent as JSON null.
func Reset() OptInt { return OptInt{Set: true, Null: true} }

// SettingsChange is what to change. Only what is set is sent; the API leaves the rest as it is.
type SettingsChange struct {
	Description        *string           // "" clears it; nil leaves it
	Labels             map[string]string // replaces ALL labels; an empty map removes them all; nil leaves them
	KeepVersions       OptInt
	ExpireAfterSeconds OptInt
}

// Empty reports whether nothing would be sent.
func (s SettingsChange) Empty() bool {
	return s.Description == nil && s.Labels == nil && !s.KeepVersions.Set && !s.ExpireAfterSeconds.Set
}

// vaultFallbacks are used only when the server sent no sentence of its own (an old server, a proxy error page).
// They use the server's fixed codes.
var vaultFallbacks = fallbackSet{
	byCode: map[string]string{
		"feature_unavailable":        "This workspace's secret store does not support this (Recently deleted, or keeping fewer versions and auto-expire).",
		"deleted_secret_exists":      "A deleted secret with this name is in Recently deleted. Restore it or destroy it permanently first.",
		"confirm_required":           "To delete a secret permanently, send its path as confirmation.",
		"destroy_not_for_ai_clients": "Permanent deletion is not available to AI clients. Use an access key or the Console.",
		"already_current":            "That version is already the current one.",
		"version_unavailable":        "That version is not available any more (it was deleted, destroyed or trimmed).",
		"conflict":                   "The secret changed in the meantime and nothing was written. Read its history again and retry.",
		"audit_failed":               "The action could not be recorded, so nothing was changed. Try again later.",
		"not_found":                  "The secret was not found, or you may not see it.",
		"description_invalid":        "The description is not valid (up to 500 characters, no control characters).",
		"labels_invalid":             "The labels are not valid (up to 10, key a-z 0-9 . _ - up to 40 characters, value up to 100 characters).",
		"expire_invalid":             "Auto-expire must be between 1 hour and 365 days, or never.",
		"rate_limited":               "Too many requests for this access key.",
	},
	byStatus: func(status int) string {
		switch status {
		case http.StatusUnauthorized:
			return "The server did not accept the access key (HTTP 401): it may be invalid, expired or revoked. Run `agentruntime login`."
		case http.StatusForbidden:
			return "The access key may not do this (HTTP 403)."
		case http.StatusNotFound:
			return "The server did not find it (HTTP 404): the secret may not exist or may not be visible to you, or the server may not offer this yet (check --api-url)."
		case http.StatusMethodNotAllowed:
			return "The server does not offer this at this address (HTTP 405): check --api-url."
		case http.StatusConflict:
			return "The request conflicts with the secret's current state (HTTP 409)."
		case http.StatusTooManyRequests:
			return "Too many requests for this access key (HTTP 429)."
		case http.StatusServiceUnavailable:
			return "The service could not do this right now (HTTP 503); nothing was changed."
		}
		return fmt.Sprintf("The server refused the request (HTTP %d).", status)
	},
}

// call sends one request to a vault route. A 2xx answer is returned; anything else becomes an *APIError.
func (c *Client) call(ctx context.Context, method, path string, query url.Values, payload any) (*reply, error) {
	var raw []byte
	if payload != nil {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	r, err := c.send(ctx, method, path, query, raw)
	if err != nil {
		return nil, err
	}
	if r.Status < 200 || r.Status > 299 {
		return nil, apiError(r.Status, r.Header, r.Body, vaultFallbacks)
	}
	return r, nil
}

func scopeQuery(scope, path string) url.Values {
	q := url.Values{}
	q.Set("scope", scope)
	q.Set("path", path)
	return q
}

// History reads a secret's history and settings.
func (c *Client) History(ctx context.Context, scope, path string) (*History, error) {
	r, err := c.call(ctx, http.MethodGet, vaultVersionsPath, scopeQuery(scope, path), nil)
	if err != nil {
		return nil, err
	}
	var h History
	if err := json.Unmarshal(r.Body, &h); err != nil {
		return nil, errors.New("unexpected answer from the server (the history is not readable)")
	}
	return &h, nil
}

// Restore writes version n of a secret back as a new version. The value never reaches the caller.
func (c *Client) Restore(ctx context.Context, scope, path string, version int) (*Restored, error) {
	r, err := c.call(ctx, http.MethodPost, vaultRestorePath, nil, map[string]any{"scope": scope, "path": path, "version": version})
	if err != nil {
		return nil, err
	}
	var out Restored
	if len(bytes.TrimSpace(r.Body)) > 0 {
		if err := json.Unmarshal(r.Body, &out); err != nil {
			return nil, errors.New("unexpected answer from the server (the restore answer is not readable)")
		}
	}
	return &out, nil
}

// Deleted lists a room's Recently deleted secrets. supported is false when the workspace's secret store cannot
// recover deleted secrets (the API answers 404 feature_unavailable).
func (c *Client) Deleted(ctx context.Context, scope string) (items []DeletedSecret, supported bool, err error) {
	q := url.Values{}
	q.Set("scope", scope)
	r, err := c.call(ctx, http.MethodGet, vaultDeletedPath, q, nil)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound && ae.Code == "feature_unavailable" {
			return nil, false, nil
		}
		return nil, false, err
	}
	body := bytes.TrimSpace(r.Body)
	if len(body) > 0 && body[0] == '[' {
		err = json.Unmarshal(body, &items)
	} else {
		var wrapped struct {
			Items []DeletedSecret `json:"items"`
		}
		err = json.Unmarshal(body, &wrapped)
		items = wrapped.Items
	}
	if err != nil {
		return nil, false, errors.New("unexpected answer from the server (the Recently deleted list is not readable)")
	}
	return items, true, nil
}

// Undelete brings a secret back from Recently deleted.
func (c *Client) Undelete(ctx context.Context, scope, path string) error {
	_, err := c.call(ctx, http.MethodPost, vaultUndeletePath, nil, map[string]any{"scope": scope, "path": path})
	return err
}

// Delete deletes a secret. recoverable is true when the API says the secret went to Recently deleted
// (header X-Recoverable: true); false when it is gone for good or the server did not say.
func (c *Client) Delete(ctx context.Context, scope, path string) (recoverable bool, err error) {
	r, err := c.call(ctx, http.MethodDelete, vaultSecretsPath, scopeQuery(scope, path), nil)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Recoverable")), "true"), nil
}

// Destroy deletes a secret for good, every version. confirm must be the path exactly as sent.
func (c *Client) Destroy(ctx context.Context, scope, path, confirm string) error {
	_, err := c.call(ctx, http.MethodPost, vaultDestroyPath, nil, map[string]any{"scope": scope, "path": path, "confirm": confirm})
	return err
}

// UpdateSettings changes a secret's description, labels, number of kept versions and auto-expire, and answers the
// secret's settings. Changing the last two saves one more version, so they apply at once.
func (c *Client) UpdateSettings(ctx context.Context, scope, path string, ch SettingsChange) (*Details, error) {
	if ch.Empty() {
		return nil, errors.New("nothing to change")
	}
	body := map[string]any{"scope": scope, "path": path}
	if ch.Description != nil {
		body["description"] = *ch.Description
	}
	if ch.Labels != nil {
		body["labels"] = ch.Labels
	}
	if ch.KeepVersions.Set {
		body["keep_versions"] = ch.KeepVersions.wire()
	}
	if ch.ExpireAfterSeconds.Set {
		body["expire_after_seconds"] = ch.ExpireAfterSeconds.wire()
	}
	r, err := c.call(ctx, http.MethodPut, vaultSettingsPath, nil, body)
	if err != nil {
		return nil, err
	}
	var d Details
	if len(bytes.TrimSpace(r.Body)) > 0 {
		if err := json.Unmarshal(r.Body, &d); err != nil {
			return nil, errors.New("unexpected answer from the server (the settings answer is not readable)")
		}
	}
	return &d, nil
}

func (o OptInt) wire() any {
	if o.Null {
		return nil
	}
	return o.Value
}

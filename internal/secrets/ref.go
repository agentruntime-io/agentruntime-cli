// Package secrets holds the pure logic behind `agentruntime secrets`: parsing
// secret references, masking fetched values in command output, and rendering
// secret files. Nothing here talks to the network or prints anything.
package secrets

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Rooms a reference can name. A reference with no room is a "short name" that
// the server resolves only when exactly one room holds it.
const (
	RoomMy        = "my"
	RoomProject   = "project"
	RoomWorkspace = "workspace"
)

// Limits the server applies too.
const (
	// MaxRefsPerCall is the most references one fetch call may carry.
	MaxRefsPerCall = 20
	// maxPathLen bounds the part before "#" (a key's list of allowed secrets uses the same cap).
	maxPathLen = 256
	// maxFieldLen bounds the field name after "#".
	maxFieldLen = 128
)

// Ref is a parsed secret reference: [secret:]<room>/<path>[#<field>].
type Ref struct {
	// Room is "my", "project", "workspace", or "" for a short name.
	Room string
	// Path is the room-relative path (for a short name, the whole name).
	Path string
	// Field is the single field asked for, or "" for the whole secret.
	Field string
}

// Whole reports whether the reference names a whole secret (no #field).
func (r Ref) Whole() bool { return r.Field == "" }

// String returns the normalized form that is sent to the server: no "secret:"
// prefix, no surrounding whitespace.
func (r Ref) String() string {
	s := r.Path
	if r.Room != "" {
		s = r.Room + "/" + r.Path
	}
	if r.Field != "" {
		s += "#" + r.Field
	}
	return s
}

// RefError says why a reference is not valid. It never contains the reference
// text itself, because a mistyped reference may be a pasted value.
type RefError struct{ Reason string }

func (e *RefError) Error() string { return "not a valid secret reference: " + e.Reason }

func badRef(format string, args ...any) error {
	return &RefError{Reason: fmt.Sprintf(format, args...)}
}

// Parse validates and normalizes a reference.
//
// Grammar: an optional "secret:" prefix, then "<room>/<path>" where room is my,
// project or workspace, or a short name with no room, then an optional
// "#<field>". A first segment equal to my, project or workspace is always a room
// (write workspace/my/... for a workspace folder called "my"). shared/ cannot be
// fetched yet.
func Parse(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "secret:")
	if !utf8.ValidString(s) {
		return Ref{}, badRef("it is not valid UTF-8 text")
	}

	body, field, hasField := strings.Cut(s, "#")
	if hasField {
		if field == "" {
			return Ref{}, badRef("nothing after '#' (name the field, or leave out '#' for the whole secret)")
		}
		if why := fieldProblem(field); why != "" {
			return Ref{}, badRef("%s", why)
		}
	}

	if body == "" {
		return Ref{}, badRef("it is empty")
	}
	if len(body) > maxPathLen {
		return Ref{}, badRef("the path is longer than %d characters", maxPathLen)
	}
	if strings.Contains(body, `\`) {
		return Ref{}, badRef(`use '/' between folders, not '\'`)
	}
	if hasControl(body) {
		return Ref{}, badRef("the path has control characters")
	}
	if strings.Contains(body, "*") {
		return Ref{}, badRef("wildcards (*) belong in a key's list of allowed secrets, not in a reference")
	}

	segs := strings.Split(body, "/")
	for _, seg := range segs {
		switch seg {
		case "":
			return Ref{}, badRef("a folder name is empty (check for '//' or a leading or trailing '/')")
		case ".", "..":
			return Ref{}, badRef("'.' and '..' are not allowed in a path")
		}
	}

	switch segs[0] {
	case RoomMy, RoomProject, RoomWorkspace:
		if len(segs) < 2 {
			return Ref{}, badRef("name the secret after the room, for example %s/<name>", segs[0])
		}
		return Ref{Room: segs[0], Path: strings.Join(segs[1:], "/"), Field: field}, nil
	case "shared":
		return Ref{}, badRef("shared secrets cannot be fetched yet (for a workspace folder called shared, write workspace/shared/...)")
	}
	return Ref{Path: body, Field: field}, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// fieldProblem says what is wrong with a field name, or returns "" when it is
// acceptable as a reference. It never contains the name.
func fieldProblem(field string) string {
	if utf8.RuneCountInString(field) > maxFieldLen {
		return fmt.Sprintf("the field name is longer than %d characters", maxFieldLen)
	}
	if hasControl(field) {
		return "the field name has control characters"
	}
	return ""
}

var (
	// ErrNoFieldNames means a reference that must name its fields has none:
	// there is no '#'.
	ErrNoFieldNames = errors.New("no field names given")
	// ErrWildcardFields means '*' was used where field names belong.
	ErrWildcardFields = errors.New("'*' cannot stand for the fields of a secret")
)

// NamedRef is a secret together with the fields a person chose to use, written
// REF#F1,F2,... The person names the fields; what the secret itself holds never
// decides which ones are used.
type NamedRef struct {
	// Secret is the secret without any field (Field is empty).
	Secret Ref
	// Names are the field names in the order they were written, without repeats.
	Names []string
}

// Refs returns one single-field reference per named field, in order. These are
// what is sent to the server, so naming N fields costs N references of the
// MaxRefsPerCall allowed in one call.
func (n NamedRef) Refs() []Ref {
	out := make([]Ref, len(n.Names))
	for i, name := range n.Names {
		out[i] = Ref{Room: n.Secret.Room, Path: n.Secret.Path, Field: name}
	}
	return out
}

// ParseNamed validates REF#F1,F2,... Fields are separated by commas, and a field
// name cannot contain a comma. The errors ErrNoFieldNames (no '#' at all) and
// ErrWildcardFields ('*' as a field name) are returned as they are
// so a caller can explain what to write instead. Every other problem is a
// *RefError. Like Parse, no error contains the text it was given: a bad field is
// reported by its position.
func ParseNamed(s string) (NamedRef, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return NamedRef{}, badRef("it is not valid UTF-8 text")
	}
	body, list, hasList := strings.Cut(s, "#")
	secret, err := Parse(body)
	if err != nil {
		return NamedRef{}, err
	}
	if !hasList {
		return NamedRef{}, ErrNoFieldNames
	}
	if list == "" {
		return NamedRef{}, badRef("nothing after '#' (name the fields, for example #DB_USER,DB_PASS)")
	}
	names := strings.Split(list, ",")
	for i, name := range names {
		switch {
		case name == "*":
			return NamedRef{}, ErrWildcardFields
		case name == "":
			return NamedRef{}, badRef("field %d is empty (check for ',,' or a trailing ',')", i+1)
		}
		if why := fieldProblem(name); why != "" {
			return NamedRef{}, badRef("field %d: %s", i+1, why)
		}
		for j := 0; j < i; j++ {
			if names[j] == name {
				return NamedRef{}, badRef("field %d repeats field %d", i+1, j+1)
			}
		}
	}
	return NamedRef{Secret: secret, Names: names}, nil
}

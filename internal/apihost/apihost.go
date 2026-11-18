// Package apihost is the one place that decides what an API host is: whether it is an AgentRuntime host, how it is
// written when it is shown, stored in a profile and compared, and which characters it may have.
//
// The rules exist because a host name is trusted on sight. Unicode case mapping turns some characters into ASCII
// letters (U+0130, the dotted capital I, lower-cases to "i" and the Kelvin sign to "k"), so a host that merely looks
// like an AgentRuntime host could be printed as one while the network dials a different name. Nothing here uses
// Unicode case folding: a host is either plain ASCII, folded by upper-case letter to lower-case letter only, or it
// is refused.
package apihost

import (
	"net/url"
	"strings"
)

// Fold lower-cases the ASCII letters A to Z and leaves every other byte as it is. It is the only case folding used
// on a host, in the address that is dialled, shown, stored and compared.
func Fold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Same reports whether two hosts (or host and port pairs) are the same name once ASCII letter case is ignored.
func Same(a, b string) bool { return Fold(a) == Fold(b) }

// ASCII reports whether s is non-empty and made only of printable ASCII characters (no space, no control, nothing
// above 0x7e). A host that is not ASCII is refused wherever an API address is read, because the name that is dialled
// (its punycode form) would not be the name that is shown.
func ASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Clean reports whether host, without port and brackets, uses only the characters of an ordinary host name or an
// address: letters, digits, dot, hyphen and colon (for an IPv6 literal).
func Clean(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// ExactLoopback reports whether host (no port, no brackets) is exactly one of the three loopback names that may be used
// over plain http, written as they are in lower case: localhost, 127.0.0.1 or ::1. It is the rule every client of the API
// and of Platform MCP applies before it sends an access key over http, and it does not fold case: LOCALHOST is not accepted.
func ExactLoopback(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// Loopback reports whether host (no port, no brackets) is exactly one of the three loopback names a test may use over plain
// http: localhost, 127.0.0.1 or ::1 (ASCII letter case ignored). Nothing else counts as the local machine: not a name
// ending in .localhost, not another 127.x.y.z address, not an alternative way of writing an address.
func Loopback(host string) bool {
	if !Clean(host) {
		return false
	}
	switch Fold(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// EmptyLabel reports whether host has an empty label: a leading dot, or two dots in a row. (A single trailing dot is the
// root label of a fully qualified name; it is not counted here, and Official and Under refuse it on their own.) A name
// with an empty label is not a name: a resolver, or a proxy that is handed the name, may read it as something else.
func EmptyLabel(host string) bool {
	return strings.HasPrefix(host, ".") || strings.Contains(host, "..")
}

// Under reports whether host (no port) is domain or a name under it. host must be Clean and made of non-empty labels:
// a host with any other character, a leading or trailing dot, or two dots in a row is never under a domain. Letter case is folded for the ASCII letters only,
// and domain is written in lower case.
func Under(host, domain string) bool {
	if !Clean(host) || EmptyLabel(host) || strings.HasSuffix(host, ".") {
		return false
	}
	h := Fold(host)
	return h == domain || strings.HasSuffix(h, "."+domain)
}

// Official reports whether host (no port) is an AgentRuntime API host: agentruntime.io or a name under it. The exact
// loopback hosts count too, so the CLI can be tried against a server on this machine. A host with any character
// outside Clean is never official, whatever it would turn into under another case mapping; neither is a name with a
// trailing dot.
func Official(host string) bool {
	return Loopback(host) || Under(host, "agentruntime.io")
}

// Authority is the host of u as it is dialled, shown, stored and compared: ASCII letters in lower case, an IPv6
// address in brackets, and the port only when it is not the default one for the scheme. It is empty when the host is
// not ASCII.
func Authority(u *url.URL) string {
	host := u.Hostname()
	if !ASCII(host) {
		return ""
	}
	host = Fold(host)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	switch port := u.Port(); {
	case port == "", port == "443" && u.Scheme == "https", port == "80" && u.Scheme == "http":
		return host
	default:
		return host + ":" + port
	}
}

// AuthorityOf parses address and returns its Authority. It is empty when the address cannot be parsed or its host is
// not ASCII.
func AuthorityOf(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return Authority(u)
}

// Display writes a host for a message in a form that cannot pass for another name: plain ASCII is shown as it is, and
// every other character as \uXXXX (or \UXXXXXXXX), so a lookalike shows up as one.
func Display(host string) string {
	var sb strings.Builder
	for _, r := range host {
		switch {
		case r >= 0x21 && r <= 0x7e:
			sb.WriteRune(r)
		case r > 0xffff:
			sb.WriteString(`\U`)
			sb.WriteString(hex(uint32(r), 8))
		default:
			sb.WriteString(`\u`)
			sb.WriteString(hex(uint32(r), 4))
		}
	}
	return sb.String()
}

func hex(v uint32, width int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = digits[v&0xf]
		v >>= 4
	}
	return string(out)
}

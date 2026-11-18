package ghactions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every token below is fake.
const (
	fakeRequestToken = "FAKE-request_token-CANARY-0123456789abcdef"
	fakeJWT          = "eyJhbGciOiJSUzI1NiJ9.eyJGQUtFLWNhbmFyeSI6IkNBTkFSWS1PSURDLUpXVCJ9.FAKE-signature_0123456789"
	bodyCanary       = "BODY-TEXT-CANARY-do-not-print"
)

func TestValidateRequestURL(t *testing.T) {
	good := []string{
		"https://pipelines.actions.githubusercontent.com/abc/_apis/distributedtask/hubs/Actions/plans/p/jobs/j/idtoken?api-version=2.0",
		"https://run-actions-1-azure-eastus.actions.githubusercontent.com/x?api-version=2.0",
		"https://actions.githubusercontent.com/x",
		"https://github.com/x",
		"HTTPS://GITHUB.COM/x",
		"https://Pipelines.Actions.GitHubUserContent.com/x",
		"https://github.com:443/x",
		"  https://github.com/x  ",
		// the exact loopback hosts, over either scheme, on any port: what lets a test stand in for GitHub
		"http://localhost:8080/x", "http://127.0.0.1:9/x", "http://[::1]:9/x", "https://localhost/x", "https://127.0.0.1:8443/x",
	}
	for _, raw := range good {
		if _, err := ValidateRequestURL(raw); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
	bad := []string{
		"", " ", "github.com/x", "//github.com/x", "/x", "https:github.com", "https:///x", "https://",
		// plain http, also to GitHub
		"http://github.com/x", "http://pipelines.actions.githubusercontent.com/x",
		// other hosts, and hosts that only look like GitHub's
		"https://evil.example/x", "https://github.com.evil.example/x", "https://evilgithub.com/x", "https://notactions.githubusercontent.com/x",
		"https://githubusercontent.com/x", "https://raw.githubusercontent.com/x", "https://api.github.com/x", "https://gist.github.com/x",
		"https://actions.githubusercontent.com.evil.example/x", "https://evil.example/actions.githubusercontent.com",
		"https://evil.example/?https://github.com/", "https://evil.example#@github.com", "https://github.com.evil.example:443/x",
		// credentials, ports, fragments, a trailing dot
		"https://user:pw@github.com/x", "https://github.com@evil.example/x", "https://github.com:8443/x", "https://github.com:80/x",
		"https://github.com./x", "https://github.com/x#frag", "https://:@github.com/x",
		// other schemes
		"ftp://github.com/x", "javascript:alert(1)", "file:///etc/passwd", "wss://github.com/x",
		// white space, control characters, backslashes, percent-encoded host, non-ASCII
		"https://github.com/x y", "https://github.com/x\ny", "https://github.com/x\\y", "https://github.com/\x00", "https://github.com/\tx",
		`https://github\.com/x`, `https://evil.example\@github.com/x`, `https://evil.example\.github.com/x`, "https://github%2ecom/x", "https://github%2Ecom/x",
		"https://g\u00efthub.com/x", "https://github\u2024com/x", "https://\u212Aithub.com/x", "https://github.com/\u00e9",
		// U+0130 (a capital I with a dot) lower-cases to a plain i in Go: the host would read as github.com, while the request goes elsewhere
		"https://G\u0130THUB.COM/x", "https://github.com\u2215evil.example/x",
		// loopback look-alikes
		"http://127.0.0.2/x", "http://localhost.evil.example/x", "http://foo.localhost/x", "http://[::ffff:127.0.0.1]/x", "http://0.0.0.0/x",
		"http://2130706433/x", "http://127.1/x", "http://127.0.0.1.evil.example/x", "https://localhost.github.com.evil.example/x",
	}
	for _, raw := range bad {
		if u, err := ValidateRequestURL(raw); err == nil {
			t.Errorf("%q accepted as %v", raw, u)
		} else if !errors.Is(err, ErrBadRequestURL) {
			t.Errorf("%q: error %v is not ErrBadRequestURL", raw, err)
		}
	}
	// A refusal says nothing about the address it refused.
	_, err := ValidateRequestURL("https://secret-looking-host-CANARY.evil.example/x?token=CANARY")
	if err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Errorf("the error repeats the address: %v", err)
	}
}

func TestValidateAudience(t *testing.T) {
	for _, a := range []string{"x", "https://api.example.test/workload", "a?b=c&d=e", strings.Repeat("a", MaxAudienceBytes), "urn:example:ci/1"} {
		if err := ValidateAudience(a); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	for _, a := range []string{"", " ", "a b", "a\tb", "a\nb", "a\x00b", "a\x7fb", "café", strings.Repeat("a", MaxAudienceBytes+1)} {
		if err := ValidateAudience(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestNewChecksTheRequestToken(t *testing.T) {
	if _, err := New("https://github.com/x", fakeRequestToken); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"", "  ", "a b", "a\nb", "a\x00b", "café", strings.Repeat("a", maxRequestTokenBytes+1)} {
		if _, err := New("https://github.com/x", tok); !errors.Is(err, ErrBadRequestToken) {
			t.Errorf("request token %q: %v", tok, err)
		}
	}
	if _, err := New("https://evil.example/x", fakeRequestToken); !errors.Is(err, ErrBadRequestURL) {
		t.Errorf("a bad address: %v", err)
	}
}

func TestTheRequesterNeverPrintsItsRequestToken(t *testing.T) {
	r, err := New("http://127.0.0.1:1/x", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{r, *r, &r} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if s := fmt.Sprintf(f, v); strings.Contains(s, fakeRequestToken) || strings.Contains(s, "CANARY") {
				t.Errorf("%s of %T prints the request token: %s", f, v, s)
			}
		}
	}
}

func TestTheRequestHasATimeoutAndFollowsNoRedirect(t *testing.T) {
	r, err := New("http://127.0.0.1:1/x", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	if r.http.Timeout <= 0 || r.http.Timeout > time.Minute {
		t.Errorf("request timeout %v", r.http.Timeout)
	}
	if r.http.CheckRedirect == nil || r.http.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("redirects are followed")
	}
}

// fakeGitHub answers the identity-token request and records what it got.
type fakeGitHub struct {
	*httptest.Server
	mu    sync.Mutex
	calls []*http.Request
	reply func(w http.ResponseWriter, r *http.Request)
}

func newFakeGitHub(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{reply: reply}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.calls = append(g.calls, r.Clone(context.Background()))
		g.mu.Unlock()
		g.reply(w, r)
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitHub) hits() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

func answerJSON(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func goodAnswer() string { return `{"count":1,"value":"` + fakeJWT + `"}` }

func TestIDTokenAsksTheWayGitHubExpects(t *testing.T) {
	g := newFakeGitHub(t, answerJSON(goodAnswer()))
	r, err := New(g.URL+"/_apis/idtoken?api-version=2.0", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.IDToken(context.Background(), "https://api.example.test/workload")
	if err != nil || tok != fakeJWT {
		t.Fatalf("token %q err %v", tok, err)
	}
	if g.hits() != 1 {
		t.Fatalf("%d requests", g.hits())
	}
	c := g.calls[0]
	if c.Method != http.MethodGet || c.URL.Path != "/_apis/idtoken" {
		t.Errorf("request %s %s", c.Method, c.URL.Path)
	}
	if got := c.Header.Get("Authorization"); got != "Bearer "+fakeRequestToken {
		t.Errorf("Authorization %q", got)
	}
	if got := c.Header.Get("Accept"); got != "application/json; api-version=2.0" {
		t.Errorf("Accept %q", got)
	}
	if c.Header.Get("Cookie") != "" || c.ContentLength > 0 {
		t.Errorf("cookie %q, body length %d", c.Header.Get("Cookie"), c.ContentLength)
	}
	q := c.URL.Query()
	if len(q) != 2 || q.Get("api-version") != "2.0" || q.Get("audience") != "https://api.example.test/workload" {
		t.Errorf("query %v", q)
	}
}

func TestIDTokenSendsTheAudienceAsOneParameterWhatEverItHolds(t *testing.T) {
	g := newFakeGitHub(t, answerJSON(goodAnswer()))
	r, err := New(g.URL+"/x?api-version=2.0", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	aud := "https://api.example.test/w?a=b&audience=other&api-version=9#frag%20x"
	if _, err := r.IDToken(context.Background(), aud); err != nil {
		t.Fatal(err)
	}
	q := g.calls[0].URL.Query()
	if got := q["audience"]; len(got) != 1 || got[0] != aud {
		t.Errorf("audience parameter %q, want %q once", got, aud)
	}
	if got := q["api-version"]; len(got) != 1 || got[0] != "2.0" {
		t.Errorf("api-version %q", got)
	}
	if len(q) != 2 {
		t.Errorf("query %v: the audience added a parameter", q)
	}
	// An audience that is not valid is refused before anything is sent.
	before := g.hits()
	for _, bad := range []string{"", "a b", "a\nb"} {
		if _, err := r.IDToken(context.Background(), bad); err == nil {
			t.Errorf("audience %q accepted", bad)
		}
	}
	if g.hits() != before {
		t.Error("a request was sent for a bad audience")
	}
}

func TestIDTokenDoesNotFollowARedirectAndNeverSendsTheRequestTokenOn(t *testing.T) {
	target := newFakeGitHub(t, answerJSON(goodAnswer()))
	g := newFakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	})
	r, err := New(g.URL+"/x", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.IDToken(context.Background(), "a")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusFound || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("error %v", err)
	}
	if target.hits() != 0 {
		t.Error("the redirect was followed")
	}
	if strings.Contains(err.Error(), fakeRequestToken) || strings.Contains(err.Error(), target.URL) {
		t.Errorf("the error repeats the token or the target: %v", err)
	}
}

func TestIDTokenStatusesAreFixedSentences(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{401, "id-token: write"}, {403, "id-token: write"}, {404, "did not give an identity token (HTTP 404)"},
		{429, "Run the step again"}, {500, "Run the step again"}, {503, "Run the step again"}, {418, "(HTTP 418)"},
	}
	for _, c := range cases {
		g := newFakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(`{"message":"` + bodyCanary + `","value":"` + fakeJWT + `"}`))
		})
		r, _ := New(g.URL+"/x", fakeRequestToken)
		tok, err := r.IDToken(context.Background(), "a")
		var se *StatusError
		if tok != "" || !errors.As(err, &se) || se.Status != c.status {
			t.Errorf("%d: token %q, error %v", c.status, tok, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d: %q lacks %q", c.status, err, c.want)
		}
		for _, secret := range []string{bodyCanary, fakeJWT, fakeRequestToken} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%d: the error carries %.12s…", c.status, secret)
			}
		}
	}
}

func TestIDTokenRefusesAnAnswerWithoutAUsableToken(t *testing.T) {
	long := strings.Repeat("a", MaxTokenBytes)
	bodies := map[string]string{
		"not json": "<html>" + bodyCanary + "</html>", "empty": "", "an array": "[]", "an object without value": `{"count":1}`,
		"empty value": `{"value":""}`, "a number": `{"value":123}`, "null": `{"value":null}`,
		"one part": `{"value":"abcdefghijklmnopqrstuvwxyz"}`, "two parts": `{"value":"abcdefghijklmnop.abcdefghijklmnop"}`,
		"four parts":    `{"value":"abcdefghij.abcdefghij.abcdefghij.abcdefghij"}`,
		"an empty part": `{"value":"abcdefghijklmnop..abcdefghijklmnop"}`, "a space": `{"value":"abcdefghij.abcdefghij abc.abcdefghij"}`,
		"a newline": `{"value":"abcdefghij.abcdefghij\nEVIL.abcdefghij"}`, "an escape": `{"value":"abcdefghij.abcdefghij\u001b[31m.abcdefghij"}`,
		"padding": `{"value":"abcdefghij.abcdefghij==.abcdefghij"}`, "a plus sign": `{"value":"abcdefghij.abcdef+ghij.abcdefghij"}`,
		"too short": `{"value":"a.b.c"}`, "too long": `{"value":"` + long + `.b.c"}`,
		"a huge answer": `{"value":"` + fakeJWT + `","pad":"` + strings.Repeat("x", 70*1024) + `"}`,
	}
	for name, body := range bodies {
		g := newFakeGitHub(t, answerJSON(body))
		r, _ := New(g.URL+"/x", fakeRequestToken)
		tok, err := r.IDToken(context.Background(), "a")
		if err == nil || tok != "" {
			t.Errorf("%s: token %.20q err %v", name, tok, err)
			continue
		}
		if !errors.Is(err, ErrBadAnswer) {
			t.Errorf("%s: error %v is not ErrBadAnswer", name, err)
		}
		if strings.Contains(err.Error(), bodyCanary) || strings.Contains(err.Error(), "EVIL") {
			t.Errorf("%s: the error repeats the answer: %v", name, err)
		}
	}
}

// The answer is read up to its cap and no further: a server that keeps sending does not make the client read it all,
// and the sizes are written out here, not taken from the code's own constants.
func TestIDTokenStopsReadingAtItsCap(t *testing.T) {
	const total = 128 << 20
	var written int64
	done := make(chan struct{})
	g := newFakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat("x", 32*1024))
		_, _ = w.Write([]byte(`{"value":"`))
		for atomic.LoadInt64(&written) < total {
			n, err := w.Write(chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	r, _ := New(g.URL+"/x", fakeRequestToken)
	if _, err := r.IDToken(context.Background(), "a"); !errors.Is(err, ErrBadAnswer) {
		t.Fatalf("error %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the server never noticed that the client had stopped reading")
	}
	if got := atomic.LoadInt64(&written); got > total/2 {
		t.Errorf("the server sent %d of %d bytes: the client kept reading past its cap", got, int64(total))
	}
}

func TestIDTokenStopsWhenTheContextEnds(t *testing.T) {
	release := make(chan struct{})
	g := newFakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	r, _ := New(g.URL+"/x", fakeRequestToken)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.IDToken(ctx, "a")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("error %v after %v", err, time.Since(start))
	}
}

func TestIDTokenNetworkErrorsCarryNeitherTheTokenNorTheAddress(t *testing.T) {
	g := newFakeGitHub(t, answerJSON(goodAnswer()))
	addr := g.URL
	g.Close()
	r, _ := New(addr+"/secret-path-CANARY?api-version=2.0", fakeRequestToken)
	_, err := r.IDToken(context.Background(), "a")
	if err == nil {
		t.Fatal("no error")
	}
	for _, s := range []string{fakeRequestToken, "secret-path-CANARY", "api-version"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the error carries %q: %v", s, err)
		}
	}
	if u, perr := url.Parse(addr); perr == nil && strings.Contains(err.Error(), "http://") {
		t.Errorf("the error carries an address (%s): %v", u.Host, err)
	}
}

func TestPlausibleJWT(t *testing.T) {
	for _, s := range []string{fakeJWT, "aaaaaaaa.bbbbbbbb.cccccccc", "A-_9aaaaaaa.B-_9bbbbbbb.C-_9ccccccc"} {
		if !plausibleJWT(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "a.b.c", "aaaaaaaa.bbbbbbbb", "aaaaaaaa.bbbbbbbb.cccccccc.dddddddd", "aaaaaaaa..cccccccc", ".bbbbbbbb.cccccccc", "aaaaaaaa.bbbbbbbb.",
		"aaaaaaaa.bbbbbbbb.cccc cccc", "aaaaaaaa.bbbb\nbbbb.cccccccc", "aaaaaaaa.bbbbbbbb.ccccc=", "aaaaaaaa.bbbbbbbb.cc/cccc", "aaaaaaaa.bbbbbbbb.ccécccc"} {
		if plausibleJWT(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// ---- the host that is checked is the host that is dialled ---------------------------------------------------------

// Lookalike characters are built from code points, so that no confusable character sits in this file.
func cp(r ...rune) string { return string(r) }

// refusedAddresses are addresses the request token must never be sent to. The percent-encoded forms are the ones a
// check on the raw bytes alone lets through: url.Parse decodes them, and a Unicode case mapping then turns the capital
// I with a dot (U+0130) into a plain i and the Kelvin sign (U+212A) into a k.
func refusedAddresses() map[string]string {
	return map[string]string{
		"https://g%C4%B0thub.com/x":                                           "an escaped U+0130 in github.com (the reported bypass)",
		"https://actions.g%C4%B0thubusercontent.com/x":                        "an escaped U+0130 in actions.githubusercontent.com (the reported bypass)",
		"https://pipelines.actions.g%C4%B0thubusercontent.com/x":              "an escaped U+0130 under actions.githubusercontent.com",
		"https://action%C5%BF.githubusercontent.com/x":                        "an escaped long s",
		"https://github%E2%84%AA.com/x":                                       "an escaped Kelvin sign",
		"https://%E2%84%AAithub.com/x":                                        "an escaped Kelvin sign first",
		"https://%EF%BD%87ithub.com/x":                                        "an escaped full-width g",
		"https://github.com%EF%BC%8Eevil.example/x":                           "an escaped full-width dot",
		"https://g%25C4%25B0thub.com/x":                                       "a doubly encoded U+0130",
		"https://github.com%252f.evil.example/x":                              "a doubly encoded slash",
		"https://github%2ecom/x":                                              "an escaped dot",
		"https://%67ithub.com/x":                                              "an escaped plain g",
		"https://github.com%40evil.example/x":                                 "an escaped @",
		"https://github.com%2f@evil.example/x":                                "an escaped slash and a user name",
		"https://github.com%00/x":                                             "an escaped NUL",
		"https://github.com./x":                                               "a trailing dot",
		"https://actions.githubusercontent.com./x":                            "a trailing dot",
		"https://github.com@evil.example/x":                                   "a user name that is github.com",
		"https://user:pw@github.com/x":                                        "a user name",
		"https://github.com:8443/x":                                           "another port",
		"https://github.com:0443/x":                                           "a port that is not written 443",
		"https://github.com:443@evil.example/x":                               "a user name that looks like a port",
		"https://[2001:db8::1]/x":                                             "an IPv6 address that is not loopback",
		"https://github.com_.evil.example/x":                                  "an underscore",
		"http://github.com/x":                                                 "plain http",
		cp(0x68, 0x74, 0x74, 0x70, 0x73) + "://" + cp(0x130) + "github.com/x": "U+0130 written out",
		"https://g" + cp(0x130) + "thub.com/x":                                "U+0130 written out in the host",
		"https://actions.g" + cp(0x130) + "thubusercontent.com/x":             "U+0130 written out in the other host",
		"https://" + cp(0x212A) + "ithub.com/x":                               "a Kelvin sign written out",
		"https://" + cp(0xFF47) + "ithub.com/x":                               "a full-width g written out",
		"https://github" + cp(0x200B) + ".com/x":                              "a zero-width space",
		"https://github.com/x" + cp(0x130):                                    "a non-ASCII character in the path",
	}
}

func TestValidateRequestURLRefusesEscapedAndLookalikeHosts(t *testing.T) {
	for raw, why := range refusedAddresses() {
		if u, err := ValidateRequestURL(raw); err == nil {
			t.Errorf("%q accepted as %v (%s)", raw, u, why)
		} else if !errors.Is(err, ErrBadRequestURL) {
			t.Errorf("%q: error %v is not ErrBadRequestURL", raw, err)
		}
	}
}

func TestEscapesOutsideTheHostAreStillFine(t *testing.T) {
	// GitHub's own addresses carry a query; only the host part is held to the strict rule.
	for _, raw := range []string{
		"https://github.com/a%20b?x=%41&y=%C4%B0",
		"https://pipelines.actions.githubusercontent.com/p/%7Bid%7D/idtoken?api-version=2.0&audience=https%3A%2F%2Fexample",
	} {
		if _, err := ValidateRequestURL(raw); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
}

func TestTheAcceptedHostIsFoldedAndIsTheOneThatIsDialled(t *testing.T) {
	for _, c := range []struct{ raw, host, authority string }{
		{"HTTPS://GITHUB.COM/x", "github.com", "github.com"},
		{"https://Pipelines.Actions.GitHubUserContent.com/x?y=1", "pipelines.actions.githubusercontent.com", "pipelines.actions.githubusercontent.com"},
		{"https://GitHub.Com:443/x", "github.com", "github.com"},
		{"http://LOCALHOST:8080/x", "localhost:8080", "localhost:8080"},
	} {
		u, err := ValidateRequestURL(c.raw)
		if err != nil {
			t.Errorf("%q refused: %v", c.raw, err)
			continue
		}
		wantHost := c.host
		if strings.Contains(c.raw, ":443") {
			wantHost += ":443"
		}
		if u.Host != wantHost {
			t.Errorf("%q: the returned address has host %q, want %q", c.raw, u.Host, wantHost)
		}
		if strings.ToLower(u.Host) != u.Host {
			t.Errorf("%q: the host is not folded: %q", c.raw, u.Host)
		}
	}
}

// network replaces the transport a client uses by default with a recorder that never connects.
type network struct {
	mu   sync.Mutex
	seen []string // the host of each request
	auth []string
}

func (n *network) RoundTrip(req *http.Request) (*http.Response, error) {
	n.mu.Lock()
	n.seen = append(n.seen, req.URL.Host)
	n.auth = append(n.auth, req.Header.Get("Authorization"))
	n.mu.Unlock()
	return nil, errors.New("recorded: no network in tests")
}

func recordNetwork(t *testing.T) *network {
	t.Helper()
	n := &network{}
	orig := http.DefaultTransport
	http.DefaultTransport = n
	t.Cleanup(func() { http.DefaultTransport = orig })
	return n
}

func TestNothingIsDialledForARefusedAddress(t *testing.T) {
	net := recordNetwork(t)
	for raw, why := range refusedAddresses() {
		r, err := New(raw, fakeRequestToken)
		if err == nil {
			t.Errorf("%q gave a requester (%s)", raw, why)
			_, _ = r.IDToken(context.Background(), "aud")
		}
	}
	if len(net.seen) != 0 {
		t.Errorf("requests were made for refused addresses: %v", net.seen)
	}
}

func TestTheCheckedHostIsTheOneTheRequestGoesTo(t *testing.T) {
	net := recordNetwork(t)
	r, err := New("HTTPS://Pipelines.Actions.GitHubUserContent.COM/x/_apis/idtoken?api-version=2.0", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Authority(); got != "pipelines.actions.githubusercontent.com" {
		t.Errorf("Authority() = %q", got)
	}
	_, _ = r.IDToken(context.Background(), "aud")
	if len(net.seen) != 1 || net.seen[0] != "pipelines.actions.githubusercontent.com" || net.seen[0] != r.Authority() {
		t.Errorf("requests %v, want one to %q", net.seen, r.Authority())
	}

	// With the default port written out, the request carries it and the authority (what is shown and compared) does not.
	net2 := recordNetwork(t)
	r2, err := New("https://GitHub.com:443/x", fakeRequestToken)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r2.IDToken(context.Background(), "aud")
	if r2.Authority() != "github.com" || len(net2.seen) != 1 || net2.seen[0] != "github.com:443" {
		t.Errorf("authority %q, requests %v", r2.Authority(), net2.seen)
	}
	if len(net.auth) != 1 || net.auth[0] != "Bearer "+fakeRequestToken {
		t.Errorf("authorization %v", net.auth)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// callbackPath is the only redirect path the server accepts.
const callbackPath = "/callback"

type callbackResult struct {
	code string
	err  error
}

// loopbackFlow runs the authorization code grant with PKCE and an RFC 8252
// loopback redirect on 127.0.0.1.
func loopbackFlow(ctx context.Context, o *Options, md *Metadata, cfg *oauth2.Config, key *ecdsa.PrivateKey, params []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	// The redirect URI uses the 127.0.0.1 literal rather than localhost, as
	// recommended by RFC 8252 section 7.3.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not start the local login listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	cfg.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath)

	state := randomString(32)
	verifier := oauth2.GenerateVerifier()
	authParams := append(append([]oauth2.AuthCodeOption{}, params...), oauth2.S256ChallengeOption(verifier))
	authURL := cfg.AuthCodeURL(state, authParams...)

	// The manual URL is the same authorization request, but the server sends
	// the browser to a page that shows the code to paste into the terminal.
	// It works from a browser on any machine. Pasting needs a terminal.
	var manualCfg *oauth2.Config
	var manualURL string
	if md.ManualRedirectURI != "" && o.Interactive {
		c := *cfg
		c.RedirectURL = md.ManualRedirectURI
		manualCfg = &c
		manualURL = c.AuthCodeURL(state, authParams...)
	}

	results := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res := validateCallback(r.URL.Query(), state, md.Issuer, md.AuthorizationResponseIssParameterSupported)
		if res.err != nil {
			writeResultPage(w, http.StatusBadRequest, false, res.err.Error())
		} else {
			writeResultPage(w, http.StatusOK, true, "")
		}
		select {
		case results <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	// The loopback URL only works in a browser on this machine, so it is not
	// shown to the user.
	log.Debug().Str("url", authURL).Msg("browser login authorize URL")
	openErr := o.OpenBrowser(authURL)
	if openErr != nil && manualCfg == nil {
		// Login switches to the device flow.
		return nil, &browserNotOpenedError{err: openErr}
	}

	pr := newProgress(o.Out, o.Interactive)
	timer := time.NewTimer(o.LoopbackTimeout)
	defer timer.Stop()

	var code string
	exchangeCfg := cfg
	if manualCfg == nil {
		pr.Println("Opening your browser to log in…")
		stop := pr.Spin("Waiting for authorization in the browser...")
		code, err = waitForCallback(ctx, results, timer.C)
		stop()
	} else {
		if openErr != nil {
			log.Debug().Err(openErr).Msg("could not open a browser")
		}
		var pasted bool
		code, pasted, err = waitForCallbackOrPaste(ctx, o.In, pr, results, timer.C, manualPrompt{
			url:    manualURL,
			opened: openErr == nil,
			state:  state,
			issuer: md.Issuer,
			maxBad: maxBadPastes,
		})
		if pasted {
			// The token request must name the redirect URI of the
			// authorization request that issued the code.
			exchangeCfg = manualCfg
		}
	}
	if err != nil {
		return nil, err
	}

	proof, err := NewKeyProof(key, cfg.Endpoint.TokenURL, code, time.Now(), 5*time.Minute)
	if err != nil {
		return nil, err
	}
	tok, err := exchangeCfg.Exchange(ctx, code,
		oauth2.VerifierOption(verifier),
		oauth2.SetAuthURLParam("mondoo_key_proof", proof),
	)
	if err != nil {
		return nil, tokenError(err)
	}
	return tok, nil
}

var errLoopbackTimeout = errors.New("timed out waiting for the browser login to complete")

// waitForCallback waits for the browser to come back to the loopback listener.
func waitForCallback(ctx context.Context, results <-chan callbackResult, timeout <-chan time.Time) (string, error) {
	select {
	case res := <-results:
		return res.code, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timeout:
		return "", errLoopbackTimeout
	}
}

// maxBadPastes is how many pasted codes that do not match the login are
// rejected before the login fails.
const maxBadPastes = 4

const (
	pasteMismatchMsg = "That code doesn't match this login; paste the code shown in the browser"
	pastePromptAuto  = "Paste the code here if the browser doesn't return automatically: "
	pastePrompt      = "Paste the code shown in the browser here: "
)

// manualPrompt describes the manual login shown next to the loopback flow.
type manualPrompt struct {
	url    string // the authorize URL with the manual redirect URI
	opened bool   // whether the browser was opened with the loopback URL
	state  string
	issuer string
	maxBad int
}

// waitForCallbackOrPaste shows the manual login URL and waits for whichever
// comes first: the browser returning to the loopback listener, or the user
// pasting the code the manual redirect page shows. pasted reports which one
// produced the code.
//
// The terminal stays in its normal line mode, so the pasted code is echoed
// and nothing needs restoring. The line reader is not cancelled when the
// loopback wins; the process exits right after the login.
func waitForCallbackOrPaste(ctx context.Context, in io.Reader, pr *progress, results <-chan callbackResult, timeout <-chan time.Time, m manualPrompt) (code string, pasted bool, err error) {
	prompt := pastePrompt
	if m.opened {
		pr.Println("Opening your browser to log in…")
		pr.Println("If the browser doesn't open or is on another machine, open this URL:")
		prompt = pastePromptAuto
	} else {
		pr.Println("Open this URL in a browser to log in:")
	}
	pr.Println("\n  %s\n", m.url)
	pr.Prompt("%s", prompt)

	lines := make(chan string)
	done := make(chan struct{})
	defer close(done)
	go readLines(in, lines, done)

	bad := 0
	for {
		select {
		case res := <-results:
			pr.ClearLine()
			return res.code, false, res.err
		case line, ok := <-lines:
			if !ok {
				// stdin closed: only the browser can complete the login.
				lines = nil
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" {
				pr.Prompt("%s", prompt)
				continue
			}
			res := parsePastedCode(line, m.state, m.issuer)
			if res.err == nil {
				return res.code, true, nil
			}
			log.Debug().Err(res.err).Msg("rejected the pasted code")
			bad++
			if bad >= m.maxBad {
				return "", false, errors.New("the pasted code does not match this login, please try again")
			}
			pr.Println(pasteMismatchMsg)
			pr.Prompt("%s", prompt)
		case <-ctx.Done():
			pr.ClearLine()
			return "", false, ctx.Err()
		case <-timeout:
			pr.ClearLine()
			return "", false, errLoopbackTimeout
		}
	}
}

// readLines sends each line read from in to lines until done is closed, and
// closes lines when in is exhausted.
func readLines(in io.Reader, lines chan<- string, done <-chan struct{}) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		select {
		case lines <- sc.Text():
		case <-done:
			return
		}
	}
	if err := sc.Err(); err != nil {
		log.Debug().Err(err).Msg("stopped reading the pasted code")
	}
	select {
	case <-done:
	default:
		close(lines)
	}
}

// parsePastedCode reads the code the manual redirect page shows,
// "<code>#<state>". The full redirect URL ("...?code=...&state=...") is also
// accepted. The state must be this login's; an iss parameter, when present,
// must name the issuer.
func parsePastedCode(s, state, issuer string) callbackResult {
	if u, err := url.Parse(s); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.RawQuery != "" {
		return validateCallback(u.Query(), state, issuer, false)
	}
	i := strings.LastIndexByte(s, '#')
	if i <= 0 || strings.ContainsAny(s, " \t") {
		return callbackResult{err: errors.New("pasted code is not in the form <code>#<state>")}
	}
	code, gotState := s[:i], s[i+1:]
	return validateCallback(url.Values{"code": {code}, "state": {gotState}}, state, issuer, false)
}

// browserNotOpenedError reports that the browser for the loopback flow could
// not be opened. The local listener is shut down by the time it is returned.
type browserNotOpenedError struct {
	err error
}

func (e *browserNotOpenedError) Error() string {
	return "could not open a browser: " + e.err.Error()
}

func (e *browserNotOpenedError) Unwrap() error { return e.err }

// validateCallback checks the authorization response: state must match, and
// the iss parameter (RFC 9207) must name the expected issuer.
func validateCallback(q url.Values, state, issuer string, issRequired bool) callbackResult {
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
		return callbackResult{err: errors.New("login response has an unexpected state, ignoring it")}
	}
	if iss := q.Get("iss"); iss != "" {
		if !sameIssuer(iss, issuer) {
			return callbackResult{err: fmt.Errorf("login response came from issuer %q, expected %q", iss, issuer)}
		}
	} else if issRequired {
		return callbackResult{err: errors.New("login response is missing the issuer")}
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return callbackResult{err: errors.New("the login request was denied")}
		}
		if d := q.Get("error_description"); d != "" {
			return callbackResult{err: fmt.Errorf("login failed: %s: %s", e, d)}
		}
		return callbackResult{err: fmt.Errorf("login failed: %s", e)}
	}
	code := q.Get("code")
	if code == "" {
		return callbackResult{err: errors.New("login response has no authorization code")}
	}
	return callbackResult{code: code}
}

// resultPage is the page the browser lands on after the login. It is
// self-contained (the local listener may be the only server reachable) and
// html/template escapes the message in the page and the frames in the script.
var resultPage = template.Must(template.New("result").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .OK}}Login complete{{else}}Login not completed{{end}}</title>
<style>
/* Colors from Mondoo's design system */
:root{--canvas:#f7f5f2;--surface:#fbfaf9;--border:color-mix(in srgb,#6d6862 20%,transparent);--text-primary:#050504;--text-secondary:#6d6862;--action:#793f99;--negative:#cf0f2b;--accent:var(--action);--shadow:0 1px 2px rgba(5,5,4,.04),0 4px 16px rgba(5,5,4,.05)}
@media (prefers-color-scheme:dark){:root{--canvas:#04040a;--surface:#1b1b22;--border:color-mix(in srgb,#9494a4 20%,transparent);--text-primary:#fcfcfd;--text-secondary:#9494a4;--action:#b76ed8;--negative:#f8444d;--shadow:none}}
.fail{--accent:var(--negative)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;font-family:"Atkinson Hyperlegible Next",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text-secondary);background:radial-gradient(circle at 50% 50%,color-mix(in srgb,var(--accent) 8%,transparent),transparent 60%) var(--canvas)}
main{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px 40px 36px;max-width:460px;width:100%;text-align:center;box-shadow:var(--shadow);animation:pop .4s ease-out both}
pre{display:inline-block;margin:0 0 20px;text-align:left;font:48px/1.1 "IBM Plex Mono","Fira Code","Cascadia Mono",ui-monospace,monospace;color:var(--accent)}
h1{font:600 24px/1.25 "Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0 0 10px;color:var(--text-primary)}
p{margin:0 0 6px;line-height:1.5;overflow-wrap:anywhere}
@keyframes pop{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (max-width:420px){pre{font-size:36px}main{padding:28px 20px}}
@media (prefers-reduced-motion:reduce){main{animation:none}}
</style>
</head>
<body{{if not .OK}} class="fail"{{end}}><main>
<pre id="cat" aria-hidden="true">{{.Still}}</pre>
{{if .OK}}<h1>You're logged in</h1><p>You can close this tab and return to your terminal.</p>
{{else}}<h1>Login not completed</h1><p>{{.Message}}</p><p>Return to your terminal for details.</p>{{end}}
</main>
<script>
(function(){var f={{.Frames}},i=-1,el=document.getElementById("cat");
if(window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches)return;
setInterval(function(){el.textContent=f[i=(i+1)%f.length]},{{.IntervalMS}})})();
</script>
</body>
</html>
`))

func writeResultPage(w http.ResponseWriter, status int, ok bool, msg string) {
	cat := catLove
	if !ok {
		cat = catCry
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = resultPage.Execute(w, struct {
		OK         bool
		Message    string
		Still      string
		Frames     []string
		IntervalMS int64
	}{ok, capitalizeFirst(msg), cat.joinedStill(), cat.joinedFrames(), catInterval.Milliseconds()})
}

// capitalizeFirst upper-cases the first letter of msg for display, leaving
// the rest untouched.
func capitalizeFirst(msg string) string {
	r, n := utf8.DecodeRuneInString(msg)
	if n == 0 || r == utf8.RuneError {
		return msg
	}
	return string(unicode.ToUpper(r)) + msg[n:]
}

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
	// The mux answers every path but callbackPath with 404; only callbackPath
	// takes part in the login.
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res := validateCallback(r.URL.Query(), state, md.Issuer, md.AuthorizationResponseIssParameterSupported)
		if errors.Is(res.err, errUnexpectedState) {
			// Not a response to this login: show the error page, but keep
			// waiting for the response that belongs to this login.
			log.Debug().Msg("ignoring a login callback with an unexpected state")
			writeResultPage(w, http.StatusBadRequest, false, res.err.Error())
			return
		}
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

// errUnexpectedState is returned for an authorization response whose state is
// not this login's. Such a response does not end the login.
var errUnexpectedState = errors.New("login response has an unexpected state, ignoring it")

// validateCallback checks the authorization response: state must match, and
// the iss parameter (RFC 9207) must name the expected issuer.
func validateCallback(q url.Values, state, issuer string, issRequired bool) callbackResult {
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
		return callbackResult{err: errUnexpectedState}
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
		e = DisplayText(e)
		if d := DisplayText(q.Get("error_description")); d != "" {
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

// mondooLogo is the Mondoo wordmark, drawn in currentColor so the page's text
// color applies. It is static markup, never built from input.
const mondooLogo template.HTML = `<svg class="logo" viewBox="0 0 185 36" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Mondoo">
<circle cx="29.7878" cy="18.5086" r="11.486" fill="currentColor"/>
<path d="M17.3441 7.09822C17.3446 7.09822 17.3451 7.09866 17.3451 7.0992V29.8316C17.3451 29.9637 17.2371 30.0711 17.105 30.0684C10.8723 29.9406 5.85876 24.8479 5.85876 18.5845C5.85882 12.2414 11.001 7.09875 17.3441 7.09822Z" fill="currentColor"/>
<path d="M42.2322 7.09822C42.2316 7.09822 42.2312 7.09866 42.2312 7.0992V29.8316C42.2312 29.9637 42.3392 30.0711 42.4713 30.0684C48.704 29.9406 53.7175 24.8479 53.7175 18.5845C53.7175 12.2414 48.5753 7.09875 42.2322 7.09822Z" fill="currentColor"/>
<path d="M65.1837 10.745C65.2843 10.7406 65.3662 10.8227 65.3662 10.9234V12.6085C66.3401 11.2364 67.8744 10.4187 69.7923 10.4187C72.1833 10.4187 73.807 11.3819 74.6617 13.0744C75.6653 11.439 77.466 10.4187 79.6502 10.4187C83.6928 10.4187 85.7299 12.87 85.7299 16.8113V26.5903H81.5383V17.3951C81.5383 15.2642 80.6538 13.9511 78.5869 13.9511C76.7565 13.9511 75.548 15.1777 75.548 17.6585V26.5903H71.3863V17.2791C71.3863 15.1777 70.5018 13.9511 68.5243 13.9511C66.5467 13.9511 65.396 15.2072 65.396 17.745L65.4196 26.5903H61.2938V14.7688C61.2938 12.6045 63.019 10.8394 65.1837 10.745Z" fill="currentColor"/>
<path d="M87.8544 18.6217C87.8544 14.0671 91.4855 10.4187 96.2654 10.4187C101.045 10.4187 104.706 14.0671 104.706 18.6217C104.706 23.1762 101.075 26.8247 96.2654 26.8247C91.4557 26.8247 87.8544 23.1468 87.8544 18.6217ZM100.664 18.5922C100.664 16.1409 98.7159 14.185 96.2952 14.185C93.8745 14.185 91.9268 16.1409 91.9268 18.5922C91.9268 21.0435 93.8447 22.9994 96.2952 22.9994C98.7457 22.9994 100.664 21.0435 100.664 18.5922Z" fill="currentColor"/>
<path d="M110.829 10.7426C110.829 10.742 110.83 10.7424 110.83 10.7432V12.7264C111.864 11.2953 113.515 10.4205 115.493 10.4205C119.271 10.4205 121.662 12.8719 121.662 16.9881V26.5903H117.5V17.6014C117.5 15.3545 116.407 13.9529 114.253 13.9529C112.335 13.9529 110.858 15.3545 110.858 17.8058V26.5903H106.756V14.7707C106.756 12.546 108.579 10.743 110.828 10.7428C110.828 10.7428 110.829 10.7427 110.829 10.7426Z" fill="currentColor"/>
<path d="M123.653 18.6217C123.653 13.6012 127.312 10.4188 131.386 10.4188C133.481 10.4188 135.222 11.2936 136.315 12.7541V3.59033H140.33V22.5335C140.33 24.7252 138.533 26.5043 136.315 26.5043V24.3439C135.194 25.891 133.393 26.8247 131.326 26.8247C127.401 26.8247 123.653 23.6422 123.653 18.6217ZM136.549 18.5923C136.549 16.141 134.632 14.1556 132.123 14.1556C129.615 14.1556 127.695 16.1115 127.695 18.5923C127.695 21.0731 129.673 23.029 132.123 23.029C134.574 23.029 136.549 21.0436 136.549 18.5923Z" fill="currentColor"/>
<path d="M142.349 18.6217C142.349 14.0671 145.98 10.4187 150.76 10.4187C155.54 10.4187 159.201 14.0671 159.201 18.6217C159.201 23.1762 155.57 26.8247 150.76 26.8247C145.95 26.8247 142.349 23.1468 142.349 18.6217ZM155.158 18.5922C155.158 16.1409 153.211 14.185 150.79 14.185C148.369 14.185 146.421 16.1409 146.421 18.5922C146.421 21.0435 148.339 22.9994 150.79 22.9994C153.24 22.9994 155.158 21.0435 155.158 18.5922Z" fill="currentColor"/>
<path d="M161.202 18.6217C161.202 14.0671 164.833 10.4187 169.613 10.4187C174.393 10.4187 178.054 14.0671 178.054 18.6217C178.054 23.1762 174.423 26.8247 169.613 26.8247C164.804 26.8247 161.202 23.1468 161.202 18.6217ZM174.012 18.5922C174.012 16.1409 172.064 14.185 169.643 14.185C167.222 14.185 165.275 16.1409 165.275 18.5922C165.275 21.0435 167.193 22.9994 169.643 22.9994C172.094 22.9994 174.012 21.0435 174.012 18.5922Z" fill="currentColor"/>
</svg>`

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
.logo{display:block;width:120px;height:auto;margin:0 auto 28px;color:var(--text-primary)}
pre{display:inline-block;margin:0 0 20px;text-align:left;font:48px/1.1 "IBM Plex Mono","Fira Code","Cascadia Mono",ui-monospace,monospace;color:var(--accent)}
h1{font:600 24px/1.25 "Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0 0 10px;color:var(--text-primary)}
p{margin:0 0 6px;line-height:1.5;overflow-wrap:anywhere}
@keyframes pop{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (max-width:420px){pre{font-size:36px}main{padding:28px 20px}}
@media (prefers-reduced-motion:reduce){main{animation:none}}
</style>
</head>
<body{{if not .OK}} class="fail"{{end}}><main>
{{.Logo}}
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
		Logo       template.HTML
	}{ok, capitalizeFirst(msg), cat.joinedStill(), cat.joinedFrames(), catInterval.Milliseconds(), mondooLogo})
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

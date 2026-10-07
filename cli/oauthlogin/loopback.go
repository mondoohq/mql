// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"time"

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
	authURL := cfg.AuthCodeURL(state, append(params, oauth2.S256ChallengeOption(verifier))...)

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

	pr := newProgress(o.Out, o.Interactive)
	pr.Println("Opening your browser to log in. If it does not open, visit this URL:\n\n  %s\n", authURL)
	if err := o.OpenBrowser(authURL); err != nil {
		pr.Println("Could not open a browser; open the URL above manually.")
	}
	stop := pr.Spin("Waiting for authorization in the browser...")

	var res callbackResult
	timer := time.NewTimer(o.LoopbackTimeout)
	defer timer.Stop()
	select {
	case res = <-results:
	case <-ctx.Done():
		stop()
		return nil, ctx.Err()
	case <-timer.C:
		stop()
		return nil, errors.New("timed out waiting for the browser login to complete")
	}
	stop()
	if res.err != nil {
		return nil, res.err
	}

	proof, err := NewKeyProof(key, cfg.Endpoint.TokenURL, res.code, time.Now(), 5*time.Minute)
	if err != nil {
		return nil, err
	}
	tok, err := cfg.Exchange(ctx, res.code,
		oauth2.VerifierOption(verifier),
		oauth2.SetAuthURLParam("mondoo_key_proof", proof),
	)
	if err != nil {
		return nil, tokenError(err)
	}
	return tok, nil
}

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
:root{--bg1:#f1ecff;--bg2:#e3f2ff;--card:#fff;--fg:#1d1d24;--muted:#55556a;--cat:#5b3fd0}
.fail{--bg1:#ffeef0;--bg2:#f1edff;--cat:#b4361b}
@media (prefers-color-scheme:dark){:root{--bg1:#1d1733;--bg2:#0f1a27;--card:#23222c;--fg:#ececf1;--muted:#a9a9bb;--cat:#c0b0ff}.fail{--bg1:#2c1719;--bg2:#17142a;--cat:#ffb48a}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:linear-gradient(135deg,var(--bg1),var(--bg2))}
main{background:var(--card);border-radius:20px;padding:32px 40px 36px;max-width:460px;width:100%;text-align:center;box-shadow:0 12px 40px rgba(40,20,90,.14);animation:pop .5s cubic-bezier(.2,.9,.3,1.3) both}
pre{display:inline-block;margin:0 0 20px;text-align:left;font:48px/1.1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--cat)}
h1{font-size:24px;margin:0 0 10px}
p{margin:0 0 6px;color:var(--muted);line-height:1.45;overflow-wrap:anywhere}
@keyframes pop{from{opacity:0;transform:translateY(12px) scale(.96)}to{opacity:1;transform:none}}
@media (max-width:420px){pre{font-size:36px}main{padding:24px 20px 28px}}
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
	}{ok, msg, cat.joinedStill(), cat.joinedFrames(), catInterval.Milliseconds()})
}

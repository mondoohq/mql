// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/term"
)

// proofSafetyMargin stops polling a little before the proof expires, so the
// last request is not rejected for an expired proof.
const proofSafetyMargin = 10 * time.Second

// deviceFlow runs the RFC 8628 device authorization grant.
func deviceFlow(ctx context.Context, o *Options, cfg *oauth2.Config, key *ecdsa.PrivateKey, params []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	da, err := cfg.DeviceAuth(ctx, params...)
	if err != nil {
		return nil, tokenError(err)
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		return nil, errors.New("device authorization response is incomplete")
	}

	pr := newProgress(o.Out, o.Interactive)
	pr.Println("! First copy your one-time code: %s", da.UserCode)
	promptEnter := o.Interactive && BrowserPlausible(o.Getenv, o.GOOS)
	if promptEnter {
		pr.Println("Press Enter to open %s in your browser...", da.VerificationURI)
	} else {
		pr.Println("Open %s in a browser and enter the code.", da.VerificationURI)
	}

	// One proof covers the whole poll window, so it must not outlive the
	// server's limit; polling stops before it expires.
	issuedAt := time.Now()
	lifetime, pollDeadline := deviceProofWindow(issuedAt, da.Expiry)
	proof, err := NewKeyProof(key, cfg.Endpoint.TokenURL, da.DeviceCode, issuedAt, lifetime)
	if err != nil {
		return nil, err
	}
	pollCtx, cancel := context.WithDeadline(ctx, pollDeadline)
	defer cancel()

	// Polling starts right away: the code can be approved on another device
	// without pressing Enter. Enter opens the browser at any time meanwhile.
	// Echo is off while waiting, so pressing Enter does not move the cursor
	// off the spinner line.
	if promptEnter {
		if restore := disableInputEcho(o.In); restore != nil {
			defer restore()
		}
	}
	stop := pr.Spin("Waiting for authorization...")
	if promptEnter {
		go waitForEnter(o.In, func() { openVerificationURI(pr, o.OpenBrowser, da.VerificationURI) })
	}
	tok, err := cfg.DeviceAccessToken(pollCtx, da, oauth2.SetAuthURLParam("mondoo_key_proof", proof))
	stop()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, errors.New("the login request expired before it was approved, please try again")
		}
		return nil, tokenError(err)
	}
	return tok, nil
}

// deviceProofWindow returns the key proof lifetime and the poll deadline for a
// device code issued at now that expires at expiry (zero: unknown). Polling
// runs until the device code expires, and the proof stays valid
// proofSafetyMargin past the last poll. Both are bounded by
// MaxKeyProofLifetime: the poll deadline is then the proof expiry minus
// proofSafetyMargin.
func deviceProofWindow(now, expiry time.Time) (time.Duration, time.Time) {
	lifetime := MaxKeyProofLifetime
	if !expiry.IsZero() {
		if remaining := expiry.Sub(now) + proofSafetyMargin; remaining < lifetime {
			lifetime = max(remaining, proofSafetyMargin)
		}
	}
	return lifetime, now.Add(lifetime - proofSafetyMargin)
}

// openVerificationURI opens uri in the browser after the user pressed Enter.
func openVerificationURI(pr *progress, openBrowser func(string) error, uri string) {
	if err := openBrowser(uri); err != nil {
		pr.AfterEnter("Could not open a browser; open %s and enter the code.", uri)
		return
	}
	pr.AfterEnter("✓ Opened %s", uri)
}

// disableInputEcho turns off echo when in is a terminal and returns the func
// that turns it back on, or nil when echo was not changed.
func disableInputEcho(in io.Reader) func() {
	f, ok := in.(interface{ Fd() uintptr })
	if !ok {
		return nil
	}
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	restore, err := disableEcho(fd)
	if err != nil {
		return nil
	}
	return restore
}

// waitForEnter calls fn once a line is read from in. The read is not
// cancelled when the login finishes first; the process exits right after.
func waitForEnter(in io.Reader, fn func()) {
	r := bufio.NewReader(in)
	if _, err := r.ReadString('\n'); err != nil {
		return
	}
	fn()
}

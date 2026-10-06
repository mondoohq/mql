// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/oauth2"
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

	fmt.Fprintf(o.Out, "! First copy your one-time code: %s\n", da.UserCode)
	if o.Interactive && BrowserPlausible(o.Getenv, o.GOOS) {
		fmt.Fprintf(o.Out, "Press Enter to open %s in your browser... ", da.VerificationURI)
		go waitForEnter(o.In, func() {
			if err := o.OpenBrowser(da.VerificationURI); err != nil {
				fmt.Fprintf(o.Out, "\nCould not open a browser; visit %s manually.\n", da.VerificationURI)
			}
		})
	} else {
		fmt.Fprintf(o.Out, "Open %s in a browser and enter the code.\n", da.VerificationURI)
	}

	// One proof covers the whole poll window, so it must not outlive the
	// server's limit; polling stops before it expires.
	issuedAt := time.Now()
	lifetime := MaxKeyProofLifetime
	if !da.Expiry.IsZero() {
		if remaining := time.Until(da.Expiry) + proofSafetyMargin; remaining < lifetime {
			lifetime = remaining
		}
	}
	proof, err := NewKeyProof(key, cfg.Endpoint.TokenURL, da.DeviceCode, issuedAt, lifetime)
	if err != nil {
		return nil, err
	}
	pollCtx, cancel := context.WithDeadline(ctx, issuedAt.Add(lifetime-proofSafetyMargin))
	defer cancel()

	stop := startSpinner(o.Out, o.Interactive, "Waiting for authorization...")
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

func waitForEnter(in io.Reader, fn func()) {
	r := bufio.NewReader(in)
	if _, err := r.ReadString('\n'); err != nil {
		return
	}
	fn()
}

// startSpinner shows msg with a spinner on a terminal, or once otherwise. The
// returned func stops it and clears the line.
func startSpinner(out io.Writer, interactive bool, msg string) func() {
	if !interactive {
		fmt.Fprintln(out, msg)
		return func() {}
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(120 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(out, "\r%s %s", frames[i%len(frames)], msg)
			select {
			case <-done:
				fmt.Fprint(out, "\r\033[K")
				return
			case <-t.C:
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
}

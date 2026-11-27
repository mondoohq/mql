// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

// deviceFlow runs the RFC 8628 device authorization grant. offerBrowser shows
// the "or press Enter to open it on this machine" offer on an interactive
// terminal.
func deviceFlow(ctx context.Context, o *Options, cfg *oauth2.Config, params []oauth2.AuthCodeOption, offerBrowser bool) (*oauth2.Token, error) {
	da, err := cfg.DeviceAuth(ctx, params...)
	if err != nil {
		return nil, tokenError(err)
	}
	userCode := DisplayText(da.UserCode)
	if da.DeviceCode == "" || userCode == "" || da.VerificationURI == "" {
		return nil, errors.New("device authorization response is incomplete")
	}
	// The verification URIs are shown and opened in the browser, so they
	// must use https (http only for a loopback server, or with --insecure).
	if err := CheckServerURL(da.VerificationURI, o.Insecure); err != nil {
		return nil, fmt.Errorf("device authorization response has an unusable verification_uri: %w", err)
	}
	if da.VerificationURIComplete != "" {
		if err := CheckServerURL(da.VerificationURIComplete, o.Insecure); err != nil {
			return nil, fmt.Errorf("device authorization response has an unusable verification_uri_complete: %w", err)
		}
	}

	pr := newProgress(o.Out, o.Interactive)
	pr.Println("! First copy your one-time code: %s", userCode)
	// The code can be entered on any device, so that comes first. Opening
	// the browser on this machine is an offer, never a step: the device flow
	// is also what --no-browser asks for.
	pr.Println("Open %s in a browser and enter the code.", da.VerificationURI)
	promptEnter := o.Interactive && offerBrowser
	if promptEnter {
		pr.Println("Or press Enter to open it in the browser on this machine...")
	}

	// Polling runs until the device code expires. A server that names no
	// expiry gets maxDevicePoll.
	pollDeadline := da.Expiry
	if pollDeadline.IsZero() {
		pollDeadline = time.Now().Add(maxDevicePoll)
	}
	pollCtx, cancel := context.WithDeadline(ctx, pollDeadline)
	defer cancel()

	// Polling starts right away: the code can be approved on another device
	// without pressing Enter. Enter opens the browser at any time meanwhile.
	// While waiting the terminal reads keys unechoed, so Enter is seen as
	// "\r" or "\n" and does not move the cursor off the spinner line.
	if promptEnter {
		if restore := terminalKeyInput(o.In); restore != nil {
			defer restore()
		}
	}
	stop := pr.Spin("Waiting for authorization...")
	if promptEnter {
		go waitForEnter(o.In, func() { openVerificationURI(pr, o.OpenBrowser, da.VerificationURI) })
	}
	tok, err := cfg.DeviceAccessToken(pollCtx, da)
	stop()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, errors.New("the login request expired before it was approved, please try again")
		}
		return nil, tokenError(err)
	}
	return tok, nil
}

// maxDevicePoll bounds polling when the server names no expiry for the
// device code.
const maxDevicePoll = 15 * time.Minute

// openVerificationURI opens uri in the browser after the user pressed Enter.
func openVerificationURI(pr *progress, openBrowser func(string) error, uri string) {
	if err := openBrowser(uri); err != nil {
		pr.AfterEnter("Could not open a browser; open %s and enter the code.", uri)
		return
	}
	pr.AfterEnter("✓ Opened %s", uri)
}

// terminalKeyInput switches in to key-by-key input when it is a terminal and
// returns the func that restores it, or nil when nothing was changed.
func terminalKeyInput(in io.Reader) func() {
	f, ok := in.(interface{ Fd() uintptr })
	if !ok {
		return nil
	}
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	restore, err := keyInput(fd)
	if err != nil {
		log.Debug().Err(err).Msg("could not switch the terminal to key input")
		return nil
	}
	return restore
}

// waitForEnter calls fn once Enter ("\r" or "\n") is read from in. The read
// is not cancelled when the login finishes first; the process exits right
// after.
func waitForEnter(in io.Reader, fn func()) {
	r := bufio.NewReader(in)
	for {
		b, err := r.ReadByte()
		if err != nil {
			log.Debug().Err(err).Msg("stopped waiting for Enter")
			return
		}
		if b == '\r' || b == '\n' {
			fn()
			return
		}
	}
}

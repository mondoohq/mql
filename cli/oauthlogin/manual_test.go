// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testManualRedirect = "https://console.example.com/oauth/code"

// manualLogin runs an interactive browser login against f with the manual
// redirect advertised. The user's terminal input is written to the returned
// pipe.
type manualLogin struct {
	f      *fakeAS
	opts   Options
	out    *syncBuffer
	in     *io.PipeWriter
	mu     sync.Mutex
	opened string // the URL the browser was opened with
	res    *Result
	err    error
	done   chan struct{}
}

func newManualLogin(t *testing.T, openBrowser func(f *fakeAS, u string) error) *manualLogin {
	f := newFakeAS(t)
	f.manualRedirectURI = testManualRedirect
	m := &manualLogin{f: f, out: &syncBuffer{}, done: make(chan struct{})}
	inR, inW := io.Pipe()
	t.Cleanup(func() { inW.Close() })
	m.in = inW
	m.opts = testOptions(f, ModeBrowser)
	m.opts.Out = m.out
	m.opts.In = inR
	m.opts.Interactive = true
	m.opts.OpenBrowser = func(u string) error {
		m.mu.Lock()
		m.opened = u
		m.mu.Unlock()
		return openBrowser(f, u)
	}
	return m
}

func (m *manualLogin) start() {
	go func() {
		defer close(m.done)
		m.res, m.err = Login(context.Background(), m.opts)
	}()
}

func (m *manualLogin) wait(t *testing.T) {
	t.Helper()
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("login did not finish, output:\n%q", m.out.String())
	}
}

// waitForOutput waits until the output contains s n times.
func (m *manualLogin) waitForOutput(t *testing.T, s string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(m.out.String(), s) < n {
		if time.Now().After(deadline) {
			t.Fatalf("output never contained %q %d times:\n%q", s, n, m.out.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// manualURL returns the URL shown for a browser on another machine.
func (m *manualLogin) manualURL(t *testing.T) *url.URL {
	t.Helper()
	for _, line := range strings.Split(m.out.String(), "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "http") {
			u, err := url.Parse(s)
			require.NoError(t, err)
			return u
		}
	}
	t.Fatalf("no URL in the output:\n%q", m.out.String())
	return nil
}

func (m *manualLogin) paste(t *testing.T, s string) {
	t.Helper()
	_, err := m.in.Write([]byte(s + "\n"))
	require.NoError(t, err)
}

func TestManualLogin_LoopbackWins(t *testing.T) {
	m := newManualLogin(t, func(f *fakeAS, u string) error { return f.authorize(u, nil) })
	m.start()
	m.wait(t)
	require.NoError(t, m.err)
	assertResult(t, m.f, m.res)

	got := m.out.String()
	assert.True(t, strings.HasPrefix(got, "Opening your browser to log in…\n"+
		"If the browser doesn't open or is on another machine, open this URL:\n\n  "+m.f.issuer()+"/oauth/authorize?"), got)
	assert.Contains(t, got, "\n\n"+pastePromptAuto)
	assert.True(t, strings.HasSuffix(got, "\r\033[K"), "the paste prompt is cleared: %q", got)

	// Both URLs are the same request but for the redirect URI.
	manual := m.manualURL(t).Query()
	opened, err := url.Parse(m.opened)
	require.NoError(t, err)
	auto := opened.Query()
	assert.Equal(t, testManualRedirect, manual.Get("redirect_uri"))
	assert.True(t, strings.HasPrefix(auto.Get("redirect_uri"), "http://127.0.0.1:"))
	for _, k := range []string{"state", "code_challenge", "code_challenge_method", "mondoo_public_key", "client_id", "scope", "mondoo_space_mrn"} {
		assert.Equal(t, auto.Get(k), manual.Get(k), k)
	}
	assert.NotContains(t, got, "%2Fcallback", "the loopback URL is never shown")

	require.Len(t, m.f.tokenForms, 1)
	assert.Equal(t, auto.Get("redirect_uri"), m.f.tokenForms[0].Get("redirect_uri"))
}

func TestManualLogin_PasteWins(t *testing.T) {
	m := newManualLogin(t, func(*fakeAS, string) error { return nil })
	m.start()
	m.waitForOutput(t, pastePromptAuto, 1)
	pasted, err := m.f.consoleAuthorize(m.manualURL(t).String())
	require.NoError(t, err)
	m.paste(t, "  "+pasted+"  ")
	m.wait(t)
	require.NoError(t, m.err)
	assertResult(t, m.f, m.res)

	require.Len(t, m.f.tokenForms, 1)
	assert.Equal(t, testManualRedirect, m.f.tokenForms[0].Get("redirect_uri"),
		"the code is redeemed with the redirect URI it was issued for")
	assert.NotEmpty(t, m.f.tokenForms[0].Get("code_verifier"))
}

func TestManualLogin_WrongStateRejected(t *testing.T) {
	m := newManualLogin(t, func(*fakeAS, string) error { return nil })
	m.start()
	m.waitForOutput(t, pastePromptAuto, 1)
	pasted, err := m.f.consoleAuthorize(m.manualURL(t).String())
	require.NoError(t, err)
	code, _, _ := strings.Cut(pasted, "#")

	m.paste(t, code+"#forged-state")
	m.waitForOutput(t, pasteMismatchMsg, 1)
	m.waitForOutput(t, pastePromptAuto, 2)
	m.paste(t, "not a code")
	m.waitForOutput(t, pasteMismatchMsg, 2)
	assert.Empty(t, m.f.tokenForms, "a mismatched code is never redeemed")

	m.paste(t, pasted)
	m.wait(t)
	require.NoError(t, m.err)
	assertResult(t, m.f, m.res)
	require.Len(t, m.f.tokenForms, 1)
}

func TestManualLogin_TooManyBadPastes(t *testing.T) {
	m := newManualLogin(t, func(*fakeAS, string) error { return nil })
	m.start()
	m.waitForOutput(t, pastePromptAuto, 1)
	for i := 1; i < maxBadPastes; i++ {
		m.paste(t, "code#forged-state")
		m.waitForOutput(t, pasteMismatchMsg, i)
	}
	m.paste(t, "code#forged-state")
	m.wait(t)
	require.Error(t, m.err)
	assert.Contains(t, m.err.Error(), "does not match this login")
	assert.Empty(t, m.f.tokenForms)
}

func TestManualLogin_BrowserOpenFails(t *testing.T) {
	m := newManualLogin(t, func(*fakeAS, string) error { return errors.New("no opener available") })
	m.start()
	m.waitForOutput(t, pastePrompt, 1)

	got := m.out.String()
	assert.Equal(t, "Open this URL in a browser to log in:\n\n  "+m.manualURL(t).String()+"\n\n"+pastePrompt, got)
	assert.NotContains(t, got, "%2Fcallback", "the loopback URL is never shown")
	assert.Equal(t, testManualRedirect, m.manualURL(t).Query().Get("redirect_uri"))

	pasted, err := m.f.consoleAuthorize(m.manualURL(t).String())
	require.NoError(t, err)
	m.paste(t, pasted)
	m.wait(t)
	require.NoError(t, m.err)
	assertResult(t, m.f, m.res)
	assert.Equal(t, testManualRedirect, m.f.tokenForms[0].Get("redirect_uri"))
	assert.Empty(t, m.f.deviceCode, "the device flow is not used")
}

func TestManualLogin_NotInteractiveUsesDeviceFlow(t *testing.T) {
	m := newManualLogin(t, func(*fakeAS, string) error { return errors.New("no opener available") })
	m.opts.Interactive = false
	m.start()
	m.wait(t)
	require.NoError(t, m.err)
	assert.Contains(t, m.out.String(), "! First copy your one-time code: WDJB-MJHT")
	assert.NotContains(t, m.out.String(), "Paste the code")
}

func TestParsePastedCode(t *testing.T) {
	const state, iss = "the-state", "https://api.example.com"
	for in, want := range map[string]string{
		"abc#the-state": "abc",
		"a#b#the-state": "a#b",
		"https://console.example.com/oauth/code?code=abc&state=the-state":                                   "abc",
		"https://console.example.com/oauth/code?code=abc&state=the-state&iss=https%3A%2F%2Fapi.example.com": "abc",
	} {
		res := parsePastedCode(in, state, iss)
		require.NoError(t, res.err, in)
		assert.Equal(t, want, res.code, in)
	}
	for _, bad := range []string{
		"abc",
		"#the-state",
		"abc#other",
		"abc#",
		"ab c#the-state",
		"https://console.example.com/oauth/code?code=abc&state=other",
		"https://console.example.com/oauth/code?code=abc&state=the-state&iss=https%3A%2F%2Fevil.example.com",
	} {
		assert.Error(t, parsePastedCode(bad, state, iss).err, bad)
	}
}

func TestDiscover_ManualRedirectURI(t *testing.T) {
	f := newFakeAS(t)
	f.manualRedirectURI = testManualRedirect
	md, err := Discover(context.Background(), f.srv.Client(), f.issuer(), false)
	require.NoError(t, err)
	assert.Equal(t, testManualRedirect, md.ManualRedirectURI)

	for _, bad := range []string{"/oauth/code", "http://console.example.com/oauth/code", "https://console.example.com/oauth/code#x"} {
		f.manualRedirectURI = bad
		md, err := Discover(context.Background(), f.srv.Client(), f.issuer(), false)
		require.NoError(t, err, bad)
		assert.Empty(t, md.ManualRedirectURI, bad)
	}
}

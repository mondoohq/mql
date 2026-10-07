// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestDisplayText(t *testing.T) {
	assert.Equal(t, "Jane Doe", DisplayText("Jane Doe"))
	assert.Equal(t, "Jäne 🐱", DisplayText("Jäne 🐱"))
	assert.Equal(t, "Jane[31mred[0m", DisplayText("Jane\x1b[31mred\x1b[0m"))
	assert.Equal(t, "line1line2", DisplayText("line1\r\nline2"))
	assert.Equal(t, "abcdef", DisplayText("abc‮def⁦"))
	assert.Equal(t, "", DisplayText(" \t\n"))
	assert.Len(t, DisplayText(strings.Repeat("a", 2*maxDisplayLen)), maxDisplayLen)
}

func TestCheckServerURL(t *testing.T) {
	for _, ok := range []string{
		"https://console.example.com/activate",
		"https://console.example.com/activate?user_code=WDJB-MJHT",
		"http://127.0.0.1:8080/activate",
		"http://localhost:8080/activate",
		"http://[::1]:8080/activate",
	} {
		assert.NoError(t, CheckServerURL(ok, false), ok)
	}
	for _, bad := range []string{
		"http://console.example.com/activate",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"/activate",
		"https://user:pass@console.example.com/activate",
		"https://console.example.com/activate\x1b[2J",
		"https://console.example.com/‮etavitca",
		"",
	} {
		assert.Error(t, CheckServerURL(bad, false), bad)
	}
	assert.NoError(t, CheckServerURL("http://console.example.com/activate", true), "--insecure allows http")
	assert.Error(t, CheckServerURL("ftp://console.example.com/activate", true))
}

func TestDeviceFlow_RejectsNonHTTPSVerificationURI(t *testing.T) {
	f := newFakeAS(t)
	f.verificationURI = "http://console.example.com/activate"
	opts := testOptions(f, ModeDevice)
	out := &bytes.Buffer{}
	opts.Out = out
	opened := false
	opts.OpenBrowser = func(string) error { opened = true; return nil }

	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification_uri")
	assert.NotContains(t, out.String(), "console.example.com", "the URI is neither shown nor opened")
	assert.False(t, opened)
	assert.Equal(t, 0, f.tokenCalls)
}

func TestLogin_RejectsNonHTTPSAPIEndpoint(t *testing.T) {
	f := newFakeAS(t)
	f.apiEndpoint = "http://api.example.com"
	opts := testOptions(f, ModeBrowser)
	opts.OpenBrowser = func(u string) error { return f.authorize(u, nil) }

	_, err := Login(context.Background(), opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_endpoint")

	f2 := newFakeAS(t)
	f2.apiEndpoint = "https://api.example.com"
	opts = testOptions(f2, ModeBrowser)
	opts.OpenBrowser = func(u string) error { return f2.authorize(u, nil) }
	res, err := Login(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", res.ConfigValues()["api_endpoint"])
}

func TestSummary_StripsControlCharacters(t *testing.T) {
	now := time.Now()
	s := SessionInfo{
		UserEmail: "jane@example.com\x1b]0;title\x07",
		SpaceName: "prod\r\n",
		OrgName:   "ac\x1b[2Jme",
	}.Summary("✓ Logged in", now)
	assert.Equal(t, "✓ Logged in as jane@example.com]0;title · space ac[2Jme/prod", s)
	assert.NotContains(t, s, "\x1b")
}

func TestTokenError_StripsControlCharacters(t *testing.T) {
	err := tokenError(&oauth2.RetrieveError{ErrorCode: "invalid_request", ErrorDescription: "bad\x1b[2J\nrequest"})
	assert.Equal(t, "login failed: invalid_request: bad[2Jrequest", err.Error())

	err = tokenError(&oauth2.RetrieveError{Response: &http.Response{Status: "500 Internal Server Error"}, Body: []byte("oops\x1b[2J")})
	assert.NotContains(t, err.Error(), "\x1b")

	plain := errors.New("connection refused")
	assert.Equal(t, plain, tokenError(plain))
}

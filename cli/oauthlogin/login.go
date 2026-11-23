// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package oauthlogin implements interactive CLI login as a public OAuth 2.0
// client. It supports two grants:
//
//   - authorization code with PKCE (RFC 7636) and a loopback redirect
//     (RFC 8252), for machines with a browser, and
//   - the device authorization grant (RFC 8628), for headless machines.
//
// The login server is found through the API endpoint (RFC 9728 protected
// resource metadata, then RFC 8414 authorization server metadata), and its
// issuer is checked on the authorization response (RFC 9207) and on the token
// response. A login ends with a bearer token. The client holds no key: the
// browser login is bound to this client by PKCE, the device login by the
// device code.
package oauthlogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	// ClientID is the public client identifier of the CLI.
	ClientID = "mondoo-cli"
	// Scope is the only scope the CLI requests.
	Scope = "mondoo:scan"

	// DefaultLoopbackTimeout bounds how long the loopback listener waits for
	// the browser to come back.
	DefaultLoopbackTimeout = 10 * time.Minute

	maxParamLen = 256
)

// Mode selects the grant.
type Mode int

const (
	// ModeAuto picks the browser flow when a local browser is plausible and
	// the device flow otherwise.
	ModeAuto Mode = iota
	// ModeBrowser uses the authorization code grant with a loopback redirect.
	ModeBrowser
	// ModeDevice uses the device authorization grant.
	ModeDevice
)

func (m Mode) String() string {
	switch m {
	case ModeBrowser:
		return "browser"
	case ModeDevice:
		return "device"
	default:
		return "auto"
	}
}

// Options configure a login.
type Options struct {
	// Endpoint is the API endpoint the user logs in to. The login server is
	// found through it (see Discover) and may be another host.
	Endpoint string
	// Insecure allows plain http to a non-loopback server.
	Insecure bool
	Mode     Mode
	// ScopeMrn preselects a space or an organization in the approval page.
	// It is only a hint.
	ScopeMrn string
	// DeviceName and DeviceInfo are shown to the approving user.
	DeviceName string
	DeviceInfo string

	HTTPClient *http.Client
	// Out receives the user-facing prompts. Defaults to os.Stderr.
	Out io.Writer
	// In is read for the "press Enter" prompt. Defaults to os.Stdin.
	In io.Reader
	// Interactive reports whether In and Out are terminals.
	Interactive bool
	// OpenBrowser opens a URL. Defaults to the system browser. When it fails
	// in the browser flow, the login continues by pasting a code if the
	// server supports it, and with the device flow otherwise.
	OpenBrowser func(url string) error
	// Getenv and GOOS feed mode detection. Default to the process values.
	Getenv func(string) string
	GOOS   string

	LoopbackTimeout time.Duration
}

// Credential is what a login issues, as the mondoo_service_account object of
// the token response. It is not a service account: Mrn is the MRN of the user
// who approved the login, and Token is a bearer token. A request made with
// the token is that user.
type Credential struct {
	Mrn string `json:"mrn"`
	// SpaceMrn is set only when the login is for a space.
	SpaceMrn string `json:"space_mrn"`
	// ScopeMrn is what the login is for: a space or an organization.
	ScopeMrn    string `json:"scope_mrn"`
	Token       string `json:"token"`
	ApiEndpoint string `json:"api_endpoint"`
	ValidUntil  string `json:"valid_until"`
}

// User describes who approved the login.
type User struct {
	Mrn   string `json:"mrn"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// LoginScope describes what the login is for: a space or an organization.
type LoginScope struct {
	Mrn  string `json:"mrn"`
	Name string `json:"name"`
	// Kind is "space" or "organization".
	Kind string `json:"kind"`
	// OrgMrn and OrgName are the space's organization, or the organization
	// itself.
	OrgMrn  string `json:"org_mrn"`
	OrgName string `json:"org_name"`
}

// ScopeKindOrganization is LoginScope.Kind for a login to an organization.
const ScopeKindOrganization = "organization"

// Result is a completed login.
type Result struct {
	Credential Credential
	User       User
	Scope      LoginScope
	// Endpoint is the API endpoint the user logged in to.
	Endpoint string
	// Issuer is the login server that issued the token. Revocation goes
	// there. It is the API endpoint unless the API names another server.
	Issuer string
	// ValidUntil is when the login ends. Zero when the server did not say.
	ValidUntil time.Time
}

func (o *Options) withDefaults() {
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	if o.Out == nil {
		o.Out = os.Stderr
	}
	if o.In == nil {
		o.In = os.Stdin
	}
	if o.OpenBrowser == nil {
		o.OpenBrowser = OpenBrowser
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.GOOS == "" {
		o.GOOS = defaultGOOS
	}
	if o.LoopbackTimeout <= 0 {
		o.LoopbackTimeout = DefaultLoopbackTimeout
	}
}

// Login runs the interactive login and returns the issued credential.
func Login(ctx context.Context, o Options) (*Result, error) {
	o.withDefaults()

	md, err := Discover(ctx, o.HTTPClient, o.Endpoint, o.Insecure)
	if err != nil {
		return nil, err
	}

	mode := o.Mode
	if mode == ModeAuto {
		mode = DetectMode(o.Getenv, o.GOOS)
	}
	switch mode {
	case ModeDevice:
		if md.DeviceAuthorizationEndpoint == "" {
			return nil, errors.New("the server does not support device login")
		}
	case ModeBrowser:
		if md.AuthorizationEndpoint == "" {
			return nil, errors.New("the server does not support browser login")
		}
	}

	cfg := &oauth2.Config{
		ClientID: ClientID,
		Scopes:   []string{Scope},
		Endpoint: oauth2.Endpoint{
			AuthURL:       md.AuthorizationEndpoint,
			TokenURL:      md.TokenEndpoint,
			DeviceAuthURL: md.DeviceAuthorizationEndpoint,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}
	var params []oauth2.AuthCodeOption
	for k, v := range map[string]string{
		"mondoo_scope_mrn":   o.ScopeMrn,
		"mondoo_device_name": o.DeviceName,
		"mondoo_device_info": o.DeviceInfo,
	} {
		if v = sanitizeParam(v); v != "" {
			params = append(params, oauth2.SetAuthURLParam(k, v))
		}
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, o.HTTPClient)

	var tok *oauth2.Token
	if mode == ModeDevice {
		tok, err = deviceFlow(ctx, &o, cfg, params, BrowserPlausible(o.Getenv, o.GOOS))
	} else {
		tok, err = loopbackFlow(ctx, &o, md, cfg, params)
		var notOpened *browserNotOpenedError
		if errors.As(err, &notOpened) && md.DeviceAuthorizationEndpoint != "" {
			// No browser could be opened on this machine: log in with a
			// one-time code instead. The device flow does not offer to open
			// a browser either.
			log.Debug().Err(notOpened.err).Msg("could not open a browser, using device login")
			cfg.RedirectURL = ""
			tok, err = deviceFlow(ctx, &o, cfg, params, false)
		}
	}
	if err != nil {
		return nil, err
	}
	res, err := parseToken(tok, md.Issuer, o.Insecure)
	if err != nil {
		return nil, err
	}
	res.Endpoint, _ = NormalizeEndpoint(o.Endpoint)
	return res, nil
}

// randomString returns n random bytes as base64url.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sanitizeParam strips control characters and caps the length.
func sanitizeParam(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	return truncateUTF8(v, maxParamLen)
}

// truncateUTF8 shortens s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// tokenError turns an RFC 6749 error response into a readable error.
func tokenError(err error) error {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err
	}
	switch re.ErrorCode {
	case "access_denied":
		return errors.New("the login request was denied")
	case "expired_token":
		return errors.New("the login request expired before it was approved, please try again")
	case "":
		// The message includes the response body.
		return errors.New(DisplayText(err.Error()))
	}
	code := DisplayText(re.ErrorCode)
	if desc := DisplayText(re.ErrorDescription); desc != "" {
		return fmt.Errorf("login failed: %s: %s", code, desc)
	}
	return fmt.Errorf("login failed: %s", code)
}

func parseToken(tok *oauth2.Token, issuer string, insecure bool) (*Result, error) {
	iss, _ := tok.Extra("iss").(string)
	if iss == "" {
		return nil, errors.New("token response is missing the issuer")
	}
	if !sameIssuer(iss, issuer) {
		return nil, fmt.Errorf("token response issuer %q does not match %q", iss, issuer)
	}

	var res Result
	if err := decodeExtra(tok, "mondoo_service_account", &res.Credential); err != nil {
		return nil, err
	}
	cred := &res.Credential
	// The token is also the response's access_token.
	if cred.Token == "" {
		cred.Token = tok.AccessToken
	}
	if cred.Mrn == "" || cred.Token == "" {
		return nil, errors.New("token response is missing the login token")
	}
	if cred.ScopeMrn == "" {
		cred.ScopeMrn = cred.SpaceMrn
	}
	if cred.ScopeMrn == "" {
		return nil, errors.New("token response does not say what the login is for")
	}
	// The CLI sends the token to api_endpoint from now on, so it gets the
	// same transport rules as the server endpoint.
	if cred.ApiEndpoint != "" {
		if err := CheckServerURL(cred.ApiEndpoint, insecure); err != nil {
			return nil, fmt.Errorf("token response has an unusable api_endpoint: %w", err)
		}
	}
	_ = decodeExtra(tok, "mondoo_user", &res.User)
	_ = decodeExtra(tok, "mondoo_scope", &res.Scope)

	// When the login ends. The token is not read for this: it is opaque to
	// the client.
	if t, err := time.Parse(time.RFC3339, cred.ValidUntil); err == nil {
		res.ValidUntil = t
	} else if !tok.Expiry.IsZero() {
		res.ValidUntil = tok.Expiry
	}

	res.Issuer = issuer
	return &res, nil
}

func decodeExtra(tok *oauth2.Token, field string, into any) error {
	raw := tok.Extra(field)
	if raw == nil {
		return fmt.Errorf("token response is missing %s", field)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("could not parse %s: %w", field, err)
	}
	return nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package oauthlogin implements interactive CLI login as a public OAuth 2.0
// client. It supports two grants:
//
//   - authorization code with PKCE (RFC 7636) and a loopback redirect
//     (RFC 8252), for machines with a browser, and
//   - the device authorization grant (RFC 8628), for headless machines.
//
// The server is found through authorization server metadata (RFC 8414) and the
// issuer is checked on the authorization response (RFC 9207) and on the token
// response. Each login generates a fresh P-384 key; the server issues a
// short-lived certificate for its public half, and every token request carries
// a signed proof that the client holds the private half.
package oauthlogin

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	// Endpoint is the server URL; it must equal the server's issuer.
	Endpoint string
	// Insecure allows plain http to a non-loopback server.
	Insecure bool
	Mode     Mode
	// SpaceMrn preselects a space in the approval page. It is only a hint.
	SpaceMrn string
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

// ServiceAccount is the session credential issued by the server.
type ServiceAccount struct {
	Mrn         string `json:"mrn"`
	SpaceMrn    string `json:"space_mrn"`
	ScopeMrn    string `json:"scope_mrn"`
	Certificate string `json:"certificate"`
	ApiEndpoint string `json:"api_endpoint"`
	ValidUntil  string `json:"valid_until"`
}

// User describes who approved the login.
type User struct {
	Mrn   string `json:"mrn"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Space describes the space the credential is scoped to.
type Space struct {
	Mrn     string `json:"mrn"`
	Name    string `json:"name"`
	OrgMrn  string `json:"org_mrn"`
	OrgName string `json:"org_name"`
}

// Result is a completed login.
type Result struct {
	ServiceAccount ServiceAccount
	User           User
	Space          Space
	// PrivateKeyPEM is the PKCS#8 PEM of the per-login key.
	PrivateKeyPEM string
	// Issuer is the authorization server that issued the credential.
	Issuer string
	// AccessToken is kept for revocation; it carries no secret.
	AccessToken string
	// ValidUntil is when the credential expires.
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

	key, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate a key: %w", err)
	}
	pub, err := EncodePublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
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
	params := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("mondoo_public_key", pub)}
	for k, v := range map[string]string{
		"mondoo_space_mrn":   o.SpaceMrn,
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
		tok, err = deviceFlow(ctx, &o, cfg, key, params, BrowserPlausible(o.Getenv, o.GOOS))
	} else {
		tok, err = loopbackFlow(ctx, &o, md, cfg, key, params)
		var notOpened *browserNotOpenedError
		if errors.As(err, &notOpened) && md.DeviceAuthorizationEndpoint != "" {
			// No browser could be opened on this machine: log in with a
			// one-time code instead, with the same key. The device flow does
			// not offer to open a browser either.
			log.Debug().Err(notOpened.err).Msg("could not open a browser, using device login")
			cfg.RedirectURL = ""
			tok, err = deviceFlow(ctx, &o, cfg, key, params, false)
		}
	}
	if err != nil {
		return nil, err
	}
	return parseToken(tok, md.Issuer, key, o.Insecure)
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

func parseToken(tok *oauth2.Token, issuer string, key *ecdsa.PrivateKey, insecure bool) (*Result, error) {
	iss, _ := tok.Extra("iss").(string)
	if iss == "" {
		return nil, errors.New("token response is missing the issuer")
	}
	if !sameIssuer(iss, issuer) {
		return nil, fmt.Errorf("token response issuer %q does not match %q", iss, issuer)
	}

	var res Result
	if err := decodeExtra(tok, "mondoo_service_account", &res.ServiceAccount); err != nil {
		return nil, err
	}
	sa := &res.ServiceAccount
	if sa.Mrn == "" || sa.Certificate == "" {
		return nil, errors.New("token response is missing the service account")
	}
	if sa.ScopeMrn == "" {
		sa.ScopeMrn = sa.SpaceMrn
	}
	// The CLI sends the credential to api_endpoint from now on, so it gets
	// the same transport rules as the server endpoint.
	if sa.ApiEndpoint != "" {
		if err := CheckServerURL(sa.ApiEndpoint, insecure); err != nil {
			return nil, fmt.Errorf("token response has an unusable api_endpoint: %w", err)
		}
	}
	_ = decodeExtra(tok, "mondoo_user", &res.User)
	_ = decodeExtra(tok, "mondoo_space", &res.Space)

	block, _ := pem.Decode([]byte(sa.Certificate))
	if block == nil {
		return nil, errors.New("issued certificate is not PEM encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse the issued certificate: %w", err)
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certKey.Equal(&key.PublicKey) {
		return nil, errors.New("issued certificate is not for this login's key")
	}

	res.ValidUntil = cert.NotAfter
	if t, err := time.Parse(time.RFC3339, sa.ValidUntil); err == nil && t.Before(res.ValidUntil) {
		res.ValidUntil = t
	}

	res.PrivateKeyPEM, err = EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	res.Issuer = issuer
	res.AccessToken = tok.AccessToken
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

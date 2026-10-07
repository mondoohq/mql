// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

// WellKnownPath is the RFC 8414 authorization server metadata location.
const WellKnownPath = "/.well-known/oauth-authorization-server"

// ErrBrowserLoginDisabled is returned when the server does not publish
// authorization server metadata, which means interactive login is turned off.
var ErrBrowserLoginDisabled = errors.New("browser login is not enabled on this server")

// Metadata is the subset of RFC 8414 authorization server metadata the client
// relies on.
type Metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	// ManualRedirectURI is a redirect URI on the server that shows the
	// authorization code for the user to paste into the CLI, so the browser
	// login works from a browser on another machine. Empty when the server
	// does not offer it.
	ManualRedirectURI string `json:"mondoo_manual_redirect_uri"`
}

// NormalizeEndpoint canonicalizes a server URL: scheme and host are lowercased,
// a trailing slash is dropped, and query or fragment are rejected. The result is
// what the server's issuer identifier must equal.
func NormalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("no API endpoint configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("invalid endpoint %q: scheme must be https", endpoint)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q: missing host", endpoint)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("invalid endpoint %q: must not contain user info, query or fragment", endpoint)
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// IsLoopbackHost reports whether host names the local machine.
func IsLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// checkTransport enforces https for everything but loopback servers. With
// insecure set, plain http to a remote host is allowed after a warning.
func checkTransport(raw string, insecure bool, warn bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if IsLoopbackHost(u.Hostname()) {
			return nil
		}
		if insecure {
			if warn {
				log.Warn().Str("url", raw).Msg("using an unencrypted connection to a remote server because --insecure is set")
			}
			return nil
		}
		return fmt.Errorf("refusing to use unencrypted http for %s: use https, or --insecure to override", raw)
	default:
		return fmt.Errorf("unsupported URL scheme in %q", raw)
	}
}

// Discover fetches the authorization server metadata for endpoint and checks
// that the server identifies itself with exactly that endpoint (RFC 8414 §3.3).
func Discover(ctx context.Context, client *http.Client, endpoint string, insecure bool) (*Metadata, error) {
	base, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if err := checkTransport(base, insecure, true); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+WellKnownPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrBrowserLoginDisabled
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorization server metadata request failed: %s", resp.Status)
	}

	var md Metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&md); err != nil {
		return nil, fmt.Errorf("could not parse authorization server metadata: %w", err)
	}

	issuer, err := NormalizeEndpoint(md.Issuer)
	if err != nil || issuer != base {
		return nil, fmt.Errorf("authorization server issuer %q does not match the requested endpoint %q", md.Issuer, base)
	}
	md.Issuer = issuer

	if md.TokenEndpoint == "" {
		return nil, errors.New("authorization server metadata has no token_endpoint")
	}
	for _, ep := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.DeviceAuthorizationEndpoint, md.RevocationEndpoint} {
		if ep == "" {
			continue
		}
		if err := checkTransport(ep, insecure, false); err != nil {
			return nil, err
		}
	}
	if md.ManualRedirectURI != "" {
		if err := checkManualRedirectURI(md.ManualRedirectURI, insecure); err != nil {
			log.Debug().Err(err).Msg("ignoring the manual redirect URI")
			md.ManualRedirectURI = ""
		}
	}
	return &md, nil
}

// checkManualRedirectURI accepts an absolute http(s) URL without fragment that
// passes the transport check.
func checkManualRedirectURI(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%q is not an absolute URL without fragment", raw)
	}
	return checkTransport(raw, insecure, false)
}

func sameIssuer(a, b string) bool {
	na, err := NormalizeEndpoint(a)
	if err != nil {
		return false
	}
	nb, err := NormalizeEndpoint(b)
	if err != nil {
		return false
	}
	return na == nb
}

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
// a trailing slash is dropped, and query or fragment are rejected. Two URLs
// name the same server when their normalized forms are equal.
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

// ProtectedResourcePath is the RFC 9728 protected resource metadata location.
// The API endpoint may publish there which login server protects it.
const ProtectedResourcePath = "/.well-known/oauth-protected-resource"

// protectedResource is the subset of RFC 9728 metadata the client reads.
type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// Discover finds the login server for an API endpoint and reads its metadata.
//
// The API endpoint is asked first which login server protects it (RFC 9728).
// When it names one, the metadata is read from that server. When it publishes
// no such document, the API endpoint is the login server itself.
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
	issuer, err := loginServer(ctx, client, base, insecure)
	if err != nil {
		return nil, err
	}
	return readMetadata(ctx, client, issuer, insecure)
}

// DiscoverIssuer reads the metadata of a login server that is already known,
// for example the issuer stored with a login session. It does not ask for a
// pointer: that document belongs to an API endpoint, and a login server that
// shares a host with an API would answer with the API's.
func DiscoverIssuer(ctx context.Context, client *http.Client, issuer string, insecure bool) (*Metadata, error) {
	base, err := NormalizeEndpoint(issuer)
	if err != nil {
		return nil, err
	}
	if err := checkTransport(base, insecure, true); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	return readMetadata(ctx, client, base, insecure)
}

// loginServer returns the login server the API endpoint base names, or base
// itself when the endpoint publishes no protected resource metadata.
//
// "Publishes none" is a 404, or a 401 or 403: a server that guards every
// path it does not know answers an anonymous request for this one that way.
// Falling back is safe, because the fallback is the endpoint the user
// configured. Any other failure stops the login.
func loginServer(ctx context.Context, client *http.Client, base string, insecure bool) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+ProtectedResourcePath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", base, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		return base, nil
	default:
		return "", fmt.Errorf("protected resource metadata request failed: %s", resp.Status)
	}

	var pr protectedResource
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return "", fmt.Errorf("could not parse protected resource metadata: %w", err)
	}
	// RFC 9728 section 3.3: the document must be about the endpoint asked.
	if resource, err := NormalizeEndpoint(pr.Resource); err != nil || resource != base {
		return "", fmt.Errorf("protected resource %q does not match the requested endpoint %q", pr.Resource, base)
	}
	if len(pr.AuthorizationServers) != 1 {
		return "", fmt.Errorf("the server names %d login servers, expected exactly one", len(pr.AuthorizationServers))
	}
	issuer, err := NormalizeEndpoint(pr.AuthorizationServers[0])
	if err != nil {
		return "", fmt.Errorf("the server names an unusable login server: %w", err)
	}
	if err := checkTransport(issuer, insecure, true); err != nil {
		return "", err
	}
	return issuer, nil
}

// readMetadata fetches the authorization server metadata of issuer and checks
// that the server identifies itself with exactly that issuer (RFC 8414
// section 3.3). issuer is normalized and its transport is checked.
func readMetadata(ctx context.Context, client *http.Client, base string, insecure bool) (*Metadata, error) {
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
		return nil, fmt.Errorf("authorization server issuer %q does not match the login server %q", md.Issuer, base)
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

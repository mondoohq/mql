// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// OptionURL carries the platform base URL through the inventory config.
	OptionURL = "url"

	// requestTimeout bounds a single API call. The configuration endpoint
	// returns the whole instance descriptor, which is large on a big instance,
	// so the timeout is generous.
	requestTimeout = 60 * time.Second
)

// ArtifactoryConnection talks to the REST API of one JFrog platform instance.
//
// Artifactory and Access are two services of the same platform, served under
// the /artifactory and /access prefixes of a shared base URL. The connection
// stores that base and builds each service URL from it, so a self-hosted
// deployment and a cloud instance are reached the same way.
type ArtifactoryConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// baseURL is the platform base without a trailing slash, for example
	// https://artifactory.example.com or https://example.jfrog.io.
	baseURL string
	// token is an access token, sent as a bearer token.
	token string
	// apiKey is a legacy API key, sent in the X-JFrog-Art-Api header.
	apiKey string
	client *http.Client
}

func NewArtifactoryConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ArtifactoryConnection, error) {
	rawURL := ""
	if conf != nil && conf.Options != nil {
		rawURL = conf.Options[OptionURL]
	}
	if rawURL == "" {
		rawURL = os.Getenv("ARTIFACTORY_URL")
	}
	if rawURL == "" {
		rawURL = os.Getenv("JFROG_URL")
	}
	if rawURL == "" {
		return nil, errors.New("an Artifactory URL is required, pass --url or set ARTIFACTORY_URL")
	}

	baseURL, err := NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, err
	}

	conn := &ArtifactoryConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		baseURL:    baseURL,
		client:     &http.Client{Timeout: requestTimeout},
	}

	conn.token = strings.TrimSpace(os.Getenv("ARTIFACTORY_TOKEN"))
	if conn.token == "" {
		conn.token = strings.TrimSpace(os.Getenv("JFROG_ACCESS_TOKEN"))
	}
	conn.apiKey = strings.TrimSpace(os.Getenv("ARTIFACTORY_API_KEY"))

	// A credential passed on the command line or from a vault wins over the
	// environment, which is what a user setting the flag expects.
	if conf != nil {
		for _, cred := range conf.Credentials {
			if cred == nil || len(cred.Secret) == 0 {
				continue
			}
			secret := strings.TrimSpace(string(cred.Secret))
			switch cred.Type {
			case vault.CredentialType_bearer:
				conn.token = secret
			case vault.CredentialType_password:
				conn.apiKey = secret
			}
		}
	}

	if conn.token == "" && conn.apiKey == "" {
		return nil, errors.New("an Artifactory access token or API key is required, pass --token or --api-key, or set ARTIFACTORY_TOKEN or ARTIFACTORY_API_KEY")
	}

	return conn, nil
}

func (c *ArtifactoryConnection) Name() string {
	return "artifactory"
}

func (c *ArtifactoryConnection) Asset() *inventory.Asset {
	return c.asset
}

// BaseURL returns the platform base URL the connection was built from.
func (c *ArtifactoryConnection) BaseURL() string {
	return c.baseURL
}

// Host returns the host of the platform base URL. It names the asset when the
// instance does not report a service identifier.
func (c *ArtifactoryConnection) Host() string {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return c.baseURL
	}
	return u.Host
}

// ArtifactoryURL builds a URL under the Artifactory service, whose path must
// start with a slash.
func (c *ArtifactoryConnection) ArtifactoryURL(path string) string {
	return c.baseURL + "/artifactory" + path
}

// XrayURL builds a URL under the Xray service, whose path must start with a
// slash. Xray is a separate service of the same platform, so it is reached
// under the same base as Artifactory and Access.
func (c *ArtifactoryConnection) XrayURL(path string) string {
	return c.baseURL + "/xray" + path
}

// AccessURL builds a URL under the Access service, whose path must start with
// a slash. Access serves users, groups, and tokens for the whole platform.
func (c *ArtifactoryConnection) AccessURL(path string) string {
	return c.baseURL + "/access" + path
}

// NormalizeBaseURL turns what a user passes into the platform base URL that
// both the Artifactory and the Access service are served under.
//
// It accepts the three shapes a user has at hand: a cloud instance
// (https://example.jfrog.io), a self-hosted platform base
// (https://artifactory.example.com), and the Artifactory service URL that the
// web interface shows (https://artifactory.example.com/artifactory). The
// trailing /artifactory is removed, because the connection appends the service
// prefix itself and would otherwise request /artifactory/artifactory/api/...
func NormalizeBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("an Artifactory URL is required")
	}

	// A bare host is the most common way to type it. Assume HTTPS rather than
	// falling back to a plaintext scheme, which would send the credential in
	// the clear.
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("cannot parse the Artifactory URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("the Artifactory URL %q must use http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("the Artifactory URL %q has no host", raw)
	}

	path := strings.TrimSuffix(u.Path, "/")
	// Strip the service prefix whatever case it was typed in, but only when it
	// is the last path segment, so a reverse proxy that serves the platform
	// under /artifactory/something keeps its path.
	if strings.EqualFold(path, "/artifactory") {
		path = ""
	}

	return u.Scheme + "://" + u.Host + path, nil
}

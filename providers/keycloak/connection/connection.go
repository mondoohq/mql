// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	// defaultAuthClientID is the built-in Keycloak client that accepts the
	// resource owner password grant. It is public, so a password login needs no
	// client secret unless the deployment replaced it with a confidential one.
	defaultAuthClientID = "admin-cli"
	// defaultAuthRealm is the realm the admin account lives in on a stock
	// install. A service account instead lives in the realm it serves, so the
	// caller overrides this with --auth-realm.
	defaultAuthRealm = "master"
	// requestTimeout bounds a single admin API call.
	requestTimeout = 60 * time.Second
)

type KeycloakConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	baseURL   string
	host      string
	authRealm string
	client    *http.Client
	tokens    *tokenSource
}

func NewKeycloakConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*KeycloakConnection, error) {
	conn := &KeycloakConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	httpClient, err := newHTTPClient(conf)
	if err != nil {
		return nil, err
	}
	conn.client = httpClient

	rawURL := option(conf, "url")
	if rawURL == "" {
		rawURL = os.Getenv("KEYCLOAK_URL")
	}
	if rawURL == "" {
		return nil, errors.New("a Keycloak base URL is required (set KEYCLOAK_URL or use --url)")
	}

	base, host, err := NormalizeBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	conn.baseURL = base
	conn.host = host

	clientID := option(conf, "client-id")
	if clientID == "" {
		clientID = os.Getenv("KEYCLOAK_CLIENT_ID")
	}
	username := option(conf, "username")
	if username == "" {
		username = os.Getenv("KEYCLOAK_USERNAME")
	}

	// A credential carrying a user name is the admin password, one without is
	// the client secret. Both can be present at once, since a password login
	// against a confidential client needs the secret as well.
	var userPassword, clientSecret string
	for _, cred := range conf.Credentials {
		if cred == nil || cred.Type != vault.CredentialType_password || len(cred.Secret) == 0 {
			continue
		}
		if cred.User != "" {
			username = cred.User
			userPassword = string(cred.Secret)
			continue
		}
		clientSecret = string(cred.Secret)
	}
	if userPassword == "" {
		userPassword = os.Getenv("KEYCLOAK_PASSWORD")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	}

	authRealm := option(conf, "auth-realm")
	if authRealm == "" {
		authRealm = os.Getenv("KEYCLOAK_AUTH_REALM")
	}

	form, err := grantForm(clientID, clientSecret, username, userPassword)
	if err != nil {
		return nil, err
	}
	if authRealm == "" {
		authRealm = defaultAuthRealmFor(form.Get("grant_type"), conn.RealmFilter())
	}
	conn.authRealm = authRealm

	conn.tokens = newTokenSource(conn.client, conn.baseURL+"/realms/"+url.PathEscape(authRealm)+"/protocol/openid-connect/token", form)

	return conn, nil
}

// newHTTPClient builds the client both the token endpoint and the admin API are
// called through.
func newHTTPClient(conf *inventory.Config) (*http.Client, error) {
	client := &http.Client{Timeout: requestTimeout}

	// A Keycloak server is commonly published under a private certificate
	// authority. Trusting that authority keeps the certificate checked, which
	// skipping verification would not.
	pem, err := CACertificate(conf)
	if err != nil {
		return nil, err
	}
	if len(pem) == 0 {
		return client, nil
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		// A system pool that cannot be read is replaced rather than dropped,
		// so the named authority still applies.
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("keycloak ca certificate holds no PEM certificate, check --ca-cert")
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	return client, nil
}

// CACertificate returns the certificate authority the connection was told to
// trust. The option carries either the PEM itself or a path to it, since a
// certificate is awkward to paste into a shell.
func CACertificate(conf *inventory.Config) ([]byte, error) {
	value := option(conf, OptionCACert)
	if value == "" {
		value = os.Getenv("KEYCLOAK_CA_CERT")
	}
	if value == "" {
		return nil, nil
	}

	if strings.Contains(value, "-----BEGIN") {
		return []byte(value), nil
	}

	pem, err := os.ReadFile(value)
	if err != nil {
		return nil, errors.New("cannot read keycloak ca certificate: " + err.Error())
	}
	return pem, nil
}

// grantForm builds the token request for whichever credentials were supplied. A
// user name selects the password grant, a bare client secret selects client
// credentials.
func grantForm(clientID, clientSecret, username, password string) (url.Values, error) {
	form := url.Values{}

	switch {
	case username != "":
		if password == "" {
			return nil, errors.New("keycloak password authentication requires a password, pass --password or set KEYCLOAK_PASSWORD")
		}
		if clientID == "" {
			clientID = defaultAuthClientID
		}
		form.Set("grant_type", "password")
		form.Set("username", username)
		form.Set("password", password)

	case clientSecret != "":
		if clientID == "" {
			return nil, errors.New("keycloak service account authentication requires a client id, pass --client-id or set KEYCLOAK_CLIENT_ID")
		}
		form.Set("grant_type", "client_credentials")

	default:
		return nil, errors.New("keycloak requires either an admin user (--username and --password) or a service account (--client-id and --client-secret)")
	}

	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return form, nil
}

// defaultAuthRealmFor picks the realm the token is requested from when the
// caller did not name one. An admin user lives in master, while a service
// account lives in the realm it was created for, which is the realm under scan.
func defaultAuthRealmFor(grantType, scopedRealm string) string {
	if grantType == "client_credentials" && scopedRealm != "" {
		return scopedRealm
	}
	return defaultAuthRealm
}

// NormalizeBaseURL trims the trailing slash a copied URL usually carries and
// returns the root the admin API is served under, together with the host used
// to identify the server. A URL without a scheme is rejected rather than
// silently treated as a path.
func NormalizeBaseURL(raw string) (string, string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", "", errors.New("keycloak base URL is empty")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", "", errors.New("keycloak base URL is not a valid URL: " + raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", errors.New("keycloak base URL must start with http:// or https://, got: " + raw)
	}
	if parsed.Host == "" {
		return "", "", errors.New("keycloak base URL has no host: " + raw)
	}

	return trimmed, parsed.Host, nil
}

func (c *KeycloakConnection) Name() string {
	return "keycloak"
}

func (c *KeycloakConnection) Asset() *inventory.Asset {
	return c.asset
}

// Host returns the host of the Keycloak server, which identifies the server
// across the realms it hosts.
func (c *KeycloakConnection) Host() string {
	return c.host
}

// BaseURL returns the root the admin API is served under.
func (c *KeycloakConnection) BaseURL() string {
	return c.baseURL
}

// AuthRealm returns the realm the token was requested from. A discovered realm
// asset carries it forward, because the default depends on the realm the
// connection is scoped to. Without it, a service account discovered from an
// unscoped root would ask its own realm for a token instead of the realm the
// root authenticated against.
func (c *KeycloakConnection) AuthRealm() string {
	return c.authRealm
}

// RealmFilter returns the realm the connection is scoped to. It is the empty
// string when every realm the credentials can read is in scope.
func (c *KeycloakConnection) RealmFilter() string {
	// A discovered realm asset carries its realm under realmName, while the
	// --realm flag arrives as realm. Reading only the flag would leave every
	// discovered asset unscoped, so each one would report every realm.
	if realm := option(c.Conf, "realmName"); realm != "" {
		return realm
	}
	return option(c.Conf, "realm")
}

func option(conf *inventory.Config, key string) string {
	if conf == nil || conf.Options == nil {
		return ""
	}
	return conf.Options[key]
}

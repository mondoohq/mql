// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/oauthlogin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	rangerUtils "go.mondoo.com/mql/utils/ranger"
	"go.mondoo.com/ranger-rpc"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// sessionMinRemaining is how long an existing login session must stay valid
// for login to keep it instead of starting a new login.
const sessionMinRemaining = 5 * time.Minute

// sessionCheckTimeout bounds the request that verifies an existing session.
const sessionCheckTimeout = 30 * time.Second

// sessionRevokeTimeout bounds revoking a replaced session. It is best effort,
// so it must not hold up a login that already succeeded for long.
const sessionRevokeTimeout = 10 * time.Second

// sessionPinger verifies a session credential against the server.
type sessionPinger func(ctx context.Context, apiEndpoint string, httpClient *http.Client, cred *upstream.ServiceAccountCredentials) error

// sessionRevoker revokes a session credential on the server.
type sessionRevoker func(ctx context.Context, httpClient *http.Client, issuer, accessToken, privateKeyPEM string) error

// pingSession runs the authenticated PingPong with the session's certificate.
func pingSession(ctx context.Context, apiEndpoint string, httpClient *http.Client, cred *upstream.ServiceAccountCredentials) error {
	plugins := []ranger.ClientPlugin{}
	plugins = append(plugins, rangerUtils.DefaultRangerPlugins(mql.DefaultFeatures, nil)...)
	certAuth, err := upstream.NewServiceAccountRangerPlugin(cred)
	if err != nil {
		return status.Error(codes.Unauthenticated, "the stored credential cannot be loaded: "+err.Error())
	}
	plugins = append(plugins, certAuth)
	client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
	if err != nil {
		return err
	}
	_, err = client.PingPong(ctx, &upstream.Ping{})
	return err
}

// revokeSession revokes a session credential. The issuer was accepted when
// the session was created, so it is not refused now.
func revokeSession(ctx context.Context, httpClient *http.Client, issuer, accessToken, privateKeyPEM string) error {
	return oauthlogin.Revoke(ctx, httpClient, issuer, accessToken, privateKeyPEM, true)
}

// existingSession decides whether login keeps the interactive login session
// in opts instead of starting a new login. It keeps it when the session is for
// the same server, stays valid for more than sessionMinRemaining, and the
// server still accepts it.
//
// It returns false, with the reason logged at debug level, when a new login is
// needed. It returns an error when the server cannot be reached to verify the
// session: a new login against that server would fail too.
func existingSession(ctx context.Context, opts *config.Config, apiEndpointOverride string, force bool, now time.Time, httpClient *http.Client, ping sessionPinger) (bool, error) {
	if opts == nil || !opts.IsOAuthSession() {
		return false, nil
	}
	if force {
		log.Debug().Msg("--force: starting a new login")
		return false, nil
	}
	// --api-endpoint also replaces api_endpoint in opts, so the issuer is
	// what still names the session's server.
	if apiEndpointOverride != "" && !sameServer(apiEndpointOverride, opts.Authentication.Issuer) {
		log.Debug().Str("api_endpoint", apiEndpointOverride).Str("session_issuer", opts.Authentication.Issuer).
			Msg("the login session is for a different server, starting a new login")
		return false, nil
	}
	notAfter, ok := opts.SessionExpiry()
	if !ok {
		log.Debug().Msg("the login session's certificate cannot be read, starting a new login")
		return false, nil
	}
	if remaining := notAfter.Sub(now); remaining <= sessionMinRemaining {
		log.Debug().Time("valid_until", notAfter).Msg("the login session expired or expires soon, starting a new login")
		return false, nil
	}

	cred := opts.GetServiceCredential()
	if cred == nil {
		log.Debug().Msg("the login session has no credential, starting a new login")
		return false, nil
	}
	apiEndpoint := opts.UpstreamApiEndpoint()
	pingCtx, cancel := context.WithTimeout(ctx, sessionCheckTimeout)
	defer cancel()
	if err := ping(pingCtx, apiEndpoint, httpClient, cred); err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.PermissionDenied:
			log.Debug().Err(err).Msg("the server no longer accepts the login session, starting a new login")
			return false, nil
		}
		return false, errors.Wrapf(err, "could not verify the existing login session with %s", apiEndpoint)
	}
	return true, nil
}

// alreadyLoggedInMessage tells the user that the existing session is kept and
// how to replace it.
func alreadyLoggedInMessage(opts *config.Config, binaryName string, now time.Time) string {
	if binaryName == "" {
		binaryName = "mql"
	}
	info := oauthlogin.SessionInfo{SpaceMrn: opts.GetScopeMrn()}
	if a := opts.Authentication; a != nil {
		info.UserEmail = a.UserEmail
		info.UserName = a.UserName
		info.UserMrn = a.UserMrn
		info.SpaceName = a.SpaceName
		info.OrgName = a.OrgName
	}
	info.ValidUntil, _ = opts.SessionExpiry()
	return info.Summary("✓ Already logged in", now) + "\n" +
		fmt.Sprintf("Run %q first, or %q to log in again.", binaryName+" logout", binaryName+" login --force")
}

// replacedSession is an interactive login session that a new login replaces.
type replacedSession struct {
	issuer        string
	accessToken   string
	privateKeyPEM string
}

// sessionToReplace returns the session in opts that a new login would leave
// behind on the server, or nil when there is nothing to revoke.
func sessionToReplace(opts *config.Config, now time.Time) *replacedSession {
	if opts == nil || !opts.IsOAuthSession() || opts.Authentication.AccessToken == "" || opts.PrivateKey == "" {
		return nil
	}
	if notAfter, ok := opts.SessionExpiry(); ok && !now.Before(notAfter) {
		return nil
	}
	issuer := opts.Authentication.Issuer
	if issuer == "" {
		issuer = opts.UpstreamApiEndpoint()
	}
	return &replacedSession{
		issuer:        issuer,
		accessToken:   opts.Authentication.AccessToken,
		privateKeyPEM: opts.PrivateKey,
	}
}

// revokeReplaced revokes the session a new login replaced, so it does not
// stay valid on the server. Best effort: a failure is only logged.
func revokeReplaced(ctx context.Context, old *replacedSession, newAccessToken string, httpClient *http.Client, revoke sessionRevoker) {
	if old == nil || old.accessToken == newAccessToken {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, sessionRevokeTimeout)
	defer cancel()
	if err := revoke(ctx, httpClient, old.issuer, old.accessToken, old.privateKeyPEM); err != nil {
		log.Debug().Err(err).Msg("could not revoke the previous login session, it expires on its own")
		return
	}
	log.Debug().Msg("revoked the previous login session")
}

// sameServer reports whether endpoint names the same server as one of
// sessionEndpoints. Loopback names are treated as one host.
func sameServer(endpoint string, sessionEndpoints ...string) bool {
	want := normalizeEndpoint(endpoint)
	for _, e := range sessionEndpoints {
		if e != "" && normalizeEndpoint(e) == want {
			return true
		}
	}
	return false
}

func normalizeEndpoint(endpoint string) string {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Host == "" {
		return strings.TrimRight(strings.ToLower(strings.TrimSpace(endpoint)), "/")
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "localhost", "127.0.0.1", "::1":
		host = "loopback"
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port + strings.TrimRight(u.Path, "/")
}

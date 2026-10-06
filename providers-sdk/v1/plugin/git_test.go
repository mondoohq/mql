// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/stretchr/testify/require"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// isolateTempDir points os.TempDir at a fresh directory and returns it, so a
// test can see exactly which clone directories gitClone created and left.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func cloneDirsIn(t *testing.T, tmp string) []string {
	t.Helper()
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	var dirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "mql-git-clone") {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

func TestGitClone_ReturnsTheRepositoryAndACloserThatRemovesIt(t *testing.T) {
	resetGitTransport(t)
	tmp := isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:"+fixtureToken))
	require.NoError(t, err)
	require.NotNil(t, closer)

	got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, fixtureMainTF, string(got))
	require.Len(t, cloneDirsIn(t, tmp), 1)

	closer()
	require.Empty(t, cloneDirsIn(t, tmp))
}

// A failed clone used to come back as ("", nil, nil): the deferred cleanup
// assigned the function's shared err, which wiped the real one. Callers then
// carried on with an empty path. These tests pin the error and the cleanup.
func TestGitClone_AuthenticationFailureIsReturnedAsAnError(t *testing.T) {
	resetGitTransport(t)
	tmp := isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:not-the-token"))

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to clone git repo")
	require.ErrorIs(t, err, transport.ErrAuthenticationRequired)
	require.Empty(t, dir)
	require.Nil(t, closer)
	require.Empty(t, cloneDirsIn(t, tmp), "a failed clone must not leave its temp dir behind")
}

func TestGitClone_EmptyRepositoryIsReturnedAsAnError(t *testing.T) {
	resetGitTransport(t)
	tmp := isolateTempDir(t)
	srv := newEmptyFakeGitServer(t, fakeStandard, fixtureToken)

	dir, closer, err := gitClone(srv.repoURL("localhost", "ci:"+fixtureToken))

	require.Error(t, err)
	require.ErrorContains(t, err, "remote repository is empty")
	require.Empty(t, dir)
	require.Nil(t, closer)
	require.Empty(t, cloneDirsIn(t, tmp))
}

func gitAsset(httpURL string, creds ...*vault.Credential) *inventory.Asset {
	return &inventory.Asset{
		Name: "fixture",
		Connections: []*inventory.Config{{
			Options:     map[string]string{"http-url": httpURL},
			Credentials: creds,
		}},
	}
}

func passwordCred(user, secret, password string) *vault.Credential {
	c := &vault.Credential{Type: vault.CredentialType_password, User: user, Password: password}
	if secret != "" {
		c.Secret = []byte(secret)
	}
	return c
}

func TestNewGitClone_BadCredentialsReturnAnErrorAndNoPath(t *testing.T) {
	resetGitTransport(t)
	isolateTempDir(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	path, closer, err := NewGitClone(gitAsset(srv.repoURL("localhost", ""), passwordCred("ci", "wrong-token", "")))

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to clone git repo")
	require.Empty(t, path)
	require.Nil(t, closer)
	require.NotContains(t, err.Error(), "wrong-token")
}

func TestNewGitClone_InputErrorsAreUnchanged(t *testing.T) {
	_, _, err := NewGitClone(&inventory.Asset{Connections: []*inventory.Config{{}}})
	require.EqualError(t, err, "missing URLs in options for HCL over Git connection")

	_, _, err = NewGitClone(&inventory.Asset{Name: "n", Connections: []*inventory.Config{{Options: map[string]string{"other": "x"}}}})
	require.EqualError(t, err, "missing url for git repo n")
}

// go-git copies the request URL into its HTTP errors. It redacts a password but
// not a username, and NewGitClone puts a token with no user name into the
// username slot. A server error therefore used to print the token.
func TestGitClone_ErrorsNeverContainTheCredential(t *testing.T) {
	resetGitTransport(t)
	tests := []struct {
		name     string
		token    string
		userinfo func(token string) *url.Userinfo
	}{
		{"user and token", fixtureToken, func(s string) *url.Userinfo { return url.UserPassword("ci", s) }},
		{"token as the user name", fixtureToken, url.User},
		{"token that needs escaping, as the user name", "p@ss/w rd+1%x", url.User},
		{"token as the user name with an empty password", fixtureToken, func(s string) *url.Userinfo { return url.UserPassword(s, "") }},
		{"token that needs escaping, as the password", "p@ss/w:rd 1+x", func(s string) *url.Userinfo { return url.UserPassword("ci", s) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateTempDir(t)
			// A strict Azure DevOps fake reached through a host the router
			// does not adjust answers go-git's default request with a 400,
			// which is an error whose text carries the request URL.
			srv := newFakeGitServer(t, fakeAzureDevOps, tt.token)
			u := srv.repoURL("localhost", "")
			parsed, err := url.Parse(u)
			require.NoError(t, err)
			parsed.User = tt.userinfo(tt.token)

			_, _, err = gitClone(parsed.String())

			require.Error(t, err)
			require.ErrorContains(t, err, "status code: 400", "the failure must be the server's 400, not an auth error")
			require.NotContains(t, err.Error(), tt.token)
			require.NotContains(t, err.Error(), url.PathEscape(tt.token))
			require.NotContains(t, err.Error(), url.User(tt.token).String())
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	cause := errors.New("GET http://abc123@host/x failed")

	require.NoError(t, redactSecrets(nil, []string{"abc123"}))
	require.Same(t, cause, redactSecrets(cause, nil), "nothing to hide: the error is returned as is")

	redacted := redactSecrets(cause, []string{"abc123"})
	require.EqualError(t, redacted, "GET http://_obfuscated_@host/x failed")
	require.ErrorIs(t, redacted, cause, "the cause stays reachable")
}

// A secret can be a substring of its own escaped spelling ("tok%" inside
// "tok%25"). Replacing the short one first would leave a fragment of the long
// one behind, whatever order the caller listed them in.
func TestRedactSecrets_ReplacesTheLongestSpellingFirst(t *testing.T) {
	cause := errors.New("GET http://tok%25@host/x failed")

	for _, secrets := range [][]string{{"tok%", "tok%25"}, {"tok%25", "tok%"}} {
		given := append([]string(nil), secrets...)
		redacted := redactSecrets(cause, given)

		require.EqualError(t, redacted, "GET http://_obfuscated_@host/x failed")
		require.Equal(t, secrets, given, "the caller's slice is not reordered")
	}
	require.EqualError(t, redactSecrets(cause, urlSecrets("https://tok%25@host/p")), "GET http://_obfuscated_@host/x failed")
}

func TestURLSecrets(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"no credentials", "https://host/p", nil},
		{"unparseable", "http://[::1", nil},
		{"empty user", "https://@host/p", nil},
		{"empty user and empty password", "https://:@host/p", nil},
		{"user and password: the password is the secret", "https://ci:tok@host/p", []string{"tok"}},
		{"token only: the user name is the secret", "https://tok@host/p", []string{"tok"}},
		{"token and an empty password: the user name is the secret", "https://tok:@host/p", []string{"tok"}},
		{"escaped spellings are listed too", "https://p%40ss:w%2Frd@host/p", []string{"w/rd", "w%2Frd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, urlSecrets(tt.raw))
		})
	}
}

func TestGitClone_InstallsTheRouterOnFirstUse(t *testing.T) {
	resetGitTransport(t)
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)
	require.Same(t, stockHTTP, client.Protocols["http"], "precondition: nothing is routed yet")

	_, closer, err := gitClone(srv.repoURL("localhost", "ci:"+fixtureToken))
	require.NoError(t, err)
	closer()

	for scheme, stock := range map[string]transport.Transport{"http": stockHTTP, "https": stockHTTPS} {
		router, ok := client.Protocols[scheme].(*hostRoutedTransport)
		require.True(t, ok, scheme)
		require.Same(t, stock, router.base, scheme)
	}
}

// NewGitClone is what the seven provider families call. These tests drive it
// the way they do: an asset with an http-url option and a password credential.
func TestNewGitClone_ClonesWithEveryCredentialShape(t *testing.T) {
	tests := []struct {
		name string
		cred *vault.Credential
	}{
		{"user and secret", passwordCred("ci", fixtureToken, "")},
		{"user and password field", passwordCred("ci", "", fixtureToken)},
		{"token only, in the secret", passwordCred("", fixtureToken, "")},
		{"token only, in the password field", passwordCred("", "", fixtureToken)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := isolateTempDir(t)
			resetGitTransport(t)
			routeLoopbackAsADO(t)
			// Strict Azure DevOps fake on the host the router treats as Azure
			// DevOps: the clone only works if the router adjusted the request.
			srv := newFakeGitServer(t, fakeAzureDevOps, fixtureToken)
			httpURL := srv.repoURL("127.0.0.1", "")
			asset := gitAsset(httpURL, tt.cred)

			dir, closer, err := NewGitClone(asset)
			require.NoError(t, err)
			require.NotNil(t, closer)

			got, err := os.ReadFile(filepath.Join(dir, "main.tf"))
			require.NoError(t, err)
			require.Equal(t, fixtureMainTF, string(got))

			// The tracked link is the URL as configured, with no credential.
			require.Equal(t, httpURL, asset.Connections[0].Options[GitUrlOptionKey])
			require.NotContains(t, asset.Connections[0].Options[GitUrlOptionKey], fixtureToken)

			closer()
			require.Empty(t, cloneDirsIn(t, tmp))
		})
	}
}

func TestNewGitClone_NonAzureDevOpsHostCloneIsUnchanged(t *testing.T) {
	resetGitTransport(t)
	isolateTempDir(t)
	routeLoopbackAsADO(t) // 127.0.0.1 is routed; localhost is the "GitHub or GitLab" host
	srv := newFakeGitServer(t, fakeStandard, fixtureToken)

	// Control: go-git's own transport against the URL NewGitClone builds from
	// this credential.
	_, err := cloneWithStockTransport(t, srv.repoURL("localhost", "oauth2:"+fixtureToken))
	require.NoError(t, err)

	dir, closer, err := NewGitClone(gitAsset(srv.repoURL("localhost", ""), passwordCred("oauth2", fixtureToken, "")))

	require.NoError(t, err)
	defer closer()
	require.FileExists(t, filepath.Join(dir, "main.tf"))
	reqs := srv.uploadPackRequests()
	require.Len(t, reqs, 2)
	for i, r := range reqs {
		require.Equal(t, []string{"agent", "ofs-delta", "shallow", "side-band-64k"}, capSet(r.Caps), "request %d", i)
	}
	// Same request bytes and the same headers as the control's.
	require.Equal(t, string(reqs[0].Body), string(reqs[1].Body))
	require.NotEmpty(t, reqs[0].Header.Get("Authorization"))
	require.Equal(t, reqs[0].Header, reqs[1].Header)
	adverts := srv.advertisementHeaders()
	require.Len(t, adverts, 2)
	require.Equal(t, adverts[0], adverts[1])
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
	"go.mondoo.com/mql/types"
)

// clearEnv keeps the developer's own environment out of a test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envToken, envClientSecret, envTenantID, envClientID} {
		t.Setenv(k, "")
	}
}

// captureLogs collects what the provider logs for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

func parse(t *testing.T, args []string, flags map[string]*llx.Primitive) (*inventory.Config, error) {
	t.Helper()
	res, err := Init().ParseCLI(&plugin.ParseCLIReq{Connector: "azuredevops", Args: args, Flags: flags})
	if err != nil {
		return nil, err
	}
	require.Len(t, res.Asset.Connections, 1)
	return res.Asset.Connections[0], nil
}

func TestParseCLIOrganizationWithAToken(t *testing.T) {
	clearEnv(t)

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"token": llx.StringPrimitive("fake-token"),
	})
	require.NoError(t, err)

	assert.Equal(t, "azuredevops", conf.Type)
	assert.Equal(t, "mondoo-ado-scan-test", conf.Options[connection.OPTION_ORGANIZATION])
	assert.NotContains(t, conf.Options, connection.OPTION_TENANT_ID)
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, vault.CredentialType_password, conf.Credentials[0].Type)
	assert.Equal(t, "fake-token", string(conf.Credentials[0].Secret))
	assert.Equal(t, []string{"auto"}, conf.Discover.Targets, "auto is the default")
}

func TestParseCLIOrganizationFromAnAddress(t *testing.T) {
	clearEnv(t)
	flags := map[string]*llx.Primitive{"token": llx.StringPrimitive("fake-token")}

	conf, err := parse(t, []string{"org", "https://dev.azure.com/mondoo-ado-scan-test"}, flags)
	require.NoError(t, err)
	assert.Equal(t, "mondoo-ado-scan-test", conf.Options[connection.OPTION_ORGANIZATION])

	conf, err = parse(t, []string{"org", "https://mondoo-ado-scan-test.visualstudio.com"}, flags)
	require.NoError(t, err)
	assert.Equal(t, "mondoo-ado-scan-test", conf.Options[connection.OPTION_ORGANIZATION])

	// as copied from a browser's address bar, without the scheme
	for _, addr := range []string{"dev.azure.com/mondoo-ado-scan-test", "mondoo-ado-scan-test.visualstudio.com/scan-test"} {
		conf, err = parse(t, []string{"org", addr}, flags)
		require.NoError(t, err, addr)
		assert.Equal(t, "mondoo-ado-scan-test", conf.Options[connection.OPTION_ORGANIZATION], addr)
	}

	_, err = parse(t, []string{"org", "https://example.com/mondoo-ado-scan-test"}, flags)
	require.Error(t, err)
}

func TestParseCLITokenFromTheEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv(envToken, "env-token")

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, nil)
	require.NoError(t, err)
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "env-token", string(conf.Credentials[0].Secret))
}

func TestParseCLIServicePrincipalFromFlags(t *testing.T) {
	clearEnv(t)

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"tenant-id":     llx.StringPrimitive("00000000-0000-4000-8000-0000000000aa"),
		"client-id":     llx.StringPrimitive("00000000-0000-4000-8000-0000000000bb"),
		"client-secret": llx.StringPrimitive("fake-secret"),
	})
	require.NoError(t, err)

	assert.Equal(t, "00000000-0000-4000-8000-0000000000aa", conf.Options[connection.OPTION_TENANT_ID])
	assert.Equal(t, "00000000-0000-4000-8000-0000000000bb", conf.Options[connection.OPTION_CLIENT_ID])
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "fake-secret", string(conf.Credentials[0].Secret))
}

func TestParseCLIServicePrincipalFromTheEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv(envTenantID, "00000000-0000-4000-8000-0000000000aa")
	t.Setenv(envClientID, "00000000-0000-4000-8000-0000000000bb")
	t.Setenv(envClientSecret, "fake-secret")

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-4000-8000-0000000000aa", conf.Options[connection.OPTION_TENANT_ID])
	assert.Equal(t, "fake-secret", string(conf.Credentials[0].Secret))
}

// An AZURE_TENANT_ID left in the shell for another tool must not turn a scan
// that was given a token into a service principal scan.
func TestParseCLITokenBeatsAnAmbientTenant(t *testing.T) {
	clearEnv(t)
	t.Setenv(envTenantID, "00000000-0000-4000-8000-0000000000aa")
	t.Setenv(envClientID, "00000000-0000-4000-8000-0000000000bb")
	t.Setenv(envClientSecret, "fake-secret")

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"token": llx.StringPrimitive("fake-token"),
	})
	require.NoError(t, err)

	assert.NotContains(t, conf.Options, connection.OPTION_TENANT_ID)
	assert.Equal(t, "fake-token", string(conf.Credentials[0].Secret))
}

// The same holds when the token, too, comes from the environment.
func TestParseCLIEnvironmentTokenBeatsAnEnvironmentServicePrincipal(t *testing.T) {
	clearEnv(t)
	t.Setenv(envToken, "env-token")
	t.Setenv(envTenantID, "00000000-0000-4000-8000-0000000000aa")
	t.Setenv(envClientID, "00000000-0000-4000-8000-0000000000bb")
	t.Setenv(envClientSecret, "fake-secret")

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, nil)
	require.NoError(t, err)

	assert.NotContains(t, conf.Options, connection.OPTION_TENANT_ID)
	assert.NotContains(t, conf.Options, connection.OPTION_CLIENT_ID)
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "env-token", string(conf.Credentials[0].Secret))
}

// Service principal flags are an explicit choice, so they win over a token,
// and the user is told the token is not used.
func TestParseCLIServicePrincipalFlagsBeatATokenAndWarn(t *testing.T) {
	clearEnv(t)
	logs := captureLogs(t)

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"token":         llx.StringPrimitive("fake-token-value"),
		"tenant-id":     llx.StringPrimitive("00000000-0000-4000-8000-0000000000aa"),
		"client-id":     llx.StringPrimitive("00000000-0000-4000-8000-0000000000bb"),
		"client-secret": llx.StringPrimitive("fake-secret"),
	})
	require.NoError(t, err)

	assert.Equal(t, "00000000-0000-4000-8000-0000000000aa", conf.Options[connection.OPTION_TENANT_ID])
	assert.Equal(t, "00000000-0000-4000-8000-0000000000bb", conf.Options[connection.OPTION_CLIENT_ID])
	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "fake-secret", string(conf.Credentials[0].Secret))
	assert.Contains(t, logs.String(), "both a personal access token and a service principal were provided")
	assert.NotContains(t, logs.String(), "fake-token-value")
	assert.NotContains(t, logs.String(), "fake-secret")
}

// A token wins over a lone --client-secret, which would otherwise be dropped
// without a word.
func TestParseCLIWarnsThatATokenIgnoresTheClientSecret(t *testing.T) {
	clearEnv(t)
	logs := captureLogs(t)

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"token":         llx.StringPrimitive("fake-token"),
		"client-secret": llx.StringPrimitive("fake-secret-value"),
	})
	require.NoError(t, err)

	require.Len(t, conf.Credentials, 1)
	assert.Equal(t, "fake-token", string(conf.Credentials[0].Secret))
	assert.Contains(t, logs.String(), "--client-secret")
	assert.NotContains(t, logs.String(), "fake-secret-value")
}

func TestParseCLIRejectsIncompleteCredentials(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]*llx.Primitive
		wantErr string
	}{
		{"nothing", nil, "--token"},
		{"a tenant without a client", map[string]*llx.Primitive{
			"tenant-id": llx.StringPrimitive("00000000-0000-4000-8000-0000000000aa"),
		}, "both --tenant-id and --client-id"},
		{"a client without a tenant", map[string]*llx.Primitive{
			"client-id": llx.StringPrimitive("00000000-0000-4000-8000-0000000000bb"),
		}, "both --tenant-id and --client-id"},
		{"a service principal without a secret", map[string]*llx.Primitive{
			"tenant-id": llx.StringPrimitive("00000000-0000-4000-8000-0000000000aa"),
			"client-id": llx.StringPrimitive("00000000-0000-4000-8000-0000000000bb"),
		}, "--client-secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			_, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, tc.flags)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestParseCLIRepository(t *testing.T) {
	clearEnv(t)
	flags := map[string]*llx.Primitive{"token": llx.StringPrimitive("fake-token")}

	conf, err := parse(t, []string{"repo", "mondoo-ado-scan-test/scan test/ado-scan-test-iac"}, flags)
	require.NoError(t, err)
	assert.Equal(t, "mondoo-ado-scan-test", conf.Options[connection.OPTION_ORGANIZATION])
	assert.Equal(t, "scan test", conf.Options[connection.OPTION_PROJECT])
	assert.Equal(t, "ado-scan-test-iac", conf.Options[connection.OPTION_REPOSITORY])

	for _, bad := range []string{"mondoo-ado-scan-test/ado-scan-test-iac", "a/b/c/d", "a//c", "/b/c"} {
		_, err := parse(t, []string{"repo", bad}, flags)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), "<organization>/<project>/<repository>", bad)
	}
}

// A clone address with a token in it is a likely thing to paste, and the error
// that rejects it must not print the token back.
func TestParseCLIErrorsLeaveAPastedTokenOut(t *testing.T) {
	clearEnv(t)
	const pasted = "pastedpatvalue7q"
	flags := map[string]*llx.Primitive{"token": llx.StringPrimitive("fake-token")}

	for _, args := range [][]string{
		{"repo", "https://user:" + pasted + "@dev.azure.com/org/project/_git/repo"},
		{"repo", "user:" + pasted + "@dev.azure.com/org/project"},
		{"repo", pasted + "@org/project/repo"},
		{"org", "https://user:" + pasted + "@example.com/org"},
		{"org", "user:" + pasted + "@dev.azure.com"},
		{"org", "user:" + pasted + "@dev.azure.com/org"},
	} {
		_, err := parse(t, args, flags)
		require.Error(t, err, args[0])
		assert.NotContains(t, err.Error(), pasted, args[0])
	}
}

func TestParseCLIRejectsABadCommand(t *testing.T) {
	clearEnv(t)
	flags := map[string]*llx.Primitive{"token": llx.StringPrimitive("fake-token")}

	_, err := parse(t, []string{"user", "someone"}, flags)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org or repo")

	_, err = parse(t, nil, flags)
	require.Error(t, err)

	_, err = parse(t, []string{"org"}, flags)
	require.Error(t, err)
}

func TestParseCLIDiscoveryAndFilters(t *testing.T) {
	clearEnv(t)

	conf, err := parse(t, []string{"org", "mondoo-ado-scan-test"}, map[string]*llx.Primitive{
		"token": llx.StringPrimitive("fake-token"),
		"discover": llx.ArrayPrimitive([]*llx.Primitive{
			llx.StringPrimitive("repos"), llx.StringPrimitive("terraform"),
		}, types.String),
		"repos":         llx.StringPrimitive("scan-test/*"),
		"repos-exclude": llx.StringPrimitive("scan-test/ado-scan-test-app"),
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"repos", "terraform"}, conf.Discover.Targets)
	assert.Equal(t, "scan-test/*", conf.Options[connection.OPTION_REPOS])
	assert.Equal(t, "scan-test/ado-scan-test-app", conf.Options[connection.OPTION_REPOS_EXCLUDE])
}

// connectReq is a request against the fake organization. A nil targets slice
// leaves discovery off.
func connectReq(t *testing.T, srv *fakeado.Server, extra map[string]string, targets []string, secret string) *plugin.ConnectReq {
	t.Helper()
	opts := map[string]string{
		connection.OPTION_ORGANIZATION: fakeado.Org,
		connection.OPTION_API_ENDPOINT: srv.URL,
	}
	for k, v := range extra {
		opts[k] = v
	}
	conf := &inventory.Config{
		Type:        "azuredevops",
		Options:     opts,
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", secret)},
	}
	if targets != nil {
		conf.Discover = &inventory.Discovery{Targets: targets}
	}
	return &plugin.ConnectReq{Asset: &inventory.Asset{Connections: []*inventory.Config{conf}}}
}

func TestConnectOrganization(t *testing.T) {
	srv := fakeado.New(t)
	res, err := Init().Connect(connectReq(t, srv, nil, []string{"auto"}, fakeado.PAT), nil)
	require.NoError(t, err)

	assert.Equal(t, "azuredevops.organization", res.Root)
	assert.Equal(t, "azuredevops", res.Name)
	assert.Equal(t, connection.PlatformOrg, res.Asset.Platform.Name)
	assert.Equal(t, fakeado.Org, res.Asset.Name)
	// the organization and the four repositories that can be scanned
	require.NotNil(t, res.Inventory)
	assert.Len(t, res.Inventory.Spec.Assets, 5)
}

func TestConnectRepository(t *testing.T) {
	srv := fakeado.New(t)
	res, err := Init().Connect(connectReq(t, srv, map[string]string{
		connection.OPTION_PROJECT:    "scan test",
		connection.OPTION_REPOSITORY: "ado-scan-test-iac",
	}, []string{"auto"}, fakeado.PAT), nil)
	require.NoError(t, err)

	assert.Equal(t, "azuredevops.repository", res.Root)
	assert.Equal(t, connection.PlatformRepo, res.Asset.Platform.Name)
	assert.Equal(t, "scan test/ado-scan-test-iac", res.Asset.Name)
	require.Len(t, res.Inventory.Spec.Assets, 1)
	assert.Equal(t, "scan test/ado-scan-test-iac", res.Inventory.Spec.Assets[0].Name)
}

func TestConnectWithoutDiscoveryHasNoInventory(t *testing.T) {
	srv := fakeado.New(t)
	res, err := Init().Connect(connectReq(t, srv, nil, nil, fakeado.PAT), nil)
	require.NoError(t, err)

	assert.Nil(t, res.Inventory)
	assert.Equal(t, "azuredevops.organization", res.Root)
}

// inventory.WithoutDiscovery leaves an empty Discovery on every asset it
// connects, so a connect with no targets must not walk anything.
func TestConnectWithNoTargetsReadsNoRepository(t *testing.T) {
	srv := fakeado.New(t)
	res, err := Init().Connect(connectReq(t, srv, map[string]string{
		connection.OPTION_PROJECT:    "scan test",
		connection.OPTION_REPOSITORY: "ado-scan-test-iac",
	}, []string{}, fakeado.PAT), nil)
	require.NoError(t, err)

	assert.Nil(t, res.Inventory)
	for _, req := range srv.Requests() {
		assert.NotContains(t, req, "/_apis/git/repositories/", "a connect without targets read %s", req)
	}
}

func TestConnectExplainsARejectedToken(t *testing.T) {
	srv := fakeado.New(t)
	_, err := Init().Connect(connectReq(t, srv, nil, []string{"auto"}, "not-the-token"), nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "personal access token")
	assert.NotContains(t, err.Error(), "not-the-token", "the rejected token is not echoed")
}

func TestConnectVerifiesTheOrganizationOnce(t *testing.T) {
	srv := fakeado.New(t)
	s := Init()

	_, err := s.Connect(connectReq(t, srv, nil, nil, fakeado.PAT), nil)
	require.NoError(t, err)
	// a repository connection to the same organization with the same credential
	_, err = s.Connect(connectReq(t, srv, map[string]string{
		connection.OPTION_PROJECT:    "scan-test",
		connection.OPTION_REPOSITORY: "ado-scan-test-app",
	}, nil, fakeado.PAT), nil)
	require.NoError(t, err)

	var verifications int
	for _, req := range srv.Requests() {
		if strings.Contains(req, "/_apis/connectionData") {
			verifications++
		}
	}
	assert.Equal(t, 1, verifications)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readContainersFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "containers-policy", name))
	require.NoError(t, err)
	return string(b)
}

// The policy the packages from the CRI-O project install: every image
// accepted without any signature check.
func TestParseContainersPolicyStock(t *testing.T) {
	p, err := parseContainersPolicy(readCrioFixture(t, "kubeadm/policy.json"))
	require.NoError(t, err)
	require.Len(t, p.Default, 1)
	assert.Equal(t, "insecureAcceptAnything", p.Default[0].Type)
	assert.Empty(t, p.scopes())
}

func TestParseContainersPolicySigned(t *testing.T) {
	p, err := parseContainersPolicy(readContainersFixture(t, "policy-signed.json"))
	require.NoError(t, err)
	assert.Equal(t, "reject", p.Default[0].Type)

	scopes := p.scopes()
	require.Len(t, scopes, 5)
	got := []string{}
	for _, s := range scopes {
		got = append(got, s.Transport+" "+s.Scope)
	}
	assert.Equal(t, []string{
		"docker ghcr.io/example", "docker quay.io/legacy", "docker registry.example.com/platform",
		"docker registry.k8s.io", "docker-daemon ",
	}, got, "by transport, then scope")

	byScope := map[string]containersPolicyRequirement{}
	for _, s := range scopes {
		byScope[s.Scope] = s.Requirements[0]
	}
	gpg := byScope["registry.example.com/platform"]
	assert.Equal(t, "signedBy", gpg.Type)
	assert.Equal(t, "GPGKeys", gpg.KeyType)
	assert.Equal(t, []string{"/etc/pki/containers/platform.gpg"}, gpg.keyPaths())
	assert.Equal(t, "matchRepoDigestOrExact", gpg.SignedIdentity["type"])

	keyless := byScope["ghcr.io/example"]
	assert.Equal(t, "sigstoreSigned", keyless.Type)
	require.NotNil(t, keyless.Fulcio)
	assert.Equal(t, "https://token.actions.githubusercontent.com", keyless.Fulcio.OIDCIssuer)
	assert.Equal(t, "release@example.com", keyless.Fulcio.SubjectEmail)
	assert.Equal(t, []string{"/etc/pki/containers/rekor.pub"}, keyless.rekorKeyPaths())
	assert.Empty(t, keyless.keyPaths())

	inline := byScope["registry.k8s.io"]
	assert.NotEmpty(t, inline.KeyData, "an inline key is reported as present, not by content")
	assert.Empty(t, inline.keyPaths())

	assert.Equal(t, "insecureAcceptAnything", byScope["quay.io/legacy"].Type)
}

func TestParseContainersPolicyMalformed(t *testing.T) {
	_, err := parseContainersPolicy(`{ "default": [ { "type": "reject" } `)
	assert.Error(t, err, "a broken policy must not read as one without requirements")
}

// CentOS Stream 10's containers-common 6.0 ships the policy only as
// /usr/share/containers/policy.json, which Podman 6 reads when there is no
// /etc/containers/policy.json.
func TestContainersPolicyPath(t *testing.T) {
	existing := func(paths ...string) func(string) (bool, error) {
		return func(p string) (bool, error) {
			for _, x := range paths {
				if x == p {
					return true, nil
				}
			}
			return false, nil
		}
	}
	p, err := containersPolicyPath(existing("/etc/containers/policy.json", "/usr/share/containers/policy.json"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/containers/policy.json", p, "the administrator's policy wins")

	p, err = containersPolicyPath(existing("/usr/share/containers/policy.json"))
	require.NoError(t, err)
	assert.Equal(t, "/usr/share/containers/policy.json", p)

	p, err = containersPolicyPath(existing())
	require.NoError(t, err)
	assert.Equal(t, "/etc/containers/policy.json", p, "without either, the missing /etc file is reported")

	_, err = containersPolicyPath(func(string) (bool, error) { return false, assert.AnError })
	assert.Error(t, err)

	policy, err := parseContainersPolicy(readContainersFixture(t, "centos-stream10-usr-share-policy.json"))
	require.NoError(t, err)
	assert.Equal(t, "insecureAcceptAnything", policy.Default[0].Type)
	scopes := policy.scopes()
	require.Len(t, scopes, 3)
	assert.Equal(t, "registry.access.redhat.com", scopes[0].Scope)
	assert.Equal(t, "sigstoreSigned", scopes[0].Requirements[0].Type)
	assert.Equal(t, []string{"/etc/pki/sigstore/SIGSTORE-redhat-release3"}, scopes[0].Requirements[0].keyPaths())
	assert.Equal(t, []string{"/etc/pki/sigstore/REKOR-signing-key"}, scopes[0].Requirements[0].rekorKeyPaths())
}

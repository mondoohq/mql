// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All cases here are synthetic: identities are written in the formats GitHub
// and GitLab ID tokens give Fulcio (job_workflow_ref, ci_config_ref_uri), with
// invented owners and projects.

func keyless(san, issuer, repo, workflow string) Result {
	return Result{SignatureValid: true, SignerKind: SignerKeyless, SAN: san, Issuer: issuer, SignerRepository: repo, SignerWorkflowRef: workflow}
}

func ghResult(repo, workflow, ref string) Result {
	san := "https://github.com/" + repo + "/" + workflow + "@" + ref
	return keyless(san, GitHubActionsIssuer, "https://github.com/"+repo, san)
}

func TestPolicyAccepts(t *testing.T) {
	p, err := ParseSigners("github-actions:org/*")
	require.NoError(t, err)

	assert.True(t, p.Accepts(ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")))
	assert.False(t, p.Accepts(ghResult("other/app", ".github/workflows/release.yml", "refs/heads/main")))
	// A repository whose name starts with the owner is another owner.
	assert.False(t, p.Accepts(ghResult("org-evil/app", ".github/workflows/release.yml", "refs/heads/main")))

	invalid := ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")
	invalid.SignatureValid = false
	assert.False(t, p.Accepts(invalid), "an invalid signature is never accepted")

	assert.False(t, Policy{}.Accepts(ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")), "an empty policy accepts no signer")
}

func TestPolicyAccepts_IssuerExact(t *testing.T) {
	s := ExactKeyless(GitHubActionsIssuer, "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main")
	p, err := NewPolicy(s)
	require.NoError(t, err)
	good := ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")
	assert.True(t, p.Accepts(good))

	// An issuer that extends the configured one is another issuer.
	extended := good
	extended.Issuer = GitHubActionsIssuer + ".evil"
	assert.False(t, p.Accepts(extended))
	prefix := good
	prefix.Issuer = "https://token.actions.githubusercontent.co"
	assert.False(t, p.Accepts(prefix))
}

func TestPolicyAccepts_IdentityMetacharactersEscaped(t *testing.T) {
	// "." and "+" in an exact identity match only themselves.
	id := "build+release@ci.example.com"
	p, err := NewPolicy(ExactKeyless("https://accounts.example.com", id))
	require.NoError(t, err)
	assert.True(t, p.Accepts(keyless(id, "https://accounts.example.com", "", "")))
	assert.False(t, p.Accepts(keyless("buildddrelease@ciXexample.com", "https://accounts.example.com", "", "")))
	assert.False(t, p.Accepts(keyless("x"+id, "https://accounts.example.com", "", "")), "anchored at the start")
	assert.False(t, p.Accepts(keyless(id+".evil", "https://accounts.example.com", "", "")), "anchored at the end")
}

func TestPolicyAccepts_SANPatternAnchored(t *testing.T) {
	// An unanchored pattern written by hand is still matched whole.
	p, err := ParseSigners("oidc:https://accounts.example.com|ci@example\\.com")
	require.NoError(t, err)
	assert.True(t, p.Accepts(keyless("ci@example.com", "https://accounts.example.com", "", "")))
	assert.False(t, p.Accepts(keyless("evil-ci@example.com.attacker.test", "https://accounts.example.com", "", "")))
}

func TestPolicyAccepts_WorkflowPinned(t *testing.T) {
	p, err := ParseSigners("github-actions:org/app@.github/workflows/release.yml@refs/tags/*")
	require.NoError(t, err)
	assert.True(t, p.Accepts(ghResult("org/app", ".github/workflows/release.yml", "refs/tags/v1")))
	assert.False(t, p.Accepts(ghResult("org/app", ".github/workflows/ci.yml", "refs/tags/v1")))
	assert.False(t, p.Accepts(ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")))
}

func TestPolicyAccepts_KeyNeverMatchesKeyless(t *testing.T) {
	sg := newKeySigner(t)
	p, err := NewPolicy(Signer{PublicKey: string(sg.verifierPEM(t))})
	require.NoError(t, err)
	keyRes := Result{SignatureValid: true, SignerKind: SignerKey, KeyFingerprint: sg.fingerprint(t), TransparencyLogged: true}
	assert.True(t, p.Accepts(keyRes))
	unlogged := keyRes
	unlogged.TransparencyLogged = false
	assert.False(t, p.Accepts(unlogged), "a key signature without a log entry is refused by default")

	optOut := false
	p2, err := NewPolicy(Signer{PublicKey: string(sg.verifierPEM(t)), RequireTlog: &optOut})
	require.NoError(t, err)
	assert.True(t, p2.Accepts(unlogged))

	gh, err := ParseSigners("github-actions:org/*")
	require.NoError(t, err)
	assert.False(t, gh.Accepts(keyRes))
	other := keyRes
	other.KeyFingerprint = newKeySigner(t).fingerprint(t)
	assert.False(t, p.Accepts(other))
}

func TestPolicyAccepts_Downgrade(t *testing.T) {
	p, err := ParseSigners("github-actions:org/*")
	require.NoError(t, err)
	r := ghResult("org/app", ".github/workflows/release.yml", "refs/heads/main")
	r.SignedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.SubjectDigests = []string{"sha256:aaaa"}

	p.NotBefore = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	assert.False(t, p.Accepts(r), "a signature older than the floor is a downgrade")
	untimed := r
	untimed.SignedAt = time.Time{}
	assert.False(t, p.Accepts(untimed), "no verified time cannot pass a floor")
	r.SignedAt = p.NotBefore.Add(time.Hour)
	assert.True(t, p.Accepts(r))

	p.Digests = []string{"sha256:bbbb"}
	assert.False(t, p.Accepts(r), "another digest than the pinned one")
	p.Digests = []string{"sha256:aaaa"}
	assert.True(t, p.Accepts(r))
}

func TestParseSigners_GitLab(t *testing.T) {
	p, err := ParseSigners("gitlab-ci:group/app-*")
	require.NoError(t, err)
	require.Len(t, p.Accept, 1)
	assert.Equal(t, "https://gitlab.com", p.Accept[0].Issuer)
	good := keyless("https://gitlab.com/group/app-api//.gitlab-ci.yml@refs/heads/main", "https://gitlab.com", "", "")
	assert.True(t, p.Accepts(good))
	assert.False(t, p.Accepts(keyless("https://gitlab.com/group/other//.gitlab-ci.yml@refs/heads/main", "https://gitlab.com", "", "")))
	assert.False(t, p.Accepts(keyless("https://gitlab.com/group/app-api//.gitlab-ci.yml@refs/heads/main", "https://gitlab.example.com", "", "")), "the host is pinned")

	gh, err := ParseSigners("github-actions:group/*")
	require.NoError(t, err)
	assert.False(t, gh.Accepts(good), "a GitLab identity is not a GitHub one")

	self, err := ParseSigners("gitlab-ci:gitlab.example.com/team/sub/svc")
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.example.com", self.Accept[0].Issuer)
	assert.True(t, self.Accepts(keyless("https://gitlab.example.com/team/sub/svc//ci/build.yml@refs/tags/v2", "https://gitlab.example.com", "", "")))
	assert.False(t, self.Accepts(keyless("https://gitlab.example.com/team/sub/svc//ci/build.yml@refs/tags/v2", "https://gitlab.com", "", "")))
}

func TestParseSigners_Several(t *testing.T) {
	p, err := ParseSigners("github-actions:org/*, oidc:https://accounts.example.com|a{1,3}@example\\.com,gitlab-ci:g/p")
	require.NoError(t, err)
	assert.Len(t, p.Accept, 3, "a comma inside a subject pattern does not split it")
	assert.True(t, p.Accepts(keyless("aa@example.com", "https://accounts.example.com", "", "")))
}

func TestParseSigners_Invalid(t *testing.T) {
	for _, s := range []string{
		"",
		"github-actions:org/.*",
		"github-actions:*/app",
		"github-actions:org",
		"github-actions:org/a/b",
		"github-actions:org/(a|b)",
		"oidc:https://accounts.example.com|.*",
		"oidc:https://accounts.example.com|",
		"oidc:|ci@example\\.com",
		"key:not-a-fingerprint",
		"gitlab-ci:group",
		"gitlab-ci:*/app",
		"unknown:x",
		"no-kind",
	} {
		_, err := ParseSigners(s)
		assert.Error(t, err, s)
	}
}

func TestParseSigners_KeyFromSet(t *testing.T) {
	sg := newKeySigner(t)
	fp := sg.fingerprint(t)
	p, err := ParseSigners("key:"+fp, sg.verifierPEM(t))
	require.NoError(t, err)
	require.Len(t, p.Accept, 1)
	assert.Equal(t, fp, p.Accept[0].Fingerprint)
	assert.Len(t, p.keys(), 1, "the PEM is found in the key set")

	// Bare hex works too.
	p2, err := ParseSigners("key:" + fp[len("sha256:"):])
	require.NoError(t, err)
	assert.Equal(t, fp, p2.Accept[0].Fingerprint)
	assert.Empty(t, p2.keys(), "no key set: matched by fingerprint, verified with keys given elsewhere")
}

func TestNewPolicy_SignerMustBeOneKind(t *testing.T) {
	sg := newKeySigner(t)
	_, err := NewPolicy(Signer{PublicKey: string(sg.verifierPEM(t)), Issuer: GitHubActionsIssuer, SANRegexp: "x"})
	assert.Error(t, err)
	_, err = NewPolicy(Signer{Issuer: GitHubActionsIssuer, IssuerRegexp: "x", SANRegexp: "x"})
	assert.Error(t, err)
	_, err = NewPolicy(Signer{Issuer: GitHubActionsIssuer})
	assert.Error(t, err, "a keyless signer needs a subject")
	_, err = NewPolicy(Signer{IssuerRegexp: ".+", SANRegexp: "x"})
	assert.Error(t, err, "an issuer pattern that accepts any issuer")
}

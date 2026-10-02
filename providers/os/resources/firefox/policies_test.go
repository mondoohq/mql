// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package firefox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The documents under test are small enough to read here, which keeps each
// case next to the shape it is about.
const (
	managedPolicy = `{
  "policies": {
    "DisableTelemetry": true,
    "SSLVersionMin": "tls1.2",
    "SanitizeOnShutdown": {
      "Cache": true,
      "Cookies": false,
      "Locked": true
    },
    "Preferences": {
      "security.default_personal_cert": {
        "Value": "Ask Every Time",
        "Status": "locked"
      }
    },
    "PrivateBrowsingModeAvailability": 1
  }
}`

	noPoliciesKey = `{
  "comment": "a well-formed document that declares no policies at all"
}`

	emptyPolicies = `{
  "policies": {}
}`

	// truncated mid-object, the shape a half-written deployment leaves behind
	malformedPolicy = `{
  "policies": {
    "DisableTelemetry": true,`
)

func TestParsePolicyFile(t *testing.T) {
	t.Run("a managed installation yields its policy set", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte(managedPolicy))
		require.NoError(t, err)
		require.NotNil(t, params)

		assert.Equal(t, true, params["DisableTelemetry"])
		assert.Equal(t, "tls1.2", params["SSLVersionMin"])
		assert.Equal(t, map[string]any{
			"Cache":   true,
			"Cookies": false,
			"Locked":  true,
		}, params["SanitizeOnShutdown"])
	})

	// The three cases below are the ones an unmanaged or half-managed host
	// actually produces, and each has to be distinguishable from the others.
	// "Absent" is handled a layer up, by never opening a file that is not
	// there; here we cover a file that exists but says nothing.

	t.Run("an empty file declares nothing and is not an error", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte(""))
		require.NoError(t, err)
		assert.Nil(t, params)
	})

	t.Run("whitespace only declares nothing and is not an error", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte("  \n\t\n"))
		require.NoError(t, err)
		assert.Nil(t, params)
	})

	t.Run("a document with no policies key declares nothing", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte(noPoliciesKey))
		require.NoError(t, err)
		assert.Nil(t, params)
	})

	t.Run("an empty policies object declares nothing", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte(emptyPolicies))
		require.NoError(t, err)
		assert.Nil(t, params)
	})

	t.Run("malformed JSON is an error, not an empty policy set", func(t *testing.T) {
		params, err := ParsePolicyFile([]byte(malformedPolicy))
		require.Error(t, err)
		assert.Nil(t, params)
		// A deployed-but-broken policy file must not be reported as "no policy
		// deployed" — that would be a false all-clear on a host an
		// administrator believes is locked down.
		assert.Contains(t, err.Error(), "failed to parse Firefox policy file")
	})
}

func TestPolicyFileCandidates(t *testing.T) {
	t.Run("linux probes the admin-owned file first", func(t *testing.T) {
		candidates := PolicyFileCandidates("linux")
		require.NotEmpty(t, candidates)
		// /etc wins outright over the install prefix, so it has to be probed
		// before any of them.
		assert.Equal(t, SystemPolicyFile, candidates[0])
	})

	// Debian and Ubuntu ship Firefox as the firefox-esr package. Missing this
	// path reads a correctly hardened host as unconfigured, and unconfigured is
	// indistinguishable from "the policy was never applied" — so every check
	// against such a host fails with nothing to hint at why.
	t.Run("linux covers the ESR install prefix", func(t *testing.T) {
		candidates := PolicyFileCandidates("linux")
		assert.Contains(t, candidates, "/usr/lib/firefox-esr/distribution/policies.json")
		assert.Contains(t, candidates, "/usr/lib64/firefox-esr/distribution/policies.json")
		// Debian's /usr/lib/firefox-esr/distribution is a symlink to here.
		assert.Contains(t, candidates, "/usr/share/firefox-esr/distribution/policies.json")
	})

	t.Run("linux covers the non-ESR layouts", func(t *testing.T) {
		candidates := PolicyFileCandidates("linux")
		assert.Contains(t, candidates, "/usr/lib/firefox/distribution/policies.json")
		assert.Contains(t, candidates, "/usr/lib64/firefox/distribution/policies.json")
	})

	t.Run("macos has no /etc lookup", func(t *testing.T) {
		candidates := PolicyFileCandidates("darwin")
		assert.Equal(t, []string{
			"/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
		}, candidates)
		assert.NotContains(t, candidates, SystemPolicyFile)
	})

	t.Run("windows probes both program files locations", func(t *testing.T) {
		candidates := PolicyFileCandidates("windows")
		assert.Equal(t, []string{
			`C:\Program Files\Mozilla Firefox\distribution\policies.json`,
			`C:\Program Files (x86)\Mozilla Firefox\distribution\policies.json`,
		}, candidates)
	})
}

func TestMerge(t *testing.T) {
	file := Source{
		Kind: KindFile,
		Path: `C:\Program Files\Mozilla Firefox\distribution\policies.json`,
		Params: map[string]any{
			"SSLVersionMin":             "tls1.2",
			"DisableFirefoxScreenshots": true,
			"SanitizeOnShutdown":        map[string]any{"Cache": true, "Cookies": true},
			"DisableFirefoxAccounts":    true,
		},
	}
	registry := Source{
		Kind: KindRegistry,
		Path: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox`,
		Params: map[string]any{
			"SSLVersionMin":      "tls1.3",
			"DisableTelemetry":   true,
			"SanitizeOnShutdown": map[string]any{"Cookies": false},
		},
	}

	t.Run("no source at all resolves to null, not an empty set", func(t *testing.T) {
		assert.Nil(t, Merge(nil))
		assert.Nil(t, Merge([]Source{}))
	})

	t.Run("the later source wins a conflicting key", func(t *testing.T) {
		merged := Merge([]Source{file, registry})
		assert.Equal(t, "tls1.3", merged["SSLVersionMin"])
	})

	t.Run("keys only one source sets are kept from both", func(t *testing.T) {
		merged := Merge([]Source{file, registry})
		assert.Equal(t, true, merged["DisableFirefoxScreenshots"], "file-only key survives the merge")
		assert.Equal(t, true, merged["DisableTelemetry"], "registry-only key survives the merge")
	})

	// Firefox's CombinedProvider merges at the top-level policy key and no
	// deeper: "We only do this for top level policies." A losing source's
	// object is replaced whole, not merged into, so the file's Cache key is
	// gone even though the registry never mentions it.
	t.Run("the merge is shallow — the losing object is replaced whole", func(t *testing.T) {
		merged := Merge([]Source{file, registry})
		assert.Equal(t, map[string]any{"Cookies": false}, merged["SanitizeOnShutdown"])
		assert.NotContains(t, merged["SanitizeOnShutdown"], "Cache")
	})

	t.Run("a single source is passed through unchanged", func(t *testing.T) {
		merged := Merge([]Source{file})
		assert.Equal(t, "tls1.2", merged["SSLVersionMin"])
	})
}

func TestDescribe(t *testing.T) {
	file := Source{Kind: KindFile}
	registry := Source{Kind: KindRegistry}

	assert.Equal(t, "", Describe(nil), "an unmanaged host names no source")
	assert.Equal(t, "file", Describe([]Source{file}))
	assert.Equal(t, "registry", Describe([]Source{registry}))
	assert.Equal(t, "file+registry", Describe([]Source{file, registry}))
	assert.Equal(t, "registry", Describe([]Source{registry, registry}),
		"both registry hives together are still one kind of source")
}

// fakeLinuxHost answers LinuxPolicyFileCandidates from a fixed set of paths.
// The layouts are the ones a Leap 15.6 / 16.0 host with Flathub Firefox 157
// actually has.
func fakeLinuxHost(arch string, homes []string, paths ...string) LinuxHost {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	return LinuxHost{
		Exists: func(path string) bool { return set[path] },
		Homes:  func() []string { return homes },
		Arch:   arch,
	}
}

const (
	flatpakSystemPolicy = "/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable/policies/policies.json"
	aliceExtension      = "/home/alice/.local/share/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable"
)

func TestLinuxPolicyFileCandidates(t *testing.T) {
	homes := []string{"/root", "/home/ec2-user", "/home/alice"}

	t.Run("a distribution Firefox keeps the /etc and prefix lookup", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes, "/usr/lib64/firefox")
		assert.Equal(t, PolicyFileCandidates("linux"), LinuxPolicyFileCandidates(host))
	})

	// Both installed: the distribution Firefox is the one reported, so its
	// /etc file still applies and the flatpak systemconfig is not mixed in.
	t.Run("a host with both installs reports the distribution Firefox", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes, "/usr/lib64/firefox", "/var/lib/flatpak/app/org.mozilla.firefox")
		candidates := LinuxPolicyFileCandidates(host)
		assert.Equal(t, SystemPolicyFile, candidates[0])
		assert.NotContains(t, candidates, flatpakSystemPolicy)
	})

	t.Run("no Firefox found keeps the distribution lookup", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes)
		assert.Equal(t, PolicyFileCandidates("linux"), LinuxPolicyFileCandidates(host))
	})

	// The false pass: Flathub Firefox ignores /etc/firefox, so a flatpak-only
	// host must not be credited with it.
	t.Run("a flatpak-only host reads the systemconfig extension, never /etc", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes, "/var/lib/flatpak/app/org.mozilla.firefox")
		candidates := LinuxPolicyFileCandidates(host)
		assert.Equal(t, []string{flatpakSystemPolicy}, candidates)
		assert.NotContains(t, candidates, SystemPolicyFile)
	})

	t.Run("a user-installed flatpak counts as a flatpak install", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes, "/home/alice/.local/share/flatpak/app/org.mozilla.firefox")
		assert.Equal(t, []string{flatpakSystemPolicy}, LinuxPolicyFileCandidates(host))
	})

	t.Run("the extension path follows the host architecture", func(t *testing.T) {
		host := fakeLinuxHost("arm64", homes, "/var/lib/flatpak/app/org.mozilla.firefox")
		assert.Equal(t, []string{
			"/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/aarch64/stable/policies/policies.json",
		}, LinuxPolicyFileCandidates(host))
	})

	t.Run("an unknown architecture probes every one Flathub builds", func(t *testing.T) {
		host := fakeLinuxHost("", homes, "/var/lib/flatpak/app/org.mozilla.firefox")
		assert.Equal(t, []string{
			flatpakSystemPolicy,
			"/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/aarch64/stable/policies/policies.json",
		}, LinuxPolicyFileCandidates(host))
	})

	// A user's own systemconfig extension replaces the system one for that
	// user, even when it carries no policy file, so the administrator's file
	// is not what governs that user's Firefox.
	t.Run("a user's systemconfig extension replaces the system one", func(t *testing.T) {
		host := fakeLinuxHost("x86_64", homes, "/var/lib/flatpak/app/org.mozilla.firefox", aliceExtension)
		candidates := LinuxPolicyFileCandidates(host)
		assert.Equal(t, []string{aliceExtension + "/policies/policies.json"}, candidates)
		assert.NotContains(t, candidates, flatpakSystemPolicy)
	})
}

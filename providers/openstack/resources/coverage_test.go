// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRBACObjectType(t *testing.T) {
	// Neutron spells the multi-word RBAC object types with either separator
	// depending on release. Matching one literal drops the other spelling.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"qos-policy", "qos_policy"},
		{"qos_policy", "qos_policy"},
		{"security_group", "security_group"},
		{"security-group", "security_group"},
		{"Address-Scope", "address_scope"},
		{"  subnetpool  ", "subnetpool"},
		{"network", "network"},
		{"", ""},
	} {
		assert.Equal(t, tc.want, normalizeRBACObjectType(tc.in), tc.in)
	}
}

func TestRBACObjectTypeIs(t *testing.T) {
	t.Run("matches across separator spellings", func(t *testing.T) {
		assert.True(t, rbacObjectTypeIs("qos_policy", "qos-policy"))
		assert.True(t, rbacObjectTypeIs("qos-policy", "qos-policy"))
		assert.True(t, rbacObjectTypeIs("security-group", "security_group"))
		assert.True(t, rbacObjectTypeIs("address_group", "address_group"))
	})
	t.Run("does not match a different type", func(t *testing.T) {
		// address_scope and address_group differ only in the last word; folding
		// separators must not fold them together.
		assert.False(t, rbacObjectTypeIs("address_scope", "address_group"))
		assert.False(t, rbacObjectTypeIs("network", "subnetpool"))
		assert.False(t, rbacObjectTypeIs("", "network"))
	})
}

func TestHSTSEnabledForMaxAge(t *testing.T) {
	// HSTS is off unless max-age is positive; includeSubDomains and preload are
	// inert on their own, so neither may stand in for "HSTS is on".
	assert.False(t, hstsEnabledForMaxAge(0), "max-age 0 disables HSTS")
	assert.False(t, hstsEnabledForMaxAge(-1), "a negative max-age is not enabled")
	assert.True(t, hstsEnabledForMaxAge(1))
	assert.True(t, hstsEnabledForMaxAge(31536000))
}

func TestListenerHSTSDecode(t *testing.T) {
	// Pin the wire names of the HSTS fields: a mistyped tag reads max_age as 0
	// on a listener that has HSTS on, which reports the listener as unprotected.
	body := []byte(`{
		"id": "00000000-0000-0000-0000-000000000001",
		"hsts_max_age": 31536000,
		"hsts_include_subdomains": true,
		"hsts_preload": true
	}`)
	var l listeners.Listener
	require.NoError(t, json.Unmarshal(body, &l))
	assert.Equal(t, 31536000, l.HSTSMaxAge)
	assert.True(t, l.HSTSIncludeSubdomains)
	assert.True(t, l.HSTSPreload)
	assert.True(t, hstsEnabledForMaxAge(int64(l.HSTSMaxAge)))

	t.Run("listener without the HSTS fields reads as not enabled", func(t *testing.T) {
		// Pre-microversion-2.27 Octavia omits the fields entirely. The safe
		// reading is "not enabled", which fails an HSTS assertion rather than
		// passing it vacuously.
		var old listeners.Listener
		require.NoError(t, json.Unmarshal([]byte(`{"id":"x"}`), &old))
		assert.Equal(t, 0, old.HSTSMaxAge)
		assert.False(t, hstsEnabledForMaxAge(int64(old.HSTSMaxAge)))
	})
}

func TestNodeAutomatedCleanDecode(t *testing.T) {
	// automated_clean is nullable: false means disks are not wiped between
	// tenants, while null means the node defers to the conductor default. The
	// two must not collapse into one another.
	t.Run("explicit false", func(t *testing.T) {
		var n nodes.Node
		require.NoError(t, json.Unmarshal([]byte(`{"automated_clean": false}`), &n))
		require.NotNil(t, n.AutomatedClean)
		assert.False(t, *n.AutomatedClean)
	})
	t.Run("explicit true", func(t *testing.T) {
		var n nodes.Node
		require.NoError(t, json.Unmarshal([]byte(`{"automated_clean": true}`), &n))
		require.NotNil(t, n.AutomatedClean)
		assert.True(t, *n.AutomatedClean)
	})
	t.Run("absent stays null", func(t *testing.T) {
		var n nodes.Node
		require.NoError(t, json.Unmarshal([]byte(`{"uuid":"x"}`), &n))
		assert.Nil(t, n.AutomatedClean, "absent must not read as false")
	})
	t.Run("explicit null stays null", func(t *testing.T) {
		var n nodes.Node
		require.NoError(t, json.Unmarshal([]byte(`{"automated_clean": null}`), &n))
		assert.Nil(t, n.AutomatedClean)
	})
	t.Run("retirement fields", func(t *testing.T) {
		var n nodes.Node
		require.NoError(t, json.Unmarshal(
			[]byte(`{"retired": true, "retired_reason": "end of lease"}`), &n))
		assert.True(t, n.Retired)
		assert.Equal(t, "end of lease", n.RetiredReason)
	})
}

func TestRedactContainerMetadata(t *testing.T) {
	// Swift returns the temp-URL signing keys as ordinary X-Container-Meta-*
	// headers, so they land in the metadata map next to user labels. Anyone
	// holding one can mint unauthenticated pre-signed URLs, so the value must
	// never leave the provider.
	in := map[string]string{
		"Owner":          "platform-team",
		"Temp-Url-Key":   "not-a-real-key",
		"Temp-Url-Key-2": "not-a-real-key-either",
		"Retention":      "30d",
	}
	out := redactContainerMetadata(in)
	assert.Equal(t, map[string]string{
		"Owner":     "platform-team",
		"Retention": "30d",
	}, out)

	t.Run("input is not mutated", func(t *testing.T) {
		assert.Len(t, in, 4, "redaction must copy, not strip the cached map")
	})
	t.Run("casing does not defeat redaction", func(t *testing.T) {
		// net/http canonicalizes header casing, and Swift itself accepts any
		// casing on the way in, so match case-insensitively.
		out := redactContainerMetadata(map[string]string{
			"TEMP-URL-KEY":   "not-a-real-key",
			"temp-url-key-2": "not-a-real-key-either",
			"Keep":           "value",
		})
		assert.Equal(t, map[string]string{"Keep": "value"}, out)
	})
	t.Run("a similarly named key is kept", func(t *testing.T) {
		out := redactContainerMetadata(map[string]string{"Temp-Url-Key-Rotated-At": "2026-01-01"})
		assert.Equal(t, map[string]string{"Temp-Url-Key-Rotated-At": "2026-01-01"}, out)
	})
	t.Run("empty and nil maps", func(t *testing.T) {
		assert.Empty(t, redactContainerMetadata(nil))
		assert.Empty(t, redactContainerMetadata(map[string]string{}))
	})
}

func TestUserOptionBoolPasswordPolicyBypasses(t *testing.T) {
	// The bypass flags share one options map with the two already shipped, and
	// each one exempts the account from a domain-wide password rule.
	options := map[string]any{
		"ignore_password_expiry":                true,
		"ignore_change_password_upon_first_use": true,
		"ignore_user_inactivity":                false,
	}
	assert.True(t, userOptionBool(options, "ignore_password_expiry"))
	assert.True(t, userOptionBool(options, "ignore_change_password_upon_first_use"))
	assert.False(t, userOptionBool(options, "ignore_user_inactivity"))
	// An account that sets no options is subject to every policy.
	assert.False(t, userOptionBool(map[string]any{}, "ignore_password_expiry"))
}

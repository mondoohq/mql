// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPolicyRuleOpenIngress pins the two ways a network firewall policy rule
// differs from a legacy VPC firewall rule.
//
// A legacy rule is an allow rule or a deny rule by construction -- the presence
// of an allow block decides. A policy rule carries an `action` string, and three
// of its four values do not open traffic. Reading "deny" as an opening is the
// error that would turn a block-all rule into reported exposure; reading
// "allow" as anything else is the error that hides real exposure.
func TestPolicyRuleOpenIngress(t *testing.T) {
	open := []any{"0.0.0.0/0"}

	t.Run("an allow rule from any address opens ingress", func(t *testing.T) {
		assert.True(t, policyRuleOpenIngress("allow", "INGRESS", false, open))
		assert.True(t, policyRuleOpenIngress("allow", "INGRESS", false, []any{"::/0"}))
		// Casing is not guaranteed by the API for either field.
		assert.True(t, policyRuleOpenIngress("ALLOW", "ingress", false, open))
	})

	t.Run("only the allow action opens ingress", func(t *testing.T) {
		// deny is the common block-all rule and must never read as exposure;
		// goto_next defers to the next policy and decides nothing itself.
		for _, action := range []string{"deny", "goto_next", "apply_security_profile_group", ""} {
			assert.False(t, policyRuleOpenIngress(action, "INGRESS", false, open),
				"action %q must not open ingress", action)
		}
	})

	t.Run("egress and disabled rules do not open ingress", func(t *testing.T) {
		assert.False(t, policyRuleOpenIngress("allow", "EGRESS", false, open))
		assert.False(t, policyRuleOpenIngress("allow", "INGRESS", true, open))
	})

	t.Run("a scoped source range does not open ingress", func(t *testing.T) {
		assert.False(t, policyRuleOpenIngress("allow", "INGRESS", false,
			[]any{"10.0.0.0/8", "192.168.0.0/16"}))
		assert.False(t, policyRuleOpenIngress("allow", "INGRESS", false, nil))
		// A non-string element must be skipped, not panic.
		assert.False(t, policyRuleOpenIngress("allow", "INGRESS", false, []any{42}))
	})

	t.Run("an open range among scoped ones still opens ingress", func(t *testing.T) {
		assert.True(t, policyRuleOpenIngress("allow", "INGRESS", false,
			[]any{"10.0.0.0/8", "0.0.0.0/0"}))
	})
}

// TestPolicyRuleTargetsInstance pins two things.
//
// First, that targetResources are network URLs, not tags: a rule scoped to one
// network inside a policy associated with several applies only to that network,
// and reading the field as a tag list would make every such rule apply to every
// instance.
//
// Second, that the two target fields compose with AND. They are independent
// axes -- targetResources picks the network, targetServiceAccounts the
// instances within it -- so a rule naming both applies only where both match.
// Treating them as alternatives over-reports exposure.
func TestPolicyRuleTargetsInstance(t *testing.T) {
	networks := map[string]bool{"prod-vpc": true}
	accounts := map[string]bool{"app@project.iam.gserviceaccount.com": true}

	const (
		prodURL = "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc"
		devURL  = "https://www.googleapis.com/compute/v1/projects/p/global/networks/dev-vpc"
		otherSA = "other@project.iam.gserviceaccount.com"
		ourSA   = "app@project.iam.gserviceaccount.com"
	)

	t.Run("no targeting applies to every instance", func(t *testing.T) {
		assert.True(t, policyRuleTargetsInstance(nil, nil, networks, accounts))
	})

	t.Run("network only, by full URL or short name", func(t *testing.T) {
		assert.True(t, policyRuleTargetsInstance([]any{prodURL}, nil, networks, accounts))
		assert.True(t, policyRuleTargetsInstance([]any{"prod-vpc"}, nil, networks, accounts))
	})

	t.Run("a rule scoped to another network does not apply", func(t *testing.T) {
		assert.False(t, policyRuleTargetsInstance([]any{devURL}, nil, networks, accounts))
	})

	t.Run("service account only", func(t *testing.T) {
		assert.True(t, policyRuleTargetsInstance(nil, []any{ourSA}, networks, accounts))
		assert.False(t, policyRuleTargetsInstance(nil, []any{otherSA}, networks, accounts))
	})

	// The AND cases. Each one is a false positive under OR.
	t.Run("both axes must match when both are named", func(t *testing.T) {
		assert.True(t, policyRuleTargetsInstance(
			[]any{prodURL}, []any{ourSA}, networks, accounts),
			"our network and our service account")

		assert.False(t, policyRuleTargetsInstance(
			[]any{prodURL}, []any{otherSA}, networks, accounts),
			"our network but another service account: the rule scopes to that account")

		assert.False(t, policyRuleTargetsInstance(
			[]any{devURL}, []any{ourSA}, networks, accounts),
			"our service account but another network: the rule never reaches this network")

		assert.False(t, policyRuleTargetsInstance(
			[]any{devURL}, []any{otherSA}, networks, accounts),
			"neither axis matches")
	})

	t.Run("non-string entries are skipped", func(t *testing.T) {
		assert.False(t, policyRuleTargetsInstance([]any{42}, []any{nil}, networks, accounts))
		// A non-string in one axis must not be read as a match for it, even
		// when the other axis matches.
		assert.False(t, policyRuleTargetsInstance([]any{42}, []any{ourSA}, networks, accounts))
	})
}

// TestPolicyAppliesToNetworks pins the association check.
//
// A firewall policy enforces nothing until it is associated with a network, so
// an unassociated policy must contribute no exposure however permissive its
// rules are. Getting this wrong would report every instance in the project as
// reachable the moment someone drafts a policy.
func TestPolicyAppliesToNetworks(t *testing.T) {
	networks := map[string]bool{"prod-vpc": true}

	assoc := func(target string) any {
		return map[string]any{"attachmentTarget": target}
	}

	t.Run("associated with the instance's network", func(t *testing.T) {
		assert.True(t, policyAppliesToNetworks([]any{
			assoc("https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc"),
		}, networks))
	})

	t.Run("an unassociated policy applies to nothing", func(t *testing.T) {
		assert.False(t, policyAppliesToNetworks(nil, networks))
		assert.False(t, policyAppliesToNetworks([]any{}, networks))
	})

	t.Run("associated only with another network", func(t *testing.T) {
		assert.False(t, policyAppliesToNetworks([]any{assoc("dev-vpc")}, networks))
	})

	t.Run("one matching association among several is enough", func(t *testing.T) {
		assert.True(t, policyAppliesToNetworks([]any{
			assoc("dev-vpc"), assoc("staging-vpc"), assoc("prod-vpc"),
		}, networks))
	})

	t.Run("malformed associations are skipped, not fatal", func(t *testing.T) {
		assert.False(t, policyAppliesToNetworks([]any{
			"not-a-dict",
			map[string]any{"attachmentTarget": 42},
			map[string]any{"attachmentTarget": ""},
			map[string]any{"shortName": "prod-vpc"}, // right value, wrong key
		}, networks))
	})
}

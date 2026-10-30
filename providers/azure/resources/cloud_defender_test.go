// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	security "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestCommonPricingArgs(t *testing.T) {
	t.Run("FullProperties", func(t *testing.T) {
		enablementTime := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
		props := &security.PricingProperties{
			PricingTier:             ptr(security.PricingTierStandard),
			SubPlan:                 new("P2"),
			Enforce:                 ptr(security.EnforceTrue),
			Deprecated:              new(false),
			FreeTrialRemainingTime:  new("P30D"),
			EnablementTime:          &enablementTime,
			Inherited:               ptr(security.InheritedFalse),
			InheritedFrom:           new("/subscriptions/parent-sub"),
			ReplacedBy:              []*string{new("plan-a"), new("plan-b")},
			ResourcesCoverageStatus: ptr(security.ResourcesCoverageStatusFullyCovered),
		}

		args := commonPricingArgs(props, "azure.subscription.cloudDefenderService.defenderForServers", "test-sub-123")

		assert.Equal(t, "azure.subscription.cloudDefenderService.defenderForServers/test-sub-123", args["__id"].Value)
		assert.Equal(t, "test-sub-123", args["subscriptionId"].Value)
		assert.Equal(t, true, args["enabled"].Value)
		assert.Equal(t, "Standard", args["pricingTier"].Value)
		assert.Equal(t, "P2", args["subPlan"].Value)
		assert.Equal(t, true, args["enforce"].Value)
		assert.Equal(t, false, args["deprecated"].Value)
		assert.Equal(t, "P30D", args["freeTrialRemainingTime"].Value)
		assert.Equal(t, &enablementTime, args["enablementTime"].Value)
		assert.Equal(t, false, args["inherited"].Value)
		assert.Equal(t, "/subscriptions/parent-sub", args["inheritedFrom"].Value)
		assert.Equal(t, "FullyCovered", args["resourcesCoverageStatus"].Value)

		replacedBy := args["replacedBy"].Value.([]any)
		require.Len(t, replacedBy, 2)
		assert.Equal(t, "plan-a", replacedBy[0])
		assert.Equal(t, "plan-b", replacedBy[1])
	})

	t.Run("FreeTier", func(t *testing.T) {
		props := &security.PricingProperties{
			PricingTier: ptr(security.PricingTierFree),
		}

		args := commonPricingArgs(props, "azure.subscription.cloudDefenderService.defenderForApis", "sub-456")

		assert.Equal(t, false, args["enabled"].Value)
		assert.Equal(t, "Free", args["pricingTier"].Value)
	})

	t.Run("NilFields", func(t *testing.T) {
		props := &security.PricingProperties{}

		args := commonPricingArgs(props, "azure.subscription.cloudDefenderService.defenderForKeyVaults", "sub-789")

		assert.Equal(t, false, args["enabled"].Value)
		assert.Equal(t, "", args["pricingTier"].Value)
		assert.Equal(t, "", args["subPlan"].Value)
		assert.Equal(t, false, args["enforce"].Value)
		assert.Equal(t, false, args["deprecated"].Value)
		assert.Equal(t, "", args["freeTrialRemainingTime"].Value)
		assert.Nil(t, args["enablementTime"].Value)
		assert.Equal(t, false, args["inherited"].Value)
		assert.Equal(t, "", args["inheritedFrom"].Value)
		assert.Equal(t, "", args["resourcesCoverageStatus"].Value)

		replacedBy := args["replacedBy"].Value.([]any)
		assert.Empty(t, replacedBy)
	})

	t.Run("NilProperties", func(t *testing.T) {
		args := commonPricingArgs(nil, "azure.subscription.cloudDefenderService.defenderForServers", "sub-nil")

		assert.Equal(t, "azure.subscription.cloudDefenderService.defenderForServers/sub-nil", args["__id"].Value)
		assert.Equal(t, "sub-nil", args["subscriptionId"].Value)
		assert.Equal(t, false, args["enabled"].Value)
		assert.Equal(t, "", args["pricingTier"].Value)
		assert.Equal(t, "", args["subPlan"].Value)
		assert.Equal(t, false, args["enforce"].Value)
		assert.Equal(t, false, args["deprecated"].Value)
		assert.Equal(t, "", args["freeTrialRemainingTime"].Value)
		assert.Nil(t, args["enablementTime"].Value)
		assert.Equal(t, false, args["inherited"].Value)
		assert.Equal(t, "", args["inheritedFrom"].Value)
		assert.Equal(t, "", args["resourcesCoverageStatus"].Value)

		replacedBy := args["replacedBy"].Value.([]any)
		assert.Empty(t, replacedBy)
	})

	t.Run("EnforceEnum", func(t *testing.T) {
		propsFalse := &security.PricingProperties{
			Enforce: ptr(security.EnforceFalse),
		}
		args := commonPricingArgs(propsFalse, "test", "sub")
		assert.Equal(t, false, args["enforce"].Value)

		propsTrue := &security.PricingProperties{
			Enforce: ptr(security.EnforceTrue),
		}
		args = commonPricingArgs(propsTrue, "test", "sub")
		assert.Equal(t, true, args["enforce"].Value)
	})

	t.Run("InheritedEnum", func(t *testing.T) {
		propsFalse := &security.PricingProperties{
			Inherited: ptr(security.InheritedFalse),
		}
		args := commonPricingArgs(propsFalse, "test", "sub")
		assert.Equal(t, false, args["inherited"].Value)

		propsTrue := &security.PricingProperties{
			Inherited: ptr(security.InheritedTrue),
		}
		args = commonPricingArgs(propsTrue, "test", "sub")
		assert.Equal(t, true, args["inherited"].Value)
	})
}

func TestArgsFromContactProperties(t *testing.T) {
	t.Run("FullProperties", func(t *testing.T) {
		props := &security.ContactProperties{
			Emails:    new("admin@example.com;security@example.com"),
			IsEnabled: new(true),
			Phone:     new("+1-555-0100"),
		}

		args := argsFromContactProperties(props)

		assert.Equal(t, true, args["isEnabled"].Value)
		assert.Equal(t, "+1-555-0100", args["phone"].Value)

		emails := args["emails"].Value.([]any)
		require.Len(t, emails, 2)
		assert.Equal(t, "admin@example.com", emails[0])
		assert.Equal(t, "security@example.com", emails[1])
	})

	t.Run("NilOptionalFields", func(t *testing.T) {
		props := &security.ContactProperties{}

		args := argsFromContactProperties(props)

		assert.Nil(t, args["isEnabled"].Value)
		assert.Nil(t, args["phone"].Value)
	})

	t.Run("NilProperties", func(t *testing.T) {
		args := argsFromContactProperties(nil)
		assert.Empty(t, args)
	})

	t.Run("DisabledContact", func(t *testing.T) {
		props := &security.ContactProperties{
			IsEnabled: new(false),
		}

		args := argsFromContactProperties(props)
		assert.Equal(t, false, args["isEnabled"].Value)
	})
}

// TestSplitSecurityContactEmails pins the empty case.
//
// strings.Split("", ";") returns []string{""}, so a contact with a phone number
// and no email used to report emails: [""] -- one element, not zero. A check
// phrased `securityContacts.any(emails.length > 0)` passed on a subscription
// with no email contact configured at all, which is the inverse of the finding
// it exists to raise.
func TestSplitSecurityContactEmails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *string
		want  []any
	}{
		{"nil is no addresses", nil, []any{}},
		{"empty string is no addresses, not one empty address", new(""), []any{}},
		{"a separator with nothing around it yields nothing", new(";"), []any{}},
		{"single address", new("soc@example.com"), []any{"soc@example.com"}},
		{"multiple addresses", new("a@example.com;b@example.com"), []any{"a@example.com", "b@example.com"}},
		{"surrounding spaces are trimmed", new(" a@example.com ; b@example.com "), []any{"a@example.com", "b@example.com"}},
		{"empty entries are dropped", new("a@example.com;;b@example.com"), []any{"a@example.com", "b@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitSecurityContactEmails(tc.input))
		})
	}
}

func TestSimpleDefenderDict(t *testing.T) {
	t.Run("Enabled", func(t *testing.T) {
		tv := &plugin.TValue[bool]{Data: true}
		got, err := simpleDefenderDict(tv)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"enabled": true}, got)
	})

	t.Run("Disabled", func(t *testing.T) {
		tv := &plugin.TValue[bool]{Data: false}
		got, err := simpleDefenderDict(tv)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"enabled": false}, got)
	})

	t.Run("Propagates underlying error", func(t *testing.T) {
		want := errors.New("boom")
		tv := &plugin.TValue[bool]{Error: want}
		_, err := simpleDefenderDict(tv)
		assert.ErrorIs(t, err, want)
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeEntryID(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		identity string
		index    int
		want     string
	}{
		{"identity wins", "teamsProtectionPolicy", "Default", 0, "teamsProtectionPolicy-Default"},
		{"identity used regardless of index", "reportSubmissionPolicy", "Default", 7, "reportSubmissionPolicy-Default"},
		{"empty identity falls back to index", "mailboxAuditBypassAssociation", "", 0, "mailboxAuditBypassAssociation-#0"},
		{"fallback stays distinct per row", "mailboxAuditBypassAssociation", "", 168, "mailboxAuditBypassAssociation-#168"},
		{"prefix always present", "hostedConnectionFilterPolicy", "", 0, "hostedConnectionFilterPolicy-#0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, exchangeEntryID(tc.prefix, tc.identity, tc.index))
		})
	}
}

// The whole point of the id builder is that no two rows of one collection can
// share a cache key -- CreateResource is first-wins, so a shared key silently
// discards every row after the first. Cover both the normal case (distinct
// identities) and the degenerate one (no identity at all), which is what
// produced 169 identical mailbox audit-bypass rows before the fix.
func TestExchangeEntryIDIsUniquePerRow(t *testing.T) {
	t.Run("distinct identities", func(t *testing.T) {
		identities := []string{"svc-backup", "svc-journal", "admin-break-glass"}
		seen := map[string]bool{}
		for i, id := range identities {
			key := exchangeEntryID("mailboxAuditBypassAssociation", id, i)
			assert.False(t, seen[key], "duplicate cache key %q", key)
			seen[key] = true
		}
		assert.Len(t, seen, len(identities))
	})

	t.Run("no identity at all", func(t *testing.T) {
		seen := map[string]bool{}
		for i := range 169 {
			key := exchangeEntryID("mailboxAuditBypassAssociation", "", i)
			assert.False(t, seen[key], "duplicate cache key %q at row %d", key, i)
			seen[key] = true
		}
		assert.Len(t, seen, 169, "every row must get its own cache key")
	})

	t.Run("prefixes keep resource types apart", func(t *testing.T) {
		assert.NotEqual(t,
			exchangeEntryID("teamsProtectionPolicy", "Default", 0),
			exchangeEntryID("reportSubmissionPolicy", "Default", 0),
			"two resource types sharing an Identity must not share a key")
	})

	// externalSender and exoMailbox are both keyed on an Exchange Identity and
	// are built from the same report, so a mailbox and a sender that share one
	// must still land on different keys.
	t.Run("externalSender and exoMailbox do not collide", func(t *testing.T) {
		const identity = "shared@example.com"
		assert.NotEqual(t,
			exchangeEntryID("externalSender", identity, 0),
			exchangeEntryID("exoMailbox", identity, 0),
			"a sender and a mailbox sharing an Identity must not share a key")
	})
}

// Identity is what the id builder keys on, so the struct tag that feeds it has
// to match the wire shape. Exchange emits PascalCase from both the REST
// InvokeCommand path and PowerShell's ConvertTo-Json.
func TestExchangePolicyIdentityDecodes(t *testing.T) {
	t.Run("teams protection policy", func(t *testing.T) {
		var p TeamsProtectionPolicy
		require.NoError(t, json.Unmarshal([]byte(`{"Identity":"Teams Protection Policy","ZapEnabled":true,"IsValid":true}`), &p))
		assert.Equal(t, "Teams Protection Policy", p.Identity)
		assert.True(t, p.ZapEnabled)
	})

	t.Run("report submission policy", func(t *testing.T) {
		var p ReportSubmissionPolicy
		require.NoError(t, json.Unmarshal([]byte(`{"Identity":"DefaultReportSubmissionPolicy","EnableReportToMicrosoft":true}`), &p))
		assert.Equal(t, "DefaultReportSubmissionPolicy", p.Identity)
		assert.True(t, p.EnableReportToMicrosoft)
	})

	t.Run("absent identity leaves the fallback to take over", func(t *testing.T) {
		var p TeamsProtectionPolicy
		require.NoError(t, json.Unmarshal([]byte(`{"ZapEnabled":false}`), &p))
		assert.Empty(t, p.Identity)
		assert.Equal(t, "teamsProtectionPolicy-#3", exchangeEntryID("teamsProtectionPolicy", p.Identity, 3))
	})
}

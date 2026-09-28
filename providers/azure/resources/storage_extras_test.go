// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/stretchr/testify/assert"
)

func TestStorageAccountResourceGroup(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		wantRG      string
		wantAccount string
		wantErr     bool
	}{
		{
			name:        "well-formed account id",
			id:          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myaccount",
			wantRG:      "my-rg",
			wantAccount: "myaccount",
		},
		{
			name:    "missing storageAccounts segment",
			id:      "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Storage",
			wantErr: true,
		},
		{
			name:    "malformed id",
			id:      "not-an-arm-id",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rg, acct, err := storageAccountResourceGroup(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantRG, rg)
			assert.Equal(t, tc.wantAccount, acct)
		})
	}
}

func TestObjectReplicationRulesToDicts(t *testing.T) {
	t.Run("empty input returns empty slice", func(t *testing.T) {
		assert.Empty(t, objectReplicationRulesToDicts(nil))
	})

	t.Run("rule with all fields populated", func(t *testing.T) {
		ruleId := "rule-1"
		src := "logs"
		dst := "audit"
		prefix := "events/"
		rules := []*storage.ObjectReplicationPolicyRule{
			{
				RuleID:               &ruleId,
				SourceContainer:      &src,
				DestinationContainer: &dst,
				Filters: &storage.ObjectReplicationPolicyFilter{
					PrefixMatch: []*string{&prefix},
				},
			},
		}
		out := objectReplicationRulesToDicts(rules)
		assert.Len(t, out, 1)
		entry := out[0].(map[string]any)
		assert.Equal(t, "rule-1", entry["ruleId"])
		assert.Equal(t, "logs", entry["sourceContainer"])
		assert.Equal(t, "audit", entry["destinationContainer"])
		assert.Equal(t, []any{"events/"}, entry["prefixMatch"])
	})

	t.Run("nil rule entry skipped", func(t *testing.T) {
		ruleId := "rule-1"
		rules := []*storage.ObjectReplicationPolicyRule{
			nil,
			{RuleID: &ruleId},
		}
		out := objectReplicationRulesToDicts(rules)
		assert.Len(t, out, 1)
		assert.Equal(t, "rule-1", out[0].(map[string]any)["ruleId"])
	})

	t.Run("rule with no filters defaults to empty prefix list", func(t *testing.T) {
		ruleId := "rule-1"
		rules := []*storage.ObjectReplicationPolicyRule{{RuleID: &ruleId}}
		out := objectReplicationRulesToDicts(rules)
		assert.Equal(t, []any{}, out[0].(map[string]any)["prefixMatch"])
	})
}

func TestInventoryRulesToDicts(t *testing.T) {
	t.Run("empty input returns empty slice", func(t *testing.T) {
		assert.Empty(t, inventoryRulesToDicts(nil))
	})

	t.Run("rule with all fields populated", func(t *testing.T) {
		name := "blob-inventory"
		enabled := true
		dest := "inventory-output"
		rules := []*storage.BlobInventoryPolicyRule{
			{
				Name:        &name,
				Enabled:     &enabled,
				Destination: &dest,
			},
		}
		out := inventoryRulesToDicts(rules)
		assert.Len(t, out, 1)
		entry := out[0].(map[string]any)
		assert.Equal(t, "blob-inventory", entry["name"])
		assert.Equal(t, true, entry["enabled"])
		assert.Equal(t, "inventory-output", entry["destination"])
	})

	t.Run("nil rule entry skipped", func(t *testing.T) {
		name := "rule-1"
		rules := []*storage.BlobInventoryPolicyRule{
			nil,
			{Name: &name},
		}
		out := inventoryRulesToDicts(rules)
		assert.Len(t, out, 1)
		assert.Equal(t, "rule-1", out[0].(map[string]any)["name"])
	})
}

func TestIsInventoryPolicyNotFoundError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, isInventoryPolicyNotFoundError(nil))
	})
	t.Run("non-azcore error", func(t *testing.T) {
		assert.False(t, isInventoryPolicyNotFoundError(errors.New("boom")))
	})
	t.Run("404 azcore.ResponseError", func(t *testing.T) {
		err := &azcore.ResponseError{StatusCode: http.StatusNotFound}
		assert.True(t, isInventoryPolicyNotFoundError(err))
	})
	t.Run("403 azcore.ResponseError not treated as not-found", func(t *testing.T) {
		err := &azcore.ResponseError{StatusCode: http.StatusForbidden}
		assert.False(t, isInventoryPolicyNotFoundError(err))
	})
}

func TestSasPolicyUserBoundDelegation(t *testing.T) {
	t.Run("nil policy is null", func(t *testing.T) {
		required, action := sasPolicyUserBoundDelegation(nil)
		assert.Nil(t, required)
		assert.Nil(t, action)
	})

	t.Run("policy without the setting is null", func(t *testing.T) {
		exp := storage.ExpirationActionLog
		period := "1.00:00:00"
		required, action := sasPolicyUserBoundDelegation(&storage.SasPolicy{
			ExpirationAction:    &exp,
			SasExpirationPeriod: &period,
		})
		assert.Nil(t, required)
		assert.Nil(t, action)
	})

	t.Run("policy with the setting", func(t *testing.T) {
		yes := true
		block := storage.PolicyViolationActionBlock
		required, action := sasPolicyUserBoundDelegation(&storage.SasPolicy{
			RequireUserBoundUserDelegationSas:       &yes,
			RequireUserBoundUserDelegationSasAction: &block,
		})
		if assert.NotNil(t, required) {
			assert.True(t, *required)
		}
		if assert.NotNil(t, action) {
			assert.Equal(t, "Block", *action)
		}
	})

	t.Run("explicit false is kept", func(t *testing.T) {
		no := false
		none := storage.PolicyViolationActionNone
		required, action := sasPolicyUserBoundDelegation(&storage.SasPolicy{
			RequireUserBoundUserDelegationSas:       &no,
			RequireUserBoundUserDelegationSasAction: &none,
		})
		if assert.NotNil(t, required) {
			assert.False(t, *required)
		}
		if assert.NotNil(t, action) {
			assert.Equal(t, "None", *action)
		}
	})
}

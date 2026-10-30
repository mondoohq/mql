// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/delegateaccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/lockbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- lockbox approval chain -----
//
// The one question an approval template has to answer is how many people must
// agree, and the API makes that awkward: three named optional slots rather
// than a list. Getting the flattening wrong reports a different chain than the
// one configured.

func TestOciApproverLevels(t *testing.T) {
	approver := func(id string) *lockbox.ApproverInfo {
		return &lockbox.ApproverInfo{
			ApproverType: lockbox.ApproverTypeGroup,
			ApproverId:   new(id),
			DomainId:     new("ocid1.domain.oc1..ddd"),
		}
	}

	t.Run("a full chain is reported in level order", func(t *testing.T) {
		got := ociApproverLevels(&lockbox.ApproverLevels{
			Level1: approver("group-a"),
			Level2: approver("group-b"),
			Level3: approver("group-c"),
		})
		require.Len(t, got, 3)

		first, ok := got[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, int64(1), first["level"])
		assert.Equal(t, "group-a", first["approverId"])
		assert.Equal(t, "GROUP", first["approverType"])
		assert.Equal(t, "ocid1.domain.oc1..ddd", first["domainId"])

		third, ok := got[2].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, int64(3), third["level"])
		assert.Equal(t, "group-c", third["approverId"])
	})

	t.Run("unset levels are dropped so the count is the approvals required", func(t *testing.T) {
		// Reporting three entries for a template with one approver would make
		// `approverLevels.length >= 2` pass on a template where one person can
		// grant access alone.
		got := ociApproverLevels(&lockbox.ApproverLevels{Level1: approver("group-a")})
		assert.Len(t, got, 1)
	})

	t.Run("a gap keeps the level it was configured at", func(t *testing.T) {
		// Renumbering level 3 to 2 would report a chain the tenancy did not
		// configure. The count still reflects how many approvals are needed.
		got := ociApproverLevels(&lockbox.ApproverLevels{
			Level1: approver("group-a"),
			Level3: approver("group-c"),
		})
		require.Len(t, got, 2)

		second, ok := got[1].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, int64(3), second["level"])
	})

	t.Run("no approver levels at all is an empty list, not null", func(t *testing.T) {
		assert.Equal(t, []any{}, ociApproverLevels(nil))
	})

	t.Run("an approver with no id does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ociApproverLevels(&lockbox.ApproverLevels{
				Level1: &lockbox.ApproverInfo{ApproverType: lockbox.ApproverTypeUser},
			})
		})
	})
}

func TestOciApproverLevelValuesAreJsonNative(t *testing.T) {
	// The entries land in a []dict field, and a dict value has to be
	// JSON-native or the llx encoder drops it. int64 and string are; a bare
	// Go int is not.
	got := ociApproverLevels(&lockbox.ApproverLevels{
		Level1: &lockbox.ApproverInfo{
			ApproverType: lockbox.ApproverTypeUser,
			ApproverId:   new("user-a"),
		},
	})
	require.Len(t, got, 1)

	entry, ok := got[0].(map[string]any)
	require.True(t, ok)
	for key, value := range entry {
		switch value.(type) {
		case string, int64, float64, bool, nil:
		default:
			t.Errorf("approverLevels[%q] is %T, which is not a JSON-native dict value", key, value)
		}
	}
}

// ----- service provider enum rendering -----

func TestOciServiceProviderEnumStrings(t *testing.T) {
	t.Run("service types are rendered as the API spells them", func(t *testing.T) {
		got := ociServiceTypeStrings([]delegateaccesscontrol.ServiceProviderServiceTypeEnum{
			delegateaccesscontrol.ServiceProviderServiceTypeTroubleshooting,
			delegateaccesscontrol.ServiceProviderServiceTypeAssistedPatching,
		})
		assert.Equal(t, []string{"TROUBLESHOOTING", "ASSISTED_PATCHING"}, got)
	})

	t.Run("supported resource types are rendered as the API spells them", func(t *testing.T) {
		got := ociDelegationResourceTypeStrings([]delegateaccesscontrol.DelegationControlResourceTypeEnum{
			delegateaccesscontrol.DelegationControlResourceTypeVmcluster,
		})
		assert.Equal(t, []string{"VMCLUSTER"}, got)
	})

	t.Run("no values is an empty list, not null", func(t *testing.T) {
		// A provider offering nothing and a provider whose services could not
		// be read must not look the same, and the caller has no way to tell an
		// empty slice from a nil one once it reaches MQL.
		assert.Equal(t, []string{}, ociServiceTypeStrings(nil))
		assert.Equal(t, []string{}, ociDelegationResourceTypeStrings(nil))
	})
}

func TestOciServiceProviderServiceTypeCoverage(t *testing.T) {
	// The service types are passed through verbatim, so a query comparing
	// against "TROUBLESHOOTING" has to match what the API returns. Driven from
	// the SDK enum so a renamed or added class of service surfaces here rather
	// than as a silently non-matching filter.
	values := delegateaccesscontrol.GetServiceProviderServiceTypeEnumValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; this check would pass vacuously")

	got := ociServiceTypeStrings(values)
	require.Len(t, got, len(values))
	for i, value := range values {
		assert.Equal(t, string(value), got[i])
	}
}

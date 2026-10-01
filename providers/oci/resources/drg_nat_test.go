// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestDrgNatRuleArgs(t *testing.T) {
	rule := core.DrgNatRule{
		Id:                    common.String("rule-1"),
		DrgNatPolicyId:        common.String("ocid1.drgnatpolicy.oc1.iad.a"),
		DrgNatRulePriority:    common.Int64(10),
		OriginalSource:        common.String("10.0.0.0/24"),
		TranslatedSource:      common.String("172.16.0.0/24"),
		OriginalDestination:   common.String("192.168.1.0/24"),
		TranslatedDestination: common.String("192.168.2.0/24"),
	}

	t.Run("maps every field", func(t *testing.T) {
		args := drgNatRuleArgs("ocid1.drgnatpolicy.oc1.iad.a", rule)
		assert.Equal(t, "ocid1.drgnatpolicy.oc1.iad.a/rule/rule-1", args["__id"].Value)
		assert.Equal(t, "rule-1", args["id"].Value)
		assert.Equal(t, int64(10), args["priority"].Value)
		assert.Equal(t, "10.0.0.0/24", args["originalSource"].Value)
		assert.Equal(t, "172.16.0.0/24", args["translatedSource"].Value)
		assert.Equal(t, "192.168.1.0/24", args["originalDestination"].Value)
		assert.Equal(t, "192.168.2.0/24", args["translatedDestination"].Value)
	})

	t.Run("same rule id in two policies gets distinct cache keys", func(t *testing.T) {
		a := drgNatRuleArgs("ocid1.drgnatpolicy.oc1.iad.a", rule)
		b := drgNatRuleArgs("ocid1.drgnatpolicy.oc1.iad.b", rule)
		assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
	})

	t.Run("absent values are null", func(t *testing.T) {
		args := drgNatRuleArgs("ocid1.drgnatpolicy.oc1.iad.a", core.DrgNatRule{Id: common.String("rule-2")})
		for _, key := range []string{"priority", "originalSource", "translatedSource", "originalDestination", "translatedDestination"} {
			require.Contains(t, args, key)
			assert.Nil(t, args[key].Value, key)
		}
	})
}

func TestStringsOrNull(t *testing.T) {
	// An omitted list is unknown, not "no features".
	assert.Equal(t, llx.NilData, stringsOrNull(nil))

	assert.Equal(t, []any{}, stringsOrNull([]string{}).Value)
	assert.Equal(t, []any{"a", "b"}, stringsOrNull([]string{"a", "b"}).Value)
}

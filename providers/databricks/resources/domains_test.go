// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	sdktime "github.com/databricks/databricks-sdk-go/common/types/time"
	"github.com/databricks/databricks-sdk-go/service/domains"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// plainValues drops the llx wrapper so assertions read against Go values. A
// field carrying llx.NilData reads as nil, which is what MQL renders as null.
func plainValues(fields map[string]*llx.RawData) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = v.Value
	}
	return out
}

func TestDomainFields(t *testing.T) {
	created := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)
	updated := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

	t.Run("a fully populated domain maps every field", func(t *testing.T) {
		got := plainValues(domainFields(domains.Domain{
			DomainId:          "finance",
			Name:              "domains/finance",
			Subtitle:          "Finance data",
			Description:       "Everything the finance team owns",
			TagKey:            "domain_finance",
			EffectiveDraft:    true,
			BusinessOwnerIds:  []int64{1001, 1002},
			TechnicalOwnerIds: []int64{2001},
			ParentDomainId:    "corp",
			CreateTime:        sdktime.New(created),
			UpdateTime:        sdktime.New(updated),
		}))

		assert.Equal(t, "databricks.domain/finance", got["__id"])
		assert.Equal(t, "finance", got["id"])
		assert.Equal(t, "domains/finance", got["name"])
		assert.Equal(t, "Finance data", got["subtitle"])
		assert.Equal(t, "Everything the finance team owns", got["description"])
		assert.Equal(t, "domain_finance", got["tagKey"])
		assert.Equal(t, true, got["effectiveDraft"])
		assert.Equal(t, []any{int64(1001), int64(1002)}, got["businessOwnerIds"])
		assert.Equal(t, []any{int64(2001)}, got["technicalOwnerIds"])

		gotCreated, ok := got["createTime"].(*time.Time)
		require.True(t, ok)
		assert.True(t, created.Equal(*gotCreated))
		gotUpdated, ok := got["updateTime"].(*time.Time)
		require.True(t, ok)
		assert.True(t, updated.Equal(*gotUpdated))
	})

	t.Run("a domain without timestamps or owners reads null times and empty owners", func(t *testing.T) {
		// A nil SDK timestamp must not become the zero time: the SDK's own
		// accessor returns year 1 for a nil pointer, which a policy comparing
		// dates would treat as a real creation date.
		got := plainValues(domainFields(domains.Domain{
			DomainId: "orphan",
			Name:     "domains/orphan",
		}))

		assert.Nil(t, got["createTime"])
		assert.Nil(t, got["updateTime"])
		assert.Equal(t, []any{}, got["businessOwnerIds"])
		assert.Equal(t, []any{}, got["technicalOwnerIds"])
		assert.Equal(t, false, got["effectiveDraft"])
	})
}

func TestSdkTime(t *testing.T) {
	assert.Nil(t, sdkTime(nil), "nil pointer must read as null")
	assert.Nil(t, sdkTime(sdktime.New(time.Time{})), "the zero time is the unset sentinel, not a date")

	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := sdkTime(sdktime.New(want))
	require.NotNil(t, got)
	assert.True(t, want.Equal(*got))
}

func TestChildDomains(t *testing.T) {
	list := []domains.Domain{
		{DomainId: "corp"},
		{DomainId: "finance", ParentDomainId: "corp"},
		{DomainId: "hr", ParentDomainId: "corp"},
		{DomainId: "payroll", ParentDomainId: "finance"},
	}

	t.Run("returns direct children only, in list order", func(t *testing.T) {
		got := childDomains(list, "corp")
		require.Len(t, got, 2)
		assert.Equal(t, "finance", got[0].DomainId)
		assert.Equal(t, "hr", got[1].DomainId)
	})

	t.Run("a leaf domain has no children", func(t *testing.T) {
		assert.Empty(t, childDomains(list, "payroll"))
	})

	t.Run("top-level domains are not children of an empty parent lookup", func(t *testing.T) {
		// A resource's own id is never empty, but guard the helper anyway: an
		// empty parent id marks a top-level domain and must never be matched
		// as "child of the domain with empty id".
		got := childDomains(list, "")
		require.Len(t, got, 1)
		assert.Equal(t, "corp", got[0].DomainId)
	})
}

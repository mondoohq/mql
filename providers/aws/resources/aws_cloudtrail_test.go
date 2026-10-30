// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// setAnyList builds a resolved list field so a resource method can be exercised
// without a runtime: GetOrCompute returns a set value without calling compute.
func setAnyList(values ...string) plugin.TValue[[]any] {
	data := make([]any, 0, len(values))
	for _, v := range values {
		data = append(data, v)
	}
	return plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
}

// equalsSelector builds a field selector matching field against values.
func equalsSelector(field string, values ...string) *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector {
	fs := &mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector{}
	fs.Field = plugin.TValue[string]{Data: field, State: plugin.StateIsSet}
	fs.Equals = setAnyList(values...)
	fs.NotEquals = setAnyList()
	fs.StartsWith = setAnyList()
	fs.NotStartsWith = setAnyList()
	fs.EndsWith = setAnyList()
	fs.NotEndsWith = setAnyList()
	return fs
}

// notEqualsSelector builds a field selector excluding values from field.
func notEqualsSelector(field string, values ...string) *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector {
	fs := equalsSelector(field)
	fs.NotEquals = setAnyList(values...)
	return fs
}

func advancedSelector(fieldSelectors ...*mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector) *mqlAwsCloudtrailTrailAdvancedEventSelector {
	data := make([]any, 0, len(fieldSelectors))
	for _, fs := range fieldSelectors {
		data = append(data, fs)
	}
	sel := &mqlAwsCloudtrailTrailAdvancedEventSelector{}
	sel.FieldSelectors = plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
	return sel
}

func advancedSelectors(sels ...*mqlAwsCloudtrailTrailAdvancedEventSelector) []any {
	data := make([]any, 0, len(sels))
	for _, s := range sels {
		data = append(data, s)
	}
	return data
}

// TestAdvancedSelectorsCaptureAllManagementEvents covers the mechanism a trail
// configured through CloudFormation or Terraform uses. An advanced selector
// says what it captures through its field selectors rather than through a
// readWriteType enum: eventCategory Equals ["Management"] selects management
// events, and the selector captures both reads and writes unless it also
// constrains readOnly.
func TestAdvancedSelectorsCaptureAllManagementEvents(t *testing.T) {
	tests := []struct {
		name      string
		selectors []any
		expected  bool
	}{
		{
			name:      "no advanced selectors",
			selectors: nil,
			expected:  false,
		},
		{
			// The shape both CloudFormation and Terraform emit for a trail that
			// logs all management events.
			name:      "management with no readOnly constraint",
			selectors: advancedSelectors(advancedSelector(equalsSelector("eventCategory", "Management"))),
			expected:  true,
		},
		{
			name: "management restricted to read events",
			selectors: advancedSelectors(advancedSelector(
				equalsSelector("eventCategory", "Management"),
				equalsSelector("readOnly", "true"),
			)),
			expected: false,
		},
		{
			name: "management restricted to write events",
			selectors: advancedSelectors(advancedSelector(
				equalsSelector("eventCategory", "Management"),
				equalsSelector("readOnly", "false"),
			)),
			expected: false,
		},
		{
			// NotEquals narrows the selector just as Equals does, so it is not
			// capturing both directions either.
			name: "management with a negated readOnly constraint",
			selectors: advancedSelectors(advancedSelector(
				equalsSelector("eventCategory", "Management"),
				notEqualsSelector("readOnly", "true"),
			)),
			expected: false,
		},
		{
			name: "data events only",
			selectors: advancedSelectors(advancedSelector(
				equalsSelector("eventCategory", "Data"),
				equalsSelector("resources.type", "AWS::S3::Object"),
			)),
			expected: false,
		},
		{
			// A trail commonly carries several selectors; one that qualifies is
			// enough, and it must be found even when it is not the first.
			name: "a qualifying selector alongside a data selector",
			selectors: advancedSelectors(
				advancedSelector(
					equalsSelector("eventCategory", "Data"),
					equalsSelector("resources.type", "AWS::S3::Object"),
				),
				advancedSelector(equalsSelector("eventCategory", "Management")),
			),
			expected: true,
		},
		{
			name: "read-only and write-only management selectors do not combine",
			selectors: advancedSelectors(
				advancedSelector(
					equalsSelector("eventCategory", "Management"),
					equalsSelector("readOnly", "true"),
				),
				advancedSelector(
					equalsSelector("eventCategory", "Management"),
					equalsSelector("readOnly", "false"),
				),
			),
			expected: false,
		},
		{
			name:      "field name in a different case",
			selectors: advancedSelectors(advancedSelector(equalsSelector("eventcategory", "management"))),
			expected:  true,
		},
		{
			// A selector with no field selectors at all selects nothing this
			// predicate can vouch for.
			name:      "selector with no field selectors",
			selectors: advancedSelectors(advancedSelector()),
			expected:  false,
		},
		{
			// An empty field name must not be read as matching either name.
			name:      "field selector with no field name",
			selectors: advancedSelectors(advancedSelector(equalsSelector("", "Management"))),
			expected:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := advancedSelectorsCaptureAllManagementEvents(test.selectors)
			require.NoError(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestFieldSelectorConstrains(t *testing.T) {
	t.Run("no condition at all", func(t *testing.T) {
		got, err := fieldSelectorConstrains(equalsSelector("readOnly"))
		require.NoError(t, err)
		assert.False(t, got)
	})

	// Every match kind narrows the selector, so every one of them counts.
	for _, tc := range []struct {
		name string
		fs   *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector
	}{
		{"equals", equalsSelector("readOnly", "true")},
		{"notEquals", notEqualsSelector("readOnly", "true")},
		{"startsWith", func() *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector {
			fs := equalsSelector("readOnly")
			fs.StartsWith = setAnyList("t")
			return fs
		}()},
		{"endsWith", func() *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector {
			fs := equalsSelector("readOnly")
			fs.EndsWith = setAnyList("e")
			return fs
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fieldSelectorConstrains(tc.fs)
			require.NoError(t, err)
			assert.True(t, got)
		})
	}
}

func TestContainsFold(t *testing.T) {
	assert.True(t, containsFold([]any{"Data", "Management"}, "Management"))
	assert.True(t, containsFold([]any{"management"}, "Management"))
	assert.False(t, containsFold([]any{"Data"}, "Management"))
	assert.False(t, containsFold(nil, "Management"))
	// A non-string element is not a match and must not panic.
	assert.False(t, containsFold([]any{42}, "Management"))
}

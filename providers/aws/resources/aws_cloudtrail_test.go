// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/stretchr/testify/assert"
)

func fieldSelector(field string, equals ...string) types.AdvancedFieldSelector {
	return types.AdvancedFieldSelector{Field: aws.String(field), Equals: equals}
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
		selectors []types.AdvancedEventSelector
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
			name: "management with no readOnly constraint",
			selectors: []types.AdvancedEventSelector{{
				Name:           aws.String("Management events"),
				FieldSelectors: []types.AdvancedFieldSelector{fieldSelector("eventCategory", "Management")},
			}},
			expected: true,
		},
		{
			name: "management restricted to read events",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Management"),
					fieldSelector("readOnly", "true"),
				},
			}},
			expected: false,
		},
		{
			name: "management restricted to write events",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Management"),
					fieldSelector("readOnly", "false"),
				},
			}},
			expected: false,
		},
		{
			// NotEquals narrows the selector just as Equals does, so it is not
			// capturing both directions either.
			name: "management with a negated readOnly constraint",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Management"),
					{Field: aws.String("readOnly"), NotEquals: []string{"true"}},
				},
			}},
			expected: false,
		},
		{
			name: "data events only",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Data"),
					fieldSelector("resources.type", "AWS::S3::Object"),
				},
			}},
			expected: false,
		},
		{
			// A trail commonly carries several selectors; one that qualifies is
			// enough, and it must be found even when it is not the first.
			name: "a qualifying selector alongside a data selector",
			selectors: []types.AdvancedEventSelector{
				{FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Data"),
					fieldSelector("resources.type", "AWS::S3::Object"),
				}},
				{FieldSelectors: []types.AdvancedFieldSelector{fieldSelector("eventCategory", "Management")}},
			},
			expected: true,
		},
		{
			name: "read-only and write-only management selectors do not combine",
			selectors: []types.AdvancedEventSelector{
				{FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Management"),
					fieldSelector("readOnly", "true"),
				}},
				{FieldSelectors: []types.AdvancedFieldSelector{
					fieldSelector("eventCategory", "Management"),
					fieldSelector("readOnly", "false"),
				}},
			},
			expected: false,
		},
		{
			name: "field name in a different case",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{fieldSelector("eventcategory", "management")},
			}},
			expected: true,
		},
		{
			// A selector with no field selectors at all selects nothing this
			// predicate can vouch for.
			name:      "selector with no field selectors",
			selectors: []types.AdvancedEventSelector{{Name: aws.String("empty")}},
			expected:  false,
		},
		{
			// An absent Field must not be read as matching either name.
			name: "field selector with no field name",
			selectors: []types.AdvancedEventSelector{{
				FieldSelectors: []types.AdvancedFieldSelector{{Equals: []string{"Management"}}},
			}},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected,
				advancedSelectorsCaptureAllManagementEvents(test.selectors))
		})
	}
}

func TestContainsFold(t *testing.T) {
	assert.True(t, containsFold([]string{"Data", "Management"}, "Management"))
	assert.True(t, containsFold([]string{"management"}, "Management"))
	assert.False(t, containsFold([]string{"Data"}, "Management"))
	assert.False(t, containsFold(nil, "Management"))
}

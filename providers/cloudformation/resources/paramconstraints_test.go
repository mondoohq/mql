// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws-cloudformation/rain/cft/parse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// CloudFormation `Number` parameters may be integers or floats, so
// `MinValue: 0.5` is legal template content. Parsing it as an int failed, and
// that error propagated out of parameterList() — erasing EVERY parameter in the
// template, including unrelated NoEcho credential parameters that policies care
// about.
func TestParameterListSurvivesFloatConstraints(t *testing.T) {
	tmpl := loadTemplateFromString(t, `
Parameters:
  Ratio:
    Type: Number
    MinValue: 0.5
    MaxValue: 1.5
  Secret:
    Type: String
    NoEcho: true
  Sized:
    Type: String
    MinLength: 8
`)

	params, err := tmpl.parameterList()
	require.NoError(t, err, "one float constraint must not fail the whole list")
	require.Len(t, params, 3, "every parameter must survive")

	byName := map[string]*mqlCloudformationParameter{}
	for _, p := range params {
		mp := p.(*mqlCloudformationParameter)
		byName[mp.Name.Data] = mp
	}

	require.Contains(t, byName, "Secret")
	assert.True(t, byName["Secret"].NoEcho.Data, "the NoEcho parameter must still be reported")

	require.Contains(t, byName, "Sized")
	require.NotNil(t, byName["Sized"].MinLength.Data)
	assert.Equal(t, int64(8), byName["Sized"].MinLength.Data)

	// The fractional bound cannot be represented by the int-typed field, so it
	// reads as absent rather than as a wrong number.
	require.Contains(t, byName, "Ratio")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, byName["Ratio"].MinValue.State&(plugin.StateIsSet|plugin.StateIsNull))
}

// An integral float (`MinValue: 1.0`) is exactly representable and must be
// reported, not dropped.
func TestNodeToIntAcceptsIntegralFloat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		want    *int64
		wantErr bool
	}{
		{name: "integer", yaml: "MinValue: 5", want: int64Ptr(5)},
		{name: "negative integer", yaml: "MinValue: -3", want: int64Ptr(-3)},
		{name: "integral float", yaml: "MinValue: 1.0", want: int64Ptr(1)},
		{name: "integral float with exponent", yaml: "MinValue: 1e3", want: int64Ptr(1000)},
		{name: "fractional float is not an int", yaml: "MinValue: 0.5", wantErr: true},
		{name: "not a number", yaml: "MinValue: abc", wantErr: true},
		{name: "absent key", yaml: "Other: 1", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parse.String("Parameters:\n  P:\n    " + tc.yaml + "\n")
			require.NoError(t, err)
			_, params, err := gatherMapValue(parsed.Node.Content[0], "Parameters")
			require.NoError(t, err)
			_, p, err := gatherMapValue(params, "P")
			require.NoError(t, err)

			got, err := nodeToInt(p, "MinValue")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

//go:fix inline
func int64Ptr(v int64) *int64 { return new(v) }

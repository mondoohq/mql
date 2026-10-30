// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestWithDefaultArg(t *testing.T) {
	t.Run("fills an absent argument", func(t *testing.T) {
		args := withDefaultArg(map[string]*llx.RawData{}, "id", "nodeidCNTRL")
		require.Contains(t, args, "id")
		assert.Equal(t, "nodeidCNTRL", args["id"].Value)
	})

	t.Run("never overrides an explicit argument", func(t *testing.T) {
		args := withDefaultArg(map[string]*llx.RawData{"id": llx.StringData("explicit")}, "id", "from-asset")
		assert.Equal(t, "explicit", args["id"].Value)
	})

	t.Run("an empty value is not injected", func(t *testing.T) {
		// An empty asset-derived id must not be written, or it would satisfy
		// the presence check while carrying nothing to look up.
		args := withDefaultArg(map[string]*llx.RawData{}, "id", "")
		assert.NotContains(t, args, "id")
	})

	t.Run("a nil map is allocated rather than panicking", func(t *testing.T) {
		args := withDefaultArg(nil, "id", "nodeidCNTRL")
		require.NotNil(t, args)
		assert.Equal(t, "nodeidCNTRL", args["id"].Value)
	})

	t.Run("a nil map with no value stays nil", func(t *testing.T) {
		assert.Nil(t, withDefaultArg(nil, "id", ""))
	})
}

func TestRequiredStringArg(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]*llx.RawData
		want    string
		wantErr string
	}{
		{
			name: "present",
			args: map[string]*llx.RawData{"id": llx.StringData("nodeidCNTRL")},
			want: "nodeidCNTRL",
		},
		{
			name:    "absent",
			args:    map[string]*llx.RawData{},
			wantErr: "missing required argument 'id'",
		},
		{
			name:    "nil raw data",
			args:    map[string]*llx.RawData{"id": nil},
			wantErr: "missing required argument 'id'",
		},
		{
			// A null argument reaches the init with a nil Value. A bare type
			// assertion would panic here, and a panic in a provider goroutine
			// takes down the whole scan.
			name:    "null value",
			args:    map[string]*llx.RawData{"id": llx.NilData},
			wantErr: "missing required argument 'id'",
		},
		{
			name:    "empty string",
			args:    map[string]*llx.RawData{"id": llx.StringData("")},
			wantErr: "missing required argument 'id'",
		},
		{
			name:    "wrong type",
			args:    map[string]*llx.RawData{"id": llx.IntData(42)},
			wantErr: "wrong type for argument 'id', expected a string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requiredStringArg(tc.args, "id")
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

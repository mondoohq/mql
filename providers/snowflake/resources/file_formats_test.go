// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileFormatOptionsToDict(t *testing.T) {
	// Shape of the format_options column SHOW FILE FORMATS returns for a CSV
	// format.
	t.Run("csv options keyed by option name", func(t *testing.T) {
		got, err := fileFormatOptionsToDict(`{"TYPE":"CSV","RECORD_DELIMITER":"\n","FIELD_DELIMITER":",","FILE_EXTENSION":null,"SKIP_HEADER":1,"PARSE_HEADER":false,"ERROR_ON_COLUMN_COUNT_MISMATCH":true,"NULL_IF":["\\N","NULL"],"COMPRESSION":"GZIP"}`)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{
			"RECORD_DELIMITER":               "\n",
			"FIELD_DELIMITER":                ",",
			"FILE_EXTENSION":                 nil,
			"SKIP_HEADER":                    int64(1),
			"PARSE_HEADER":                   false,
			"ERROR_ON_COLUMN_COUNT_MISMATCH": true,
			"NULL_IF":                        []any{`\N`, "NULL"},
			"COMPRESSION":                    "GZIP",
		}, got)
	})

	// TYPE duplicates the format's own type field.
	t.Run("type is dropped", func(t *testing.T) {
		got, err := fileFormatOptionsToDict(`{"TYPE":"JSON","STRIP_OUTER_ARRAY":true}`)
		require.NoError(t, err)
		assert.NotContains(t, got, "TYPE")
		assert.Equal(t, true, got["STRIP_OUTER_ARRAY"])
	})

	// An integral option must compare equal to an int in MQL, not 1.0.
	t.Run("integral numbers are int64, others float64", func(t *testing.T) {
		got, err := fileFormatOptionsToDict(`{"SKIP_HEADER":2,"RATIO":0.5,"NESTED":[3]}`)
		require.NoError(t, err)
		assert.Equal(t, int64(2), got["SKIP_HEADER"])
		assert.Equal(t, 0.5, got["RATIO"])
		assert.Equal(t, []any{int64(3)}, got["NESTED"])
	})

	t.Run("empty column is null, not an empty dict", func(t *testing.T) {
		got, err := fileFormatOptionsToDict("")
		require.NoError(t, err)
		assert.Nil(t, got)

		got, err = fileFormatOptionsToDict("null")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("malformed column is an error", func(t *testing.T) {
		got, err := fileFormatOptionsToDict(`{"SKIP_HEADER":`)
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

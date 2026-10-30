// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestStringOrRegexMatcher(t *testing.T) {
	tests := []struct {
		term    *llx.RawData
		matches []string
		fails   []string
	}{
		{
			term:    llx.StringData("word"),
			matches: []string{"word"},
			fails:   []string{"", "myword", "wordle"},
		},
		{
			term:    llx.StringData(""),
			matches: []string{""},
			fails:   []string{"myword", "wordle"},
		},
		{
			term:    llx.RegexData("my.*"),
			matches: []string{"myword", "ohmy"},
			fails:   []string{"", "wordle"},
		},
		{
			term:    llx.DictData("word"),
			matches: []string{"word"},
			fails:   []string{"", "myword", "wordle"},
		},
		{
			term:    llx.NilData,
			matches: []string{"", "all"},
			fails:   []string{},
		},
	}

	for i := range tests {
		cur := tests[i]
		t.Run(cur.term.String(), func(t *testing.T) {
			m, err := llx.StringOrRegexMatcher(cur.term)
			require.NoError(t, err)

			if m == nil {
				assert.Empty(t, cur.fails)
				return
			}

			for _, s := range cur.matches {
				assert.True(t, m(s), "matches "+s)
			}
			for _, s := range cur.fails {
				assert.False(t, m(s), "matches "+s)
			}
		})
	}
}

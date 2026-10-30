// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

// filtersFlag builds the --filters key-value flag the CLI hands to ParseCLI.
func filtersFlag(kv map[string]string) map[string]*llx.Primitive {
	m := map[string]*llx.Primitive{}
	for k, v := range kv {
		m[k] = llx.StringPrimitive(v)
	}
	return map[string]*llx.Primitive{"filters": {Map: m}}
}

func TestParseFlagsToFiltersOpts(t *testing.T) {
	t.Run("returns no options when the flag is absent", func(t *testing.T) {
		assert.Empty(t, parseFlagsToFiltersOpts(map[string]*llx.Primitive{}))
	})

	t.Run("returns no options for an empty filter map", func(t *testing.T) {
		assert.Empty(t, parseFlagsToFiltersOpts(filtersFlag(nil)))
	})

	t.Run("keeps the supported filter keys", func(t *testing.T) {
		want := map[string]string{
			"regions":         "nyc1,sfo3",
			"exclude:regions": "ams3",
			"tags":            "production",
			"exclude:tags":    "temporary",
		}
		assert.Equal(t, want, parseFlagsToFiltersOpts(filtersFlag(want)))
	})

	t.Run("drops unknown keys so a typo does not look accepted", func(t *testing.T) {
		opts := parseFlagsToFiltersOpts(filtersFlag(map[string]string{
			"region": "nyc1",
			"tag":    "production",
		}))
		assert.Empty(t, opts)
	})
}

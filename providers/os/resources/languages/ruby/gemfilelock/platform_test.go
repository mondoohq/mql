// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemfilelock

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rails 7.1's Gemfile.lock, resolved for three platforms, lists nokogiri once
// per platform. With the platform stripped that is the same gem three times,
// and ruby.packages reported three packages with one id. Fails if the entries
// are no longer merged, or if a platform entry's dependency lines are
// attached to the wrong gem.
func TestGemfileLockMergesPlatformVariants(t *testing.T) {
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.4)
    nokogiri (1.15.4)
      mini_portile2 (~> 2.8.2)
      racc (~> 1.4)
    nokogiri (1.15.4-x86_64-darwin)
      racc (~> 1.4)
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.1)

PLATFORMS
  ruby
  x86_64-darwin
  x86_64-linux

DEPENDENCIES
  nokogiri
`
	bom, err := (&Extractor{}).Parse(strings.NewReader(lock), "Gemfile.lock")
	require.NoError(t, err)

	var ids []string
	for _, p := range bom.Transitive() {
		ids = append(ids, p.Name+"@"+p.Version)
	}
	assert.Equal(t, []string{"mini_portile2@2.8.4", "nokogiri@1.15.4", "racc@1.7.1"}, ids)

	direct := bom.Direct()
	require.Len(t, direct, 1)
	assert.Equal(t, []string{"pkg:gem/mini_portile2@2.8.4", "pkg:gem/racc@1.7.1"}, direct[0].DependsOn)
}

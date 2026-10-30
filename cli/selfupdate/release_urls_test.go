// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/config"
)

// The service's layout is tried first; the bucket's is the fallback.
func TestReleaseURLsOrder(t *testing.T) {
	urls := ReleaseURLs("", "mql", "")
	require.Len(t, urls, 2)
	assert.Equal(t, "https://install.mondoo.com/package/mql/latest.json", urls[0])
	assert.Equal(t, "https://install.mondoo.com/mql/latest.json", urls[1])
}

// A channel is spelled differently in each layout. Producing only one spelling
// would drop a preview client back onto stable whenever the fallback is used --
// an update to the wrong track, reported as success.
func TestReleaseURLsCarryTheChannelIntoBothLayouts(t *testing.T) {
	urls := ReleaseURLs("https://mirror.example.de", "mql", config.ChannelPreview)
	require.Len(t, urls, 2)
	assert.Equal(t, "https://mirror.example.de/package/mql/latest.json?channel=preview", urls[0])
	assert.Equal(t, "https://mirror.example.de/mql/preview.json", urls[1])
}

func TestReleaseURLsHonoursAConfiguredHost(t *testing.T) {
	urls := ReleaseURLs("https://releases.example.de/", "cnspec", "")
	require.Len(t, urls, 2)
	assert.Equal(t, "https://releases.example.de/package/cnspec/latest.json", urls[0])
	assert.Equal(t, "https://releases.example.de/cnspec/latest.json", urls[1])
}

func TestConfigReleaseURLsOrdering(t *testing.T) {
	cfg := Config{ReleaseURL: "https://a/one.json", FallbackReleaseURLs: []string{"https://b/two.json"}}
	assert.Equal(t, []string{"https://a/one.json", "https://b/two.json"}, cfg.releaseURLs())
}

// A caller that sets no fallback must check exactly one URL, and duplicates and
// blanks must not turn into extra requests.
func TestConfigReleaseURLsSkipsBlanksAndDuplicates(t *testing.T) {
	cfg := Config{ReleaseURL: "https://a/one.json"}
	assert.Equal(t, []string{"https://a/one.json"}, cfg.releaseURLs())

	cfg = Config{ReleaseURL: "https://a/one.json", FallbackReleaseURLs: []string{"", "https://a/one.json"}}
	assert.Equal(t, []string{"https://a/one.json"}, cfg.releaseURLs())
}

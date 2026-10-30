// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/cli/config"
)

func TestReleaseURLDefaults(t *testing.T) {
	assert.Equal(t, "https://install.mondoo.com/package/mql/latest.json",
		ReleaseURL("", "mql", ""))
	assert.Equal(t, "https://install.mondoo.com/package/cnspec/latest.json",
		ReleaseURL("", "cnspec", ""))
}

// An unset channel and the stable one must produce the same URL, so configuring
// the channel a client is already on cannot change which document it reads.
func TestReleaseURLStableIsTheBareManifest(t *testing.T) {
	bare := ReleaseURL("", "mql", "")
	assert.Equal(t, bare, ReleaseURL("", "mql", config.ChannelStable))
}

// The channel is a query parameter, not a sibling document: the service's routes
// are named after the package, so /package/mql/preview.json is not a route.
func TestReleaseURLChannelIsAQueryParameter(t *testing.T) {
	assert.Equal(t, "https://install.mondoo.com/package/mql/latest.json?channel=preview",
		ReleaseURL("", "mql", config.ChannelPreview))
}

func TestReleaseURLHonoursAConfiguredHost(t *testing.T) {
	assert.Equal(t, "https://mirror.example.com/package/mql/latest.json",
		ReleaseURL("https://mirror.example.com", "mql", ""))

	// A trailing slash must not double up into "//package".
	assert.Equal(t, "https://mirror.example.com/package/mql/latest.json",
		ReleaseURL("https://mirror.example.com/", "mql", ""))
}

// ReleaseURL is exported, so a caller can reach it with something other than the
// two normalized constants. That must stay a valid URL with one odd parameter
// rather than a second "?" or an injected one.
func TestReleaseURLEncodesAnUnexpectedChannel(t *testing.T) {
	assert.Equal(t, "https://install.mondoo.com/package/mql/latest.json?channel=a%26b%3Dc",
		ReleaseURL("", "mql", "a&b=c"))
}

// The bucket spells the manifest and the channel differently, which is why one
// updates_url cannot address both layouts. Pin the shape we build so a change
// back to the bucket's is deliberate rather than incidental.
func TestReleaseURLIsNotTheBucketLayout(t *testing.T) {
	url := ReleaseURL("", "mql", config.ChannelPreview)
	// The bucket hangs the manifest straight off the host, "<host>/mql/...";
	// the install service routes it under the package.
	assert.NotContains(t, url, "mondoo.com/mql/", "that is the bucket's path")
	assert.NotContains(t, url, "preview.json", "the bucket spells a channel as a sibling document")
	assert.Contains(t, url, "/package/mql/latest.json")
}

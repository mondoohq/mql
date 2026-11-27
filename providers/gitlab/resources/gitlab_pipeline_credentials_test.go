// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestMirrorHostKeyFingerprints(t *testing.T) {
	// Synthetic: attribute names from the GitLab remote mirrors API for a
	// mirror that pins host keys and one that does not. No target showed this.
	var mirrors []*gitlab.ProjectMirror
	require.NoError(t, json.Unmarshal([]byte(`[
		{"id": 1, "host_keys": [{"fingerprint_sha256": "SHA256:abc"}, {"fingerprint_sha256": ""}, {"fingerprint_sha256": "SHA256:def"}],
		 "last_update_started_at": "2026-11-01T10:00:00Z"},
		{"id": 2, "host_keys": []},
		{"id": 3}
	]`), &mirrors))
	require.Len(t, mirrors, 3)

	assert.Equal(t, []string{"SHA256:abc", "SHA256:def"}, mirrorHostKeyFingerprints(mirrors[0].HostKeys))
	require.NotNil(t, mirrors[0].LastUpdateStartedAt)
	assert.Nil(t, mirrorHostKeyFingerprints(mirrors[1].HostKeys), "no pinned keys reads null")
	assert.Nil(t, mirrorHostKeyFingerprints(mirrors[2].HostKeys))
	assert.Nil(t, stringsOrNull(mirrorHostKeyFingerprints(mirrors[2].HostKeys)).Value)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// References that normalize to the same name are separate resources, each
// reporting the reference it was asked for.
func TestContainerImageIsKeyedByReference(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	refs := []string{
		"alpine",
		"docker.io/library/alpine:latest",
		"index.docker.io/library/alpine",
	}
	for _, ref := range refs {
		_, res, err := initContainerImage(runtime, map[string]*llx.RawData{
			"reference": llx.StringData(ref),
		})
		require.NoError(t, err)
		img := res.(*mqlContainerImage)
		assert.Equal(t, ref, img.Reference.Data)
		assert.Equal(t, "index.docker.io/library/alpine:latest", img.Name.Data)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/functions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFunctionContainerImage(t *testing.T) {
	t.Run("container image function", func(t *testing.T) {
		var fn functions.FunctionSummary
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "ocid1.fnfunc.oc1..a",
			"sourceDetails": {
				"sourceType": "CONTAINER_IMAGE",
				"image": "phx.ocir.io/ten/functions/hello:0.0.1",
				"imageDigest": "sha256:ca0e"
			}
		}`), &fn))

		image, digest := functionContainerImage(fn.SourceDetails)
		require.NotNil(t, image)
		require.NotNil(t, digest)
		assert.Equal(t, "phx.ocir.io/ten/functions/hello:0.0.1", *image)
		assert.Equal(t, "sha256:ca0e", *digest)
	})

	t.Run("archive function has no image", func(t *testing.T) {
		var fn functions.FunctionSummary
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "ocid1.fnfunc.oc1..b",
			"sourceDetails": {"sourceType": "ARCHIVE"}
		}`), &fn))

		image, digest := functionContainerImage(fn.SourceDetails)
		assert.Nil(t, image)
		assert.Nil(t, digest)
	})

	t.Run("absent source details", func(t *testing.T) {
		image, digest := functionContainerImage(nil)
		assert.Nil(t, image)
		assert.Nil(t, digest)
	})
}

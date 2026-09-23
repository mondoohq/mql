// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
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

func decodeFunctionSummarySource(t *testing.T, body string) functionSource {
	t.Helper()
	var fn functions.FunctionSummary
	require.NoError(t, json.Unmarshal([]byte(body), &fn))
	return decodeFunctionSource(fn.SourceDetails)
}

func TestDecodeFunctionSource(t *testing.T) {
	t.Run("container image function", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..a",
			"sourceDetails": {
				"sourceType": "CONTAINER_IMAGE",
				"image": "phx.ocir.io/ten/functions/hello:0.0.1",
				"imageDigest": "sha256:ca0e"
			}
		}`)
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "CONTAINER_IMAGE", *src.sourceType)
		assert.Nil(t, src.runtime)
		assert.Nil(t, src.runtimeUpdateStrategy)
		assert.Nil(t, src.handler)
		assert.Nil(t, src.sourceCodeSha256)
		assert.Nil(t, src.bucketName)
		assert.Nil(t, src.bucketNamespace)
		assert.Nil(t, src.objectName)
	})

	t.Run("archive from object storage, updated with the function", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..b",
			"sourceDetails": {
				"sourceType": "ARCHIVE",
				"archiveSourceDetails": {
					"archiveSourceType": "OBJECT_STORAGE_ARCHIVE",
					"bucketName": "fn-code",
					"namespace": "examplens",
					"objectName": "hello/v1.zip",
					"objectVersionId": "v1"
				},
				"runtimeConfig": {
					"runtimeConfigType": "FUNCTION_UPDATE",
					"functionsRuntimeName": "python311",
					"functionsRuntimeVersionId": "ocid1.fnruntimeversion.oc1..x"
				},
				"handler": "func.handler",
				"sourceCodeSha256": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
			}
		}`)
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "ARCHIVE", *src.sourceType)
		require.NotNil(t, src.runtime)
		assert.Equal(t, "python311", *src.runtime)
		require.NotNil(t, src.runtimeUpdateStrategy)
		assert.Equal(t, "FUNCTION_UPDATE", *src.runtimeUpdateStrategy)
		require.NotNil(t, src.handler)
		assert.Equal(t, "func.handler", *src.handler)
		require.NotNil(t, src.sourceCodeSha256)
		assert.Equal(t, "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", *src.sourceCodeSha256)
		require.NotNil(t, src.bucketNamespace)
		assert.Equal(t, "examplens", *src.bucketNamespace)
		require.NotNil(t, src.bucketName)
		assert.Equal(t, "fn-code", *src.bucketName)
		require.NotNil(t, src.objectName)
		assert.Equal(t, "hello/v1.zip", *src.objectName)
	})

	t.Run("direct archive with a pinned runtime", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..c",
			"sourceDetails": {
				"sourceType": "ARCHIVE",
				"archiveSourceDetails": {"archiveSourceType": "DIRECT_ARCHIVE"},
				"runtimeConfig": {
					"runtimeConfigType": "MANUAL",
					"functionsRuntimeName": "node20"
				},
				"handler": ""
			}
		}`)
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "ARCHIVE", *src.sourceType)
		require.NotNil(t, src.runtime)
		assert.Equal(t, "node20", *src.runtime)
		require.NotNil(t, src.runtimeUpdateStrategy)
		assert.Equal(t, "MANUAL", *src.runtimeUpdateStrategy)
		// An empty handler and an absent hash read as null, not "".
		assert.Nil(t, src.handler)
		assert.Nil(t, src.sourceCodeSha256)
		// A direct upload names no bucket.
		assert.Nil(t, src.bucketNamespace)
		assert.Nil(t, src.bucketName)
		assert.Nil(t, src.objectName)
	})

	t.Run("archive with a runtime config type the SDK does not know", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..d",
			"sourceDetails": {
				"sourceType": "ARCHIVE",
				"archiveSourceDetails": {"archiveSourceType": "DIRECT_ARCHIVE"},
				"runtimeConfig": {"runtimeConfigType": "SCHEDULED", "functionsRuntimeName": "java21"}
			}
		}`)
		require.NotNil(t, src.runtimeUpdateStrategy)
		assert.Equal(t, "SCHEDULED", *src.runtimeUpdateStrategy)
		assert.Nil(t, src.runtime)
	})

	t.Run("pre-built function", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..e",
			"sourceDetails": {
				"sourceType": "PRE_BUILT_FUNCTIONS",
				"pbfListingId": "ocid1.fnpbflisting.oc1..y"
			}
		}`)
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "PRE_BUILT_FUNCTIONS", *src.sourceType)
		assert.Nil(t, src.runtime)
		assert.Nil(t, src.handler)
		assert.Nil(t, src.bucketName)
	})

	t.Run("source type the SDK does not know", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{
			"id": "ocid1.fnfunc.oc1..f",
			"sourceDetails": {"sourceType": "GIT_REPOSITORY"}
		}`)
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "GIT_REPOSITORY", *src.sourceType)
		assert.Nil(t, src.runtime)
	})

	t.Run("summary without source details", func(t *testing.T) {
		src := decodeFunctionSummarySource(t, `{"id": "ocid1.fnfunc.oc1..g"}`)
		assert.Nil(t, src.sourceType)
		assert.Nil(t, src.runtime)
		assert.Nil(t, src.bucketName)
	})

	t.Run("GetFunction response decodes the same way", func(t *testing.T) {
		var fn functions.Function
		require.NoError(t, json.Unmarshal([]byte(`{
			"id": "ocid1.fnfunc.oc1..h",
			"sourceDetails": {
				"sourceType": "ARCHIVE",
				"archiveSourceDetails": {
					"archiveSourceType": "OBJECT_STORAGE_ARCHIVE",
					"bucketName": "fn-code",
					"namespace": "examplens",
					"objectName": "hello.zip"
				},
				"runtimeConfig": {"runtimeConfigType": "MANUAL", "functionsRuntimeName": "go122"},
				"handler": "main"
			}
		}`), &fn))
		src := decodeFunctionSource(fn.SourceDetails)
		require.NotNil(t, src.runtime)
		assert.Equal(t, "go122", *src.runtime)
		require.NotNil(t, src.bucketName)
		assert.Equal(t, "fn-code", *src.bucketName)
		require.NotNil(t, src.objectName)
		assert.Equal(t, "hello.zip", *src.objectName)
	})

	t.Run("pointer variants", func(t *testing.T) {
		src := decodeFunctionSource(&functions.ArchiveFunctionSourceDetails{
			RuntimeConfig: &functions.ManualRuntimeConfig{FunctionsRuntimeName: common.String("python312")},
			ArchiveSourceDetails: &functions.ObjectStorageArchiveSourceDetails{
				BucketName: common.String("b"),
				Namespace:  common.String("ns"),
				ObjectName: common.String("o.zip"),
			},
		})
		require.NotNil(t, src.sourceType)
		assert.Equal(t, "ARCHIVE", *src.sourceType)
		require.NotNil(t, src.runtime)
		assert.Equal(t, "python312", *src.runtime)
		require.NotNil(t, src.runtimeUpdateStrategy)
		assert.Equal(t, "MANUAL", *src.runtimeUpdateStrategy)
		require.NotNil(t, src.bucketName)
		assert.Equal(t, "b", *src.bucketName)

		assert.Nil(t, decodeFunctionSource((*functions.ArchiveFunctionSourceDetails)(nil)).sourceType)
	})
}

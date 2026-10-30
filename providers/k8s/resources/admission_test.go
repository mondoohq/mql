// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/admission"
	"go.mondoo.com/mql/utils/syncx"
)

// loadAdmissionRuntime builds an admission connection from the given review
// fixture and wires a runtime against it.
func loadAdmissionRuntime(t *testing.T, fixture string) *plugin.Runtime {
	t.Helper()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)

	conn, err := admission.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{Options: map[string]string{}}},
	}, base64.StdEncoding.EncodeToString(data))
	require.NoError(t, err)
	require.NotNil(t, conn)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

// TestAdmissionReviewRequest_Delete pins the fix for the panic that occurred
// when request() indexed obj[0] on a DELETE review, whose incoming object is
// empty (the object lives in oldObject instead). The accessor must resolve
// without panicking, report object as null, and surface the old object.
func TestAdmissionReviewRequest_Delete(t *testing.T) {
	runtime := loadAdmissionRuntime(t, "testdata/admission-review-delete.json")

	review := &mqlK8sAdmissionreview{MqlRuntime: runtime}
	req, err := review.request()
	require.NoError(t, err)
	require.NotNil(t, req)

	assert.Equal(t, "DELETE", req.Operation.Data)
	assert.Equal(t, "deleted-pod", req.Name.Data)

	// The incoming object is empty on DELETE and must be null, not a panic.
	assert.Nil(t, req.Object.Data, "object must be null on a DELETE review")
	assert.True(t, req.Object.State&plugin.StateIsNull != 0, "object must be marked null")

	// The old object carries the deleted resource.
	require.NotNil(t, req.OldObject.Data, "oldObject must be populated on a DELETE review")
}

// TestAdmissionReviewRequest_Create keeps the happy path (CREATE, populated
// object) covered so the DELETE guard doesn't regress the common case.
func TestAdmissionReviewRequest_Create(t *testing.T) {
	runtime := loadAdmissionRuntime(t, "../connection/shared/resources/testdata/admission-review.json")

	review := &mqlK8sAdmissionreview{MqlRuntime: runtime}
	req, err := review.request()
	require.NoError(t, err)
	require.NotNil(t, req)

	assert.Equal(t, "CREATE", req.Operation.Data)
	require.NotNil(t, req.Object.Data, "object must be populated on a CREATE review")
}

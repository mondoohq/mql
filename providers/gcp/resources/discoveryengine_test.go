// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceAccountProjectFromEmail(t *testing.T) {
	// Synthetic: a user-managed service account names its project in the domain.
	assert.Equal(t, "my-project", serviceAccountProjectFromEmail("drive-reader@my-project.iam.gserviceaccount.com"))
	// Synthetic: the Compute Engine default account carries a project number
	// in its local part, not its domain, so it gives no project.
	assert.Empty(t, serviceAccountProjectFromEmail("123456789-compute@developer.gserviceaccount.com"))
	// Synthetic: a Google-managed service agent lives in a Google project.
	assert.Empty(t, serviceAccountProjectFromEmail("service-123@gcp-sa-discoveryengine.iam.gserviceaccount.com"))
	// Synthetic: a user address and an empty value.
	assert.Empty(t, serviceAccountProjectFromEmail("admin@example.com"))
	assert.Empty(t, serviceAccountProjectFromEmail(""))
}

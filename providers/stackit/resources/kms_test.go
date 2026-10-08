// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestKmsKeyVersionsOfDeletedKey(t *testing.T) {
	// The API answers 404 "key not found" for a deleted key's versions. The
	// short-circuit must answer before any client is built, which is why this
	// resource needs no runtime.
	r := &mqlStackitKmsKey{}
	r.State = plugin.TValue[string]{Data: string(kms.KEYSTATE_DELETED), State: plugin.StateIsSet}
	got, err := r.versions()
	if err != nil {
		t.Fatalf("versions of a deleted key: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("versions of a deleted key = %v, want empty", got)
	}
}

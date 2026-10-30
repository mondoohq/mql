// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	logs "github.com/stackitcloud/stackit-sdk-go/services/logs/v1api"
)

func TestLogsAccessPolicyArgs(t *testing.T) {
	// Synthetic: shape from the logs v1 API model; no target was scanned.
	var p logs.AccessPolicy
	if err := json.Unmarshal([]byte(`{"id": "p-1", "email": "ci@sa.stackit.cloud", "description": "ci shipper", "permissions": ["read", "write"]}`), &p); err != nil {
		t.Fatalf("decoding policy: %v", err)
	}
	args := logsAccessPolicyArgs("l-1", &p)
	if args["__id"].Value != "stackit.logs.accessPolicy/l-1/p-1" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}
	if args["email"].Value != "ci@sa.stackit.cloud" || args["description"].Value != "ci shipper" {
		t.Fatalf("email/description = %v/%v", args["email"].Value, args["description"].Value)
	}
	if perms := args["permissions"].Value.([]any); len(perms) != 2 || perms[0] != "read" || perms[1] != "write" {
		t.Fatalf("permissions = %v", perms)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectRecordDecodesOptionsAllowlist(t *testing.T) {
	const payload = `{
		"id": "prj_1",
		"name": "web",
		"optionsAllowlist": {"paths": [{"value": "/api/webhook"}, {"value": ""}, {"value": "/api/health"}]}
	}`

	var rec projectRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	paths := allowlistPaths(rec.OptionsAllowlist)
	want := []any{"/api/webhook", "/api/health"}
	if len(paths) != len(want) {
		t.Fatalf("allowlistPaths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("allowlistPaths[%d] = %v, want %v", i, paths[i], want[i])
		}
	}
}

// A project with no allowlist must yield an empty list rather than nil, so the
// field reports "no exempt paths" instead of an unset value.
func TestAllowlistPathsAbsentYieldsEmpty(t *testing.T) {
	var rec projectRecord
	if err := json.Unmarshal([]byte(`{"id": "prj_1"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if paths := allowlistPaths(rec.OptionsAllowlist); paths == nil || len(paths) != 0 {
		t.Errorf("allowlistPaths = %v, want empty non-nil slice", paths)
	}
}

// Vercel keys each bypass entry by the bypass secret. The reduction must report
// the count and scopes without ever surfacing a key.
func TestAliasRecordReducesProtectionBypassWithoutLeakingSecrets(t *testing.T) {
	const payload = `{
		"uid": "alias_1",
		"alias": "example.com",
		"deploymentId": "dpl_1",
		"projectId": "prj_1",
		"redirectStatusCode": 308,
		"creator": {"uid": "user_1", "email": "a@b.com", "username": "ab"},
		"protectionBypass": {
			"secret-aaa": {"createdBy": "user_1", "scope": "automation-bypass"},
			"secret-bbb": {"createdBy": "user_2", "scope": "shareable-link"},
			"secret-ccc": {"createdBy": "user_1", "scope": "automation-bypass"}
		}
	}`

	var rec aliasRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := len(rec.ProtectionBypass); got != 3 {
		t.Errorf("protectionBypass count = %d, want 3", got)
	}

	scopes := bypassScopes(rec.ProtectionBypass)
	want := []any{"automation-bypass", "shareable-link"}
	if len(scopes) != len(want) {
		t.Fatalf("bypassScopes = %v, want %v", scopes, want)
	}
	for i := range want {
		if scopes[i] != want[i] {
			t.Errorf("bypassScopes[%d] = %v, want %v", i, scopes[i], want[i])
		}
	}

	for _, s := range scopes {
		if str, _ := s.(string); strings.HasPrefix(str, "secret-") {
			t.Errorf("bypassScopes leaked a bypass secret: %v", s)
		}
	}

	if rec.DeploymentID == nil || *rec.DeploymentID != "dpl_1" {
		t.Error("deploymentId did not decode")
	}
	if rec.RedirectStatusCode == nil || *rec.RedirectStatusCode != 308 {
		t.Error("redirectStatusCode did not decode")
	}
}

func TestBypassScopesAbsentYieldsEmpty(t *testing.T) {
	var rec aliasRecord
	if err := json.Unmarshal([]byte(`{"uid": "alias_1", "alias": "x.vercel.app"}`), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if scopes := bypassScopes(rec.ProtectionBypass); scopes == nil || len(scopes) != 0 {
		t.Errorf("bypassScopes = %v, want empty non-nil slice", scopes)
	}
}

// The detail endpoint keys a deployment by id and the list endpoint by uid.
// newVercelDeployment falls back between them, so both shapes must decode.
func TestDeploymentRecordDecodesBothIdKeys(t *testing.T) {
	var list deploymentRecord
	if err := json.Unmarshal([]byte(`{"uid": "dpl_list", "projectId": "prj_1"}`), &list); err != nil {
		t.Fatalf("decode list shape: %v", err)
	}
	if list.UID != "dpl_list" || list.ProjectID != "prj_1" {
		t.Errorf("list shape decoded as %+v", list)
	}

	var detail deploymentRecord
	if err := json.Unmarshal([]byte(`{"id": "dpl_detail"}`), &detail); err != nil {
		t.Fatalf("decode detail shape: %v", err)
	}
	if detail.ID != "dpl_detail" || detail.UID != "" {
		t.Errorf("detail shape decoded as %+v", detail)
	}
}

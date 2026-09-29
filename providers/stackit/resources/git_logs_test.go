// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	git "github.com/stackitcloud/stackit-sdk-go/services/git/v1betaapi"
	logs "github.com/stackitcloud/stackit-sdk-go/services/logs/v1api"
)

const gitInstanceBase = `"id": "g-1", "name": "code", "url": "https://code.git.onstackit.cloud", "state": "Ready", "version": "v11", "flavor": "git-10", "created": "2026-09-01T10:00:00Z", "acl": ["10.0.0.0/8"], "consumed_disk": "0", "consumed_object_storage": "0"`

func TestGitInstanceArgsFeatureToggles(t *testing.T) {
	var set git.Instance
	if err := json.Unmarshal([]byte(`{`+gitInstanceBase+`, "feature_toggle": {"enable_local_login": false, "enable_commit_signatures": true, "default_email_notifications": "onmention"}}`), &set); err != nil {
		t.Fatalf("decoding instance: %v", err)
	}
	args := gitInstanceArgs(&set)
	if args["localLoginEnabled"].Value != false || args["commitSignaturesEnabled"].Value != true {
		t.Fatalf("toggles = %v/%v", args["localLoginEnabled"].Value, args["commitSignaturesEnabled"].Value)
	}
	if args["defaultEmailNotifications"].Value != "onmention" || args["state"].Value != "Ready" {
		t.Fatalf("notifications/state = %v/%v", args["defaultEmailNotifications"].Value, args["state"].Value)
	}
	if acl := args["acl"].Value.([]any); len(acl) != 1 || acl[0] != "10.0.0.0/8" {
		t.Fatalf("acl = %v", acl)
	}

	var unset git.Instance
	if err := json.Unmarshal([]byte(`{`+gitInstanceBase+`, "feature_toggle": {}}`), &unset); err != nil {
		t.Fatalf("decoding instance: %v", err)
	}
	args = gitInstanceArgs(&unset)
	if args["localLoginEnabled"].Value != nil || args["commitSignaturesEnabled"].Value != nil || args["defaultEmailNotifications"].Value != nil {
		t.Fatalf("unreported toggles should read null, got %v/%v/%v",
			args["localLoginEnabled"].Value, args["commitSignaturesEnabled"].Value, args["defaultEmailNotifications"].Value)
	}
}

func TestGitAuthenticationArgs(t *testing.T) {
	var a git.Authentication
	if err := json.Unmarshal([]byte(`{"id": "a-1", "name": "corp", "provider": "openidConnect", "auto_discover_url": "https://idp.example.com/.well-known/openid-configuration", "client_id": "git-client", "icon_url": "https://idp.example.com/i.png", "scopes": "openid email,profile", "status": "active", "created_at": "2026-09-01T10:00:00Z"}`), &a); err != nil {
		t.Fatalf("decoding authentication: %v", err)
	}
	args := gitAuthenticationArgs("g-1", &a)
	if args["__id"].Value != "stackit.git.authentication/g-1/a-1" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}
	scopes := args["scopes"].Value.([]any)
	if len(scopes) != 3 || scopes[0] != "openid" || scopes[2] != "profile" {
		t.Fatalf("scopes = %v", scopes)
	}
	if args["clientId"].Value != "git-client" || args["provider"].Value != "openidConnect" {
		t.Fatalf("clientId/provider = %v/%v", args["clientId"].Value, args["provider"].Value)
	}
}

func TestLogsAccessTokenArgs(t *testing.T) {
	var tok logs.AccessToken
	if err := json.Unmarshal([]byte(`{"id": "t-1", "displayName": "shipper", "creator": "ops@example.com", "expires": true, "validUntil": "2027-01-01T00:00:00Z", "permissions": ["read", "write"], "status": "active", "accessToken": "tok-SECRET-value"}`), &tok); err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	args := logsAccessTokenArgs("l-1", &tok)
	if argsContain(args, "tok-SECRET-value") {
		t.Fatal("the token value reached the mapped fields")
	}
	if args["__id"].Value != "stackit.logs.accessToken/l-1/t-1" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}
	if p := args["permissions"].Value.([]any); len(p) != 2 || p[1] != "write" {
		t.Fatalf("permissions = %v", p)
	}
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if got, _ := args["validUntil"].Value.(*time.Time); got == nil || !got.Equal(want) {
		t.Fatalf("validUntil = %v", args["validUntil"].Value)
	}

	var forever logs.AccessToken
	if err := json.Unmarshal([]byte(`{"id": "t-2", "displayName": "reader", "creator": "ops@example.com", "expires": false, "permissions": ["read"], "status": "active"}`), &forever); err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	args = logsAccessTokenArgs("l-1", &forever)
	if args["expires"].Value != false || args["validUntil"].Value != nil {
		t.Fatalf("non-expiring token: expires=%v validUntil=%v", args["expires"].Value, args["validUntil"].Value)
	}
}

func TestLogsInstanceArgs(t *testing.T) {
	var inst logs.LogsInstance
	if err := json.Unmarshal([]byte(`{"id": "l-1", "displayName": "app-logs", "created": "2026-09-01T10:00:00Z", "retentionDays": 30, "status": "active", "acl": ["192.0.2.0/24"], "ingestUrl": "https://ingest.example.com"}`), &inst); err != nil {
		t.Fatalf("decoding instance: %v", err)
	}
	args := logsInstanceArgs(&inst)
	if args["name"].Value != "app-logs" || args["retentionDays"].Value != int64(30) || args["ingestUrl"].Value != "https://ingest.example.com" {
		t.Fatalf("name/retention/ingest = %v/%v/%v", args["name"].Value, args["retentionDays"].Value, args["ingestUrl"].Value)
	}
	if args["queryUrl"].Value != "" {
		t.Fatalf("absent queryUrl = %v", args["queryUrl"].Value)
	}
}

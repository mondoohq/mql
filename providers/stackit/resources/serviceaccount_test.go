// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	serviceaccount "github.com/stackitcloud/stackit-sdk-go/services/serviceaccount/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// assertDictSerializable asserts that a []dict payload (a slice of
// map[string]any) round-trips through llx without a conversion error. A `dict`
// value must be a dict-native scalar; a *time.Time or a named string enum makes
// dict2primitive fail, which is exactly the regression the entry helpers guard
// against (the keys/accessTokens fields previously errored on every account
// that had any credentials).
func assertDictSerializable(t *testing.T, entries []any) {
	t.Helper()
	res := llx.ArrayData(entries, types.Dict).Result()
	if res.Error != "" {
		t.Fatalf("[]dict payload failed to serialize: %s", res.Error)
	}
}

func TestServiceAccountKeyEntry(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	k := &serviceaccount.ServiceAccountKeyListResponse{}
	k.SetId("key-1")
	k.SetActive(true)
	k.SetKeyType(serviceaccount.ServiceAccountKeyListResponseKeyType("USER_MANAGED"))
	k.SetKeyAlgorithm(serviceaccount.ServiceAccountKeyListResponseKeyAlgorithm("RSA_2048"))
	k.SetKeyOrigin(serviceaccount.ServiceAccountKeyListResponseKeyOrigin("USER_PROVIDED"))
	k.SetCreatedAt(now)
	// ValidUntil intentionally left unset -> should map to nil.

	entry := serviceAccountKeyEntry(k)

	// The named-string enums must be plain strings, or the []dict field errors
	// at serialization time (a defined string type does not match `case string`).
	if got, ok := entry["keyType"].(string); !ok || got != "USER_MANAGED" {
		t.Fatalf("keyType = %v (%T), want string %q", entry["keyType"], entry["keyType"], "USER_MANAGED")
	}
	if got, ok := entry["keyAlgorithm"].(string); !ok || got != "RSA_2048" {
		t.Fatalf("keyAlgorithm = %v (%T), want string %q", entry["keyAlgorithm"], entry["keyAlgorithm"], "RSA_2048")
	}
	// A timestamp inside a dict must be an RFC3339 string, not a *time.Time.
	if got, ok := entry["createdAt"].(string); !ok || got != now.Format(time.RFC3339) {
		t.Fatalf("createdAt = %v (%T), want RFC3339 %q", entry["createdAt"], entry["createdAt"], now.Format(time.RFC3339))
	}
	if entry["validUntil"] != nil {
		t.Fatalf("validUntil = %v, want nil for an unset time", entry["validUntil"])
	}

	assertDictSerializable(t, []any{entry})
}

func TestServiceAccountKeyArgs(t *testing.T) {
	// Synthetic: a key without expiry and one with; no live account was checked.
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	k := &serviceaccount.ServiceAccountKeyListResponse{}
	k.SetId("key-1")
	k.SetActive(false)
	k.SetKeyType(serviceaccount.SERVICEACCOUNTKEYLISTRESPONSEKEYTYPE_USER_MANAGED)
	k.SetKeyOrigin(serviceaccount.SERVICEACCOUNTKEYLISTRESPONSEKEYORIGIN_GENERATED)
	k.SetKeyAlgorithm(serviceaccount.SERVICEACCOUNTKEYLISTRESPONSEKEYALGORITHM_RSA_4096)
	k.SetCreatedAt(created)

	args := serviceAccountKeyArgs("a@sa.stackit.cloud", k)
	if args["validUntil"].Value != nil {
		t.Fatalf("validUntil = %v, want null for a key without expiry", args["validUntil"].Value)
	}
	if got := args["createdAt"].Value.(*time.Time); !got.Equal(created) {
		t.Fatalf("createdAt = %v, want %v", got, created)
	}
	if args["active"].Value != false || args["keyOrigin"].Value != "GENERATED" || args["keyAlgorithm"].Value != "RSA_4096" {
		t.Fatalf("active/keyOrigin/keyAlgorithm = %v/%v/%v", args["active"].Value, args["keyOrigin"].Value, args["keyAlgorithm"].Value)
	}

	expiry := created.AddDate(1, 0, 0)
	k.SetValidUntil(expiry)
	args = serviceAccountKeyArgs("a@sa.stackit.cloud", k)
	if got := args["validUntil"].Value.(*time.Time); !got.Equal(expiry) {
		t.Fatalf("validUntil = %v, want %v", got, expiry)
	}

	other := serviceAccountKeyArgs("b@sa.stackit.cloud", k)
	if other["__id"].Value == args["__id"].Value {
		t.Fatalf("keys with one id on two accounts share the cache key %v", args["__id"].Value)
	}
}

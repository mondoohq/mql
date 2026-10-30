// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
	"time"

	"github.com/databricks/databricks-sdk-go/service/workspace"
)

func secretValues(t *testing.T, scope string, s workspace.SecretMetadata) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range secretFields(scope, s) {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = v.Value
	}
	return out
}

func TestSecretFields(t *testing.T) {
	// 2026-08-01T00:00:00Z in epoch milliseconds.
	const writtenMs int64 = 1785110400000

	t.Run("a secret maps its scope, key and write time", func(t *testing.T) {
		got := secretValues(t, "prod", workspace.SecretMetadata{
			Key:                  "database-password",
			LastUpdatedTimestamp: writtenMs,
		})

		if got["scopeName"] != "prod" {
			t.Fatalf("scopeName = %v, want prod", got["scopeName"])
		}
		if got["key"] != "database-password" {
			t.Fatalf("key = %v", got["key"])
		}
		written, ok := got["lastUpdated"].(*time.Time)
		if !ok || written == nil || !written.Equal(time.UnixMilli(writtenMs)) {
			t.Fatalf("lastUpdated = %v, want %v", got["lastUpdated"], time.UnixMilli(writtenMs))
		}
	})

	t.Run("an absent write time stays null", func(t *testing.T) {
		got := secretValues(t, "prod", workspace.SecretMetadata{Key: "database-password"})

		// The zero epoch renders as 1 January 1970, which a rotation-age check
		// would read as a real date and treat as very stale rather than as
		// unknown.
		if v := got["lastUpdated"]; v != nil {
			if tv, ok := v.(*time.Time); !ok || tv != nil {
				t.Fatalf("lastUpdated = %v, want null", v)
			}
		}
	})

	// A secret repeats along both the scope and the key. Keying on the key
	// alone would collapse the same key in two scopes onto one resource, and a
	// scope inventory would under-report what it holds.
	t.Run("the same key in two scopes gets two cache keys", func(t *testing.T) {
		a := secretFields("prod", workspace.SecretMetadata{Key: "database-password"})["__id"].Value
		b := secretFields("staging", workspace.SecretMetadata{Key: "database-password"})["__id"].Value
		if a == b {
			t.Fatalf("two scopes collapsed onto one key: %v", a)
		}
	})

	t.Run("two keys in one scope get two cache keys", func(t *testing.T) {
		a := secretFields("prod", workspace.SecretMetadata{Key: "database-password"})["__id"].Value
		b := secretFields("prod", workspace.SecretMetadata{Key: "api-token"})["__id"].Value
		if a == b {
			t.Fatalf("two keys collapsed onto one key: %v", a)
		}
	})

	// The listing endpoint is metadata only, and nothing in the mapping may
	// introduce a field that could hold a value. This pins that: if a future
	// change starts reading a secret's value into the resource, it fails here.
	t.Run("no field can carry a secret value", func(t *testing.T) {
		fields := secretFields("prod", workspace.SecretMetadata{
			Key:                  "database-password",
			LastUpdatedTimestamp: writtenMs,
		})
		allowed := map[string]bool{"__id": true, "scopeName": true, "key": true, "lastUpdated": true}
		for name := range fields {
			if !allowed[name] {
				t.Fatalf("unexpected field %q on a metadata-only secret", name)
			}
			if strings.Contains(strings.ToLower(name), "value") {
				t.Fatalf("field %q names a secret value", name)
			}
		}
	})
}

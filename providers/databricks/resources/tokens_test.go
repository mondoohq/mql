// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/databricks/databricks-sdk-go/service/settings"
)

// timeOf reads a time field back out of the mapped fields, reporting whether it
// carries a value at all. A nil value is what MQL renders as null, and telling
// that apart from a zero time is the point of most of these cases.
func timeOf(t *testing.T, fields map[string]any, key string) (time.Time, bool) {
	t.Helper()
	raw, ok := fields[key]
	if !ok {
		t.Fatalf("field %q missing from the mapping", key)
	}
	if raw == nil {
		return time.Time{}, false
	}
	got, ok := raw.(*time.Time)
	if !ok {
		t.Fatalf("field %q = %T, want *time.Time", key, raw)
	}
	if got == nil {
		return time.Time{}, false
	}
	return *got, true
}

// rawValues drops the llx wrapper so the assertions read against plain Go
// values rather than against RawData internals.
func rawValues(t *testing.T, info settings.TokenInfo) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range tokenFields(info) {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = v.Value
	}
	return out
}

func TestTokenFields(t *testing.T) {
	// 2026-08-01T00:00:00Z and 2027-08-01T00:00:00Z in epoch milliseconds.
	const (
		createdMs  int64 = 1785110400000
		expiresMs  int64 = 1816646400000
		lastUsedMs int64 = 1787788800000
	)

	t.Run("a fully populated token maps every field", func(t *testing.T) {
		got := rawValues(t, settings.TokenInfo{
			TokenId:           "1234abcd",
			Comment:           "ci runner",
			OwnerId:           42,
			CreatedByUsername: "ci@example.com",
			CreationTime:      createdMs,
			ExpiryTime:        expiresMs,
			LastUsedDay:       lastUsedMs,
			Scopes:            []string{"sql", "dashboards.genie"},
		})

		if got["__id"] != "databricks.token/1234abcd" {
			t.Fatalf("__id = %v, want databricks.token/1234abcd", got["__id"])
		}
		if got["id"] != "1234abcd" {
			t.Fatalf("id = %v, want 1234abcd", got["id"])
		}
		if got["comment"] != "ci runner" {
			t.Fatalf("comment = %v, want ci runner", got["comment"])
		}
		if got["ownerId"] != int64(42) {
			t.Fatalf("ownerId = %v, want 42", got["ownerId"])
		}
		if got["createdByUsername"] != "ci@example.com" {
			t.Fatalf("createdByUsername = %v, want ci@example.com", got["createdByUsername"])
		}

		lastUsed, ok := timeOf(t, got, "lastUsedDay")
		if !ok {
			t.Fatal("lastUsedDay is null, want a time")
		}
		if want := time.UnixMilli(lastUsedMs); !lastUsed.Equal(want) {
			t.Fatalf("lastUsedDay = %v, want %v", lastUsed, want)
		}

		scopes, ok := got["scopes"].([]any)
		if !ok {
			t.Fatalf("scopes = %T, want []any", got["scopes"])
		}
		if len(scopes) != 2 || scopes[0] != "sql" || scopes[1] != "dashboards.genie" {
			t.Fatalf("scopes = %v, want [sql dashboards.genie]", scopes)
		}
	})

	// A token that has never been used carries no last_used_day at all. Mapping
	// the missing value to the zero time would report 1 January 1970 as a real
	// last use, and "used before any date you care about" is exactly the answer
	// a stale-credential check would accept.
	t.Run("a token that has never been used reports null", func(t *testing.T) {
		got := rawValues(t, settings.TokenInfo{TokenId: "unused", CreationTime: createdMs})
		if _, ok := timeOf(t, got, "lastUsedDay"); ok {
			t.Fatalf("lastUsedDay = %v, want null", got["lastUsedDay"])
		}
	})

	// A token with no expiry is a standing credential. It has to stay null so a
	// check for an over-long lifetime can tell "never expires" apart from
	// "expired at the epoch".
	t.Run("a token with no expiry reports null", func(t *testing.T) {
		got := rawValues(t, settings.TokenInfo{TokenId: "forever", CreationTime: createdMs})
		if _, ok := timeOf(t, got, "expiryTime"); ok {
			t.Fatalf("expiryTime = %v, want null", got["expiryTime"])
		}
		created, ok := timeOf(t, got, "creationTime")
		if !ok {
			t.Fatal("creationTime is null, want a time")
		}
		if want := time.UnixMilli(createdMs); !created.Equal(want) {
			t.Fatalf("creationTime = %v, want %v", created, want)
		}
	})

	// An unscoped token carries the owner's full authority. It must arrive as an
	// empty list rather than nil, so `scopes.length == 0` is answerable without
	// tripping over a null.
	t.Run("an unscoped token reports an empty list", func(t *testing.T) {
		got := rawValues(t, settings.TokenInfo{TokenId: "unscoped"})
		scopes, ok := got["scopes"].([]any)
		if !ok {
			t.Fatalf("scopes = %T, want []any", got["scopes"])
		}
		if len(scopes) != 0 {
			t.Fatalf("scopes = %v, want empty", scopes)
		}
	})
}

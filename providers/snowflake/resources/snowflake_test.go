// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk/datatypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []any
	}{
		{"empty string", "", []any{}},
		{"whitespace only", "   ", []any{}},
		{"single value", "s3://bucket/", []any{"s3://bucket/"}},
		{"two values", "s3://a/,s3://b/", []any{"s3://a/", "s3://b/"}},
		{"values with spaces", "s3://a/, s3://b/", []any{"s3://a/", "s3://b/"}},
		{"bracket wrapped", "[s3://a/,s3://b/]", []any{"s3://a/", "s3://b/"}},
		{"trailing comma dropped", "s3://a/,", []any{"s3://a/"}},
		{"empty entries dropped", "s3://a/,,s3://b/", []any{"s3://a/", "s3://b/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCommaList(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitCommaList(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSnowflakeSchemaObjectID(t *testing.T) {
	cases := []struct {
		name                     string
		database, schema, object string
		want                     string
	}{
		{"plain parts", "DB", "PUBLIC", "CUSTOMERS", `"DB"."PUBLIC"."CUSTOMERS"`},
		{"lowercase parts", "db", "public", "customers", `"db"."public"."customers"`},
		// Quoting each part is what keeps these two distinct: without it both
		// would render as A.B.C and collide in the resource cache.
		{"dot in object name", "A", "B", "C.D", `"A"."B"."C.D"`},
		{"dot in schema name", "A", "B.C", "D", `"A"."B.C"."D"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := snowflakeSchemaObjectID(tc.database, tc.schema, tc.object)
			if got != tc.want {
				t.Errorf("snowflakeSchemaObjectID(%q, %q, %q) = %q, want %q",
					tc.database, tc.schema, tc.object, got, tc.want)
			}
		})
	}

	// Distinct coordinates must never produce the same cache key.
	if a, b := snowflakeSchemaObjectID("A", "B", "C.D"), snowflakeSchemaObjectID("A", "B.C", "D"); a == b {
		t.Errorf("distinct objects share a cache key: %q", a)
	}
}

func TestSnowflakeTime(t *testing.T) {
	// A nullable timestamp column reaches us as the zero time, because the SDK
	// reads it into a sql.NullTime and only copies through a valid value. It
	// must resolve to null rather than to the year 1.
	t.Run("zero time is null", func(t *testing.T) {
		got := snowflakeTime(time.Time{})
		if got.Type != types.Nil {
			t.Errorf("snowflakeTime(zero) type = %v, want Nil", got.Type)
		}
	})

	t.Run("real time is preserved", func(t *testing.T) {
		want := time.Date(2023, 1, 2, 15, 4, 5, 0, time.UTC)
		got := snowflakeTime(want)
		if got.Type != types.Time {
			t.Fatalf("snowflakeTime(%v) type = %v, want Time", want, got.Type)
		}
		gotTime, ok := got.Value.(*time.Time)
		if !ok {
			t.Fatalf("snowflakeTime(%v) value is %T, want *time.Time", want, got.Value)
		}
		if !gotTime.Equal(want) {
			t.Errorf("snowflakeTime(%v) = %v, want %v", want, gotTime, want)
		}
	})
}

func TestParseSnowflakeTime(t *testing.T) {
	// null cases: empty and unparseable strings must resolve to null, never error.
	nullCases := []struct {
		name string
		in   string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
		{"unrecognized format", "not-a-timestamp"},
		{"date only", "2023-01-02"},
	}
	for _, tc := range nullCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSnowflakeTime(tc.in)
			if got.Type != types.Nil {
				t.Errorf("parseSnowflakeTime(%q) type = %v, want Nil", tc.in, got.Type)
			}
		})
	}

	// valid cases: each supported layout must parse to the same instant.
	want := time.Date(2023, 1, 2, 15, 4, 5, 0, time.FixedZone("", -7*3600))
	validCases := []struct {
		name string
		in   string
	}{
		{"snowflake show format", "2023-01-02 15:04:05.000 -0700"},
		{"snowflake show format nanos", "2023-01-02 15:04:05.000000000 -0700"},
		{"snowflake show format no fraction", "2023-01-02 15:04:05 -0700"},
		{"rfc3339", "2023-01-02T15:04:05-07:00"},
		// The form an authentication policy's created_on takes. The RFC3339
		// layout carries no fractional second, so this only parses because
		// time.Parse accepts one following the seconds field regardless. If
		// that ever stopped holding, the field would go silently null.
		{"rfc3339 with milliseconds", "2023-01-02T15:04:05.000-07:00"},
	}
	t.Run("rfc3339 keeps a non-zero fraction", func(t *testing.T) {
		// Verbatim shape of snowflake.authenticationPolicy.createdAt.
		got := parseSnowflakeTime("2026-08-20T04:38:48.289-07:00")
		gotTime, ok := got.Value.(*time.Time)
		if !ok {
			t.Fatalf("value is %T, want *time.Time", got.Value)
		}
		want := time.Date(2026, 8, 20, 4, 38, 48, 289000000, time.FixedZone("", -7*3600))
		if !gotTime.Equal(want) {
			t.Errorf("got %v, want %v", gotTime, want)
		}
	})

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSnowflakeTime(tc.in)
			if got.Type != types.Time {
				t.Fatalf("parseSnowflakeTime(%q) type = %v, want Time", tc.in, got.Type)
			}
			gotTime, ok := got.Value.(*time.Time)
			if !ok {
				t.Fatalf("parseSnowflakeTime(%q) value is %T, want *time.Time", tc.in, got.Value)
			}
			if !gotTime.Equal(want) {
				t.Errorf("parseSnowflakeTime(%q) = %v, want %v", tc.in, gotTime, want)
			}
		})
	}
}

func TestLegacyDataTypeName(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"VARCHAR", "VARCHAR"},
		{"VARCHAR(16777216)", "VARCHAR"},
		{"STRING", "VARCHAR"},
		{"NUMBER(38,0)", "NUMBER"},
		{"BOOLEAN", "BOOLEAN"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			dt, err := datatypes.ParseDataType(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.want, legacyDataTypeName(dt))
		})
	}

	assert.Equal(t, "", legacyDataTypeName(nil))
}

func TestSnowflakeTimePtr(t *testing.T) {
	assert.Equal(t, types.Nil, snowflakeTimePtr(nil).Type)

	var zero time.Time
	assert.Equal(t, types.Nil, snowflakeTimePtr(&zero).Type)

	ts := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	got := snowflakeTimePtr(&ts)
	assert.Equal(t, types.Time, got.Type)
	assert.Equal(t, &ts, got.Value)
}

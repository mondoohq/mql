// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"reflect"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseQualifiedName(t *testing.T) {
	cases := []struct {
		name                       string
		in                         string
		wantDB, wantSchema, wantOb string
		wantOK                     bool
	}{
		// The SDK renders every part quoted; a DESCRIBE property lists them bare.
		{"quoted", `"DB"."SCH"."RULE"`, "DB", "SCH", "RULE", true},
		{"bare", "DB.SCH.RULE", "DB", "SCH", "RULE", true},
		{"mixed", `DB."SCH".RULE`, "DB", "SCH", "RULE", true},
		{"surrounding space", "  DB.SCH.RULE  ", "DB", "SCH", "RULE", true},
		{"space around parts", `"DB" . "SCH" . "RULE"`, "DB", "SCH", "RULE", true},
		// A quoted identifier may legally contain a dot, which a plain split
		// would turn into a fourth part and reject.
		{"dot inside quotes", `"DB"."SCH"."my.rule"`, "DB", "SCH", "my.rule", true},
		{"dot in database", `"a.b"."SCH"."RULE"`, "a.b", "SCH", "RULE", true},
		{"escaped quote", `"DB"."SCH"."ru""le"`, "DB", "SCH", `ru"le`, true},
		{"lower case preserved", `"db"."sch"."rule"`, "db", "sch", "rule", true},

		{"empty", "", "", "", "", false},
		{"blank", "   ", "", "", "", false},
		{"one part", "RULE", "", "", "", false},
		{"two parts", "SCH.RULE", "", "", "", false},
		{"four parts", "A.B.C.D", "", "", "", false},
		{"empty middle part", "DB..RULE", "", "", "", false},
		{"unterminated quote", `"DB"."SCH"."RULE`, "", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, schema, object, ok := parseQualifiedName(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseQualifiedName(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if db != tc.wantDB || schema != tc.wantSchema || object != tc.wantOb {
				t.Errorf("parseQualifiedName(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tc.in, db, schema, object, tc.wantDB, tc.wantSchema, tc.wantOb)
			}
		})
	}
}

// TestQualifiedNameKeyMatchesResourceID pins the join the reference resolution
// depends on: the key built from a reported name has to be the same string the
// target resource carries as its cache key, or every reference silently
// resolves to nothing.
func TestQualifiedNameKeyMatchesResourceID(t *testing.T) {
	want := snowflakeSchemaObjectID("DB", "SCH", "RULE")

	for _, in := range []string{`"DB"."SCH"."RULE"`, "DB.SCH.RULE", `DB."SCH".RULE`} {
		got, ok := qualifiedNameKey(in)
		if !ok {
			t.Fatalf("qualifiedNameKey(%q) reported not ok", in)
		}
		if got != want {
			t.Errorf("qualifiedNameKey(%q) = %q, want %q", in, got, want)
		}
	}

	if _, ok := qualifiedNameKey("RULE"); ok {
		t.Error("qualifiedNameKey accepted a bare name")
	}
}

func TestPolicyEntityKey(t *testing.T) {
	cases := map[string]string{
		"ALICE":     "ALICE",
		"alice":     "ALICE",
		`"alice"`:   "ALICE",
		"  alice  ": "ALICE",
		"":          "",
	}
	for in, want := range cases {
		if got := policyEntityKey(in); got != want {
			t.Errorf("policyEntityKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRefsFromNameList covers the three states a resolved reference list can be
// in. The one that matters is the middle: a source list that could not be read,
// and a target listing that could not be read, both have to leave the resolved
// list null. An empty list is the claim that the object references nothing, and
// an assertion such as
// `allowedNetworkRuleRefs.none(valueList.contains("0.0.0.0/0"))` passes on it.
func TestRefsFromNameList(t *testing.T) {
	resolved := []any{"a", "b"}

	t.Run("resolves a readable source", func(t *testing.T) {
		source := plugin.TValue[[]any]{Data: []any{"DB.SCH.A", "DB.SCH.B"}, State: plugin.StateIsSet}
		field := plugin.TValue[[]any]{}
		got, err := refsFromNameList(&source, &field, func([]any) ([]any, error) { return resolved, nil })
		if err != nil {
			t.Fatalf("refsFromNameList returned %v", err)
		}
		if !reflect.DeepEqual(got, resolved) {
			t.Errorf("value = %#v, want %#v", got, resolved)
		}
		if field.State&plugin.StateIsNull != 0 {
			t.Error("a resolved list was marked null")
		}
	})

	t.Run("a null source list stays null", func(t *testing.T) {
		source := plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		field := plugin.TValue[[]any]{}
		got, err := refsFromNameList(&source, &field, func([]any) ([]any, error) {
			t.Fatal("the resolver ran against a source list that was never read")
			return nil, nil
		})
		if err != nil || got != nil {
			t.Fatalf("value = (%#v, %v), want (nil, nil)", got, err)
		}
		if field.State&plugin.StateIsNull == 0 {
			t.Error("a null source produced an empty list rather than null")
		}
	})

	t.Run("an unreadable target listing is null, not empty", func(t *testing.T) {
		source := plugin.TValue[[]any]{Data: []any{"DB.SCH.A"}, State: plugin.StateIsSet}
		field := plugin.TValue[[]any]{}
		got, err := refsFromNameList(&source, &field, func([]any) ([]any, error) {
			return nil, errRefListingUnavailable
		})
		if err != nil || got != nil {
			t.Fatalf("value = (%#v, %v), want (nil, nil)", got, err)
		}
		if field.State&plugin.StateIsNull == 0 {
			t.Error("a listing the role cannot read produced an empty list rather than null")
		}
	})

	t.Run("a source error propagates", func(t *testing.T) {
		source := plugin.TValue[[]any]{Error: errors.New("connection reset"), State: plugin.StateIsSet}
		field := plugin.TValue[[]any]{}
		if _, err := refsFromNameList(&source, &field, func([]any) ([]any, error) { return resolved, nil }); err == nil {
			t.Error("a transport failure on the source list was swallowed")
		}
	})

	t.Run("an empty source resolves to an empty list", func(t *testing.T) {
		source := plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		field := plugin.TValue[[]any]{}
		got, err := refsFromNameList(&source, &field, func(names []any) ([]any, error) {
			return resolveObjectRefs[*mqlSnowflakeNetworkRule](nil, names, "network rule", nil)
		})
		if err != nil {
			t.Fatalf("refsFromNameList returned %v", err)
		}
		if !reflect.DeepEqual(got, []any{}) {
			t.Errorf("value = %#v, want an empty list", got)
		}
	})
}

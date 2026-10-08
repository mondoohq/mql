// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/stackitcloud/stackit-sdk-go/core/oapierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestTimeOrNil(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		in   time.Time
		ok   bool
		want *time.Time
	}{
		{"ok=false", now, false, nil},
		{"ok=true zero time", time.Time{}, true, nil},
		{"ok=true real time", now, true, &now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := timeOrNil(tc.in, tc.ok)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("expected nil, got %v", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("expected %v, got nil", *tc.want)
			case tc.want != nil && got != nil && !tc.want.Equal(*got):
				t.Fatalf("expected %v, got %v", *tc.want, *got)
			}
		})
	}
}

func TestRfc3339OrNil(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		in   time.Time
		ok   bool
		want any
	}{
		{"ok=false", now, false, nil},
		{"ok=true zero time", time.Time{}, true, nil},
		{"ok=true real time", now, true, now.Format(time.RFC3339)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rfc3339OrNil(tc.in, tc.ok); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseDnsTime(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantNil bool
		wantStr string
	}{
		{"empty", "", true, ""},
		{"malformed", "not-a-date", true, ""},
		{"valid RFC3339", "2026-05-12T14:49:23Z", false, "2026-05-12T14:49:23Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDnsTime(tc.in)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s, got nil", tc.wantStr)
			}
			if got.Format(time.RFC3339) != tc.wantStr {
				t.Fatalf("expected %s, got %s", tc.wantStr, got.Format(time.RFC3339))
			}
		})
	}
}

func TestParseRFC3339(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantNil bool
		wantStr string
	}{
		{"empty", "", true, ""},
		{"malformed", "not-a-date", true, ""},
		{"valid RFC3339", "2027-11-30T23:59:59Z", false, "2027-11-30T23:59:59Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRFC3339(tc.in)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %s, got nil", tc.wantStr)
			}
			if got.Format(time.RFC3339) != tc.wantStr {
				t.Fatalf("expected %s, got %s", tc.wantStr, got.Format(time.RFC3339))
			}
		})
	}
}

func TestParseKeyBitSize(t *testing.T) {
	i := func(n int64) *int64 { return &n }
	cases := []struct {
		name string
		in   string
		want *int64
	}{
		{"empty", "", nil},
		{"rsa", "RSA 2048", i(2048)},
		{"rsa 4096", "RSA 4096", i(4096)},
		{"ecdsa curve", "ECDSA P-256", nil},
		{"ed25519", "Ed25519", nil},
		{"bare number", "3072", i(3072)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseKeyBitSize(tc.in)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("expected nil, got %d", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("expected %d, got nil", *tc.want)
			case tc.want != nil && got != nil && *tc.want != *got:
				t.Fatalf("expected %d, got %d", *tc.want, *got)
			}
		})
	}
}

func TestIsAccessDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("connection refused"), false},
		{"401 oapierror", &oapierror.GenericOpenAPIError{StatusCode: 401}, true},
		{"403 oapierror", &oapierror.GenericOpenAPIError{StatusCode: 403}, true},
		{"404 oapierror", &oapierror.GenericOpenAPIError{StatusCode: 404}, false},
		{"500 oapierror", &oapierror.GenericOpenAPIError{StatusCode: 500}, false},
		{"text 401", errors.New("got status 401 Unauthorized"), true},
		{"text 403", errors.New("status 403 forbidden"), true},
		{"text 404", errors.New("status 404 not found"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAccessDenied(tc.err); got != tc.want {
				t.Fatalf("isAccessDenied(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestLabelData(t *testing.T) {
	// STACKIT label maps come back as either map[string]string (resourcemanager,
	// some SDK modules) or map[string]interface{} (iaas) via GetLabels(); both
	// must round-trip to the same map[string]any. The SDK getters always
	// dereference, so labelData is only called with unwrapped maps.
	wantOne := map[string]any{"env": "prod", "tier": "frontend"}
	wantEmpty := map[string]any{}

	cases := []struct {
		name string
		in   any
		want map[string]any
	}{
		{"nil", nil, wantEmpty},
		{"empty string map", map[string]string{}, wantEmpty},
		{"string map", map[string]string{"env": "prod", "tier": "frontend"}, wantOne},
		{"any map (string values)", map[string]interface{}{"env": "prod", "tier": "frontend"}, wantOne},
		{"any map drops non-strings", map[string]interface{}{"env": "prod", "n": 7}, map[string]any{"env": "prod"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rd := labelData(tc.in)
			got, ok := rd.Value.(map[string]any)
			if !ok {
				t.Fatalf("expected map[string]any value, got %T", rd.Value)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d entries, got %d (%v)", len(tc.want), len(got), got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("key %q: expected %v, got %v", k, v, got[k])
				}
			}
		})
	}
}

func TestDictAny(t *testing.T) {
	in := map[string]interface{}{
		"a": "x",
		"b": []interface{}{"y", 1.0},
		"c": map[string]interface{}{"d": true},
	}
	out := dictAny(in)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", out)
	}
	if m["a"] != "x" {
		t.Fatalf("a: got %v", m["a"])
	}
	if arr, ok := m["b"].([]any); !ok || len(arr) != 2 || arr[0] != "y" || arr[1] != 1.0 {
		t.Fatalf("b: got %v (%T)", m["b"], m["b"])
	}
	if nested, ok := m["c"].(map[string]any); !ok || nested["d"] != true {
		t.Fatalf("c: got %v (%T)", m["c"], m["c"])
	}
}

func TestToDictRoundTrip(t *testing.T) {
	type sub struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	in := sub{Name: "foo", Tags: []string{"a", "b"}}
	out := toDict(in)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", out)
	}
	if m["name"] != "foo" {
		t.Fatalf("name: got %v", m["name"])
	}
	if arr, ok := m["tags"].([]any); !ok || len(arr) != 2 || arr[0] != "a" || arr[1] != "b" {
		t.Fatalf("tags: got %v", m["tags"])
	}
}

func TestIdArg(t *testing.T) {
	cases := []struct {
		name    string
		args    map[string]*llx.RawData
		key     string
		wantStr string
		wantOk  bool
	}{
		{"missing", map[string]*llx.RawData{}, "id", "", false},
		{"nil entry", map[string]*llx.RawData{"id": nil}, "id", "", false},
		{"empty string", map[string]*llx.RawData{"id": llx.StringData("")}, "id", "", false},
		{"wrong type", map[string]*llx.RawData{"id": llx.IntData(1)}, "id", "", false},
		{"set", map[string]*llx.RawData{"id": llx.StringData("abc")}, "id", "abc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := idArg(tc.args, tc.key)
			if got != tc.wantStr || ok != tc.wantOk {
				t.Fatalf("got (%q, %v), want (%q, %v)", got, ok, tc.wantStr, tc.wantOk)
			}
		})
	}
}

func TestStrSlice(t *testing.T) {
	if got := strSlice(nil); len(got) != 0 {
		t.Fatalf("nil input: expected empty slice, got %#v", got)
	}
	got := strSlice([]string{"a", "b"})
	want := []any{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestStringMap(t *testing.T) {
	if got := stringMap(nil); len(got) != 0 {
		t.Fatalf("nil input: expected empty map, got %#v", got)
	}
	got := stringMap(map[string]string{"k": "v"})
	want := map[string]any{"k": "v"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestPtrStr(t *testing.T) {
	if got := ptrStr[*string](nil); got != "" {
		t.Fatalf("nil pointer: expected empty string, got %q", got)
	}
	s := "value"
	if got := ptrStr(&s); got != "value" {
		t.Fatalf("got %q, want %q", got, "value")
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed 404", &oapierror.GenericOpenAPIError{StatusCode: 404}, true},
		{"typed 403", &oapierror.GenericOpenAPIError{StatusCode: 403}, false},
		{"string 404", errors.New("request failed with status 404"), true},
		{"unrelated", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStrOrNil(t *testing.T) {
	version := "7.2.4"

	t.Run("value form: absent stays null", func(t *testing.T) {
		if got := strOrNil("", false); got != nil {
			t.Fatalf("strOrNil(\"\", false) = %q, want null", *got)
		}
	})
	t.Run("value form: present", func(t *testing.T) {
		got := strOrNil(version, true)
		if got == nil || *got != version {
			t.Fatalf("strOrNil(%q, true) = %v, want %q", version, got, version)
		}
	})
	t.Run("pointer form: absent stays null", func(t *testing.T) {
		if got := strOrNil((*string)(nil), false); got != nil {
			t.Fatalf("strOrNil(nil, false) = %q, want null", *got)
		}
	})
	t.Run("pointer form: present", func(t *testing.T) {
		got := strOrNil(&version, true)
		if got == nil || *got != version {
			t.Fatalf("strOrNil(&%q, true) = %v, want %q", version, got, version)
		}
	})
	t.Run("an empty string the API did report is not the same as an absent one", func(t *testing.T) {
		got := strOrNil("", true)
		if got == nil {
			t.Fatal("strOrNil(\"\", true) = null, want a reported empty string")
		}
		if *got != "" {
			t.Fatalf("strOrNil(\"\", true) = %q, want %q", *got, "")
		}
	})
}

func TestDeniedList(t *testing.T) {
	denied := &oapierror.GenericOpenAPIError{StatusCode: http.StatusForbidden}

	// Structured errors off: the v13 answer, an empty list and no error.
	list, err := deniedList(denied)
	require.NoError(t, err)
	assert.Equal(t, []any{}, list)

	// Structured errors on: the refusal is the answer, classified, so a
	// missing permission does not read as an empty project.
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	t.Cleanup(func() { plugin.ReadFeatures(nil) })
	list, err = deniedList(denied)
	assert.Nil(t, list)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

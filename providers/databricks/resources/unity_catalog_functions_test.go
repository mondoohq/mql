// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/catalog"
)

// fieldValues drops the llx wrapper so the assertions read against plain Go
// values rather than against RawData internals.
func fieldValues(t *testing.T, fields map[string]any) map[string]any {
	t.Helper()
	return fields
}

func functionValues(t *testing.T, f catalog.FunctionInfo) map[string]any {
	t.Helper()
	out := map[string]any{}
	for k, v := range functionFields(f) {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = v.Value
	}
	return fieldValues(t, out)
}

// A Unity Catalog name is three-level, so the same function name legitimately
// exists in two schemas, and Unity Catalog also allows overloads that share a
// fully qualified name. A cache key that misses either dimension makes
// CreateResource return the first instance for both, and a DEFINER function
// disappears behind an INVOKER one that happens to be listed first.
func TestFunctionCacheKey(t *testing.T) {
	tests := []struct {
		name string
		in   catalog.FunctionInfo
		want string
	}{
		{
			name: "full name and id",
			in:   catalog.FunctionInfo{FullName: "main.sales.mask", FunctionId: "fn-1"},
			want: "databricks.function/main.sales.mask/fn-1",
		},
		{
			name: "no id falls back to the full name",
			in:   catalog.FunctionInfo{FullName: "main.sales.mask"},
			want: "databricks.function/main.sales.mask",
		},
		{
			name: "no full name is rebuilt from its three levels",
			in:   catalog.FunctionInfo{CatalogName: "main", SchemaName: "sales", Name: "mask"},
			want: "databricks.function/main.sales.mask",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := functionCacheKey(tc.in); got != tc.want {
				t.Fatalf("functionCacheKey() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("the same name in two schemas gets two keys", func(t *testing.T) {
		a := functionCacheKey(catalog.FunctionInfo{
			CatalogName: "main", SchemaName: "sales", Name: "mask", FullName: "main.sales.mask",
		})
		b := functionCacheKey(catalog.FunctionInfo{
			CatalogName: "main", SchemaName: "hr", Name: "mask", FullName: "main.hr.mask",
		})
		if a == b {
			t.Fatalf("two schemas collapsed onto one key: %q", a)
		}
	})

	t.Run("overloads sharing a full name get two keys", func(t *testing.T) {
		a := functionCacheKey(catalog.FunctionInfo{FullName: "main.sales.mask", FunctionId: "fn-1"})
		b := functionCacheKey(catalog.FunctionInfo{FullName: "main.sales.mask", FunctionId: "fn-2"})
		if a == b {
			t.Fatalf("two overloads collapsed onto one key: %q", a)
		}
	})

	t.Run("the same catalog name in two catalogs gets two keys", func(t *testing.T) {
		a := functionCacheKey(catalog.FunctionInfo{FullName: "prod.sales.mask"})
		b := functionCacheKey(catalog.FunctionInfo{FullName: "dev.sales.mask"})
		if a == b {
			t.Fatalf("two catalogs collapsed onto one key: %q", a)
		}
	})
}

func TestFunctionFields(t *testing.T) {
	// 2026-08-01T00:00:00Z and 2026-08-02T00:00:00Z in epoch milliseconds.
	const (
		createdMs int64 = 1785110400000
		updatedMs int64 = 1785196800000
	)

	t.Run("a DEFINER function reports its security type verbatim", func(t *testing.T) {
		got := functionValues(t, catalog.FunctionInfo{
			FunctionId:      "fn-1",
			Name:            "mask_ssn",
			FullName:        "main.sales.mask_ssn",
			CatalogName:     "main",
			SchemaName:      "sales",
			Owner:           "owner@example.com",
			Comment:         "masks a national id",
			SecurityType:    catalog.FunctionInfoSecurityTypeDefiner,
			RoutineBody:     catalog.FunctionInfoRoutineBodySql,
			SqlDataAccess:   catalog.FunctionInfoSqlDataAccessReadsSqlData,
			SqlPath:         "main.sales",
			IsDeterministic: true,
			IsNullCall:      true,
			DataType:        catalog.ColumnTypeNameString,
			FullDataType:    "STRING",
			ParameterStyle:  catalog.FunctionInfoParameterStyleS,
			MetastoreId:     "ms-1",
			BrowseOnly:      false,
			CreatedAt:       createdMs,
			CreatedBy:       "owner@example.com",
			UpdatedAt:       updatedMs,
			UpdatedBy:       "editor@example.com",
		})

		// DEFINER is the whole finding: a caller holding only EXECUTE runs the
		// body with the owner's privileges. If this ever decodes to anything
		// else the escalation primitive becomes invisible.
		if got["securityType"] != "DEFINER" {
			t.Fatalf("securityType = %v, want DEFINER", got["securityType"])
		}
		if got["owner"] != "owner@example.com" {
			t.Fatalf("owner = %v", got["owner"])
		}
		if got["routineBody"] != "SQL" {
			t.Fatalf("routineBody = %v, want SQL", got["routineBody"])
		}
		if got["sqlDataAccess"] != "READS_SQL_DATA" {
			t.Fatalf("sqlDataAccess = %v, want READS_SQL_DATA", got["sqlDataAccess"])
		}
		if got["isDeterministic"] != true || got["isNullCall"] != true {
			t.Fatalf("isDeterministic = %v, isNullCall = %v", got["isDeterministic"], got["isNullCall"])
		}
		if got["fullName"] != "main.sales.mask_ssn" {
			t.Fatalf("fullName = %v", got["fullName"])
		}
		if got["catalogName"] != "main" || got["schemaName"] != "sales" {
			t.Fatalf("catalogName = %v, schemaName = %v", got["catalogName"], got["schemaName"])
		}

		created, ok := got["createdAt"].(*time.Time)
		if !ok || created == nil || !created.Equal(time.UnixMilli(createdMs)) {
			t.Fatalf("createdAt = %v, want %v", got["createdAt"], time.UnixMilli(createdMs))
		}
	})

	// DEFINER is the only security type the API reports today. A value the SDK
	// enum does not know must still pass through verbatim rather than being
	// normalized away, so a future INVOKER is not silently read as DEFINER.
	t.Run("an unknown security type passes through verbatim", func(t *testing.T) {
		got := functionValues(t, catalog.FunctionInfo{
			FullName:     "main.sales.plain",
			SecurityType: catalog.FunctionInfoSecurityType("INVOKER"),
		})
		if got["securityType"] != "INVOKER" {
			t.Fatalf("securityType = %v, want INVOKER", got["securityType"])
		}
	})

	t.Run("an unreported security type is an empty string", func(t *testing.T) {
		got := functionValues(t, catalog.FunctionInfo{FullName: "main.sales.plain"})
		if got["securityType"] != "" {
			t.Fatalf("securityType = %v, want an empty string", got["securityType"])
		}
	})

	t.Run("absent timestamps stay null", func(t *testing.T) {
		got := functionValues(t, catalog.FunctionInfo{FullName: "main.sales.plain"})

		// The zero epoch would render as 1 January 1970 and a zero time.Time as
		// the year 1, either of which reads as a real date a query can compare.
		if v := got["createdAt"]; v != nil {
			if tv, ok := v.(*time.Time); !ok || tv != nil {
				t.Fatalf("createdAt = %v, want null", v)
			}
		}
		if v := got["updatedAt"]; v != nil {
			if tv, ok := v.(*time.Time); !ok || tv != nil {
				t.Fatalf("updatedAt = %v, want null", v)
			}
		}
	})

	// The function body is author-controlled text that routinely carries
	// credentials inline. It must never appear among the mapped fields.
	t.Run("the routine definition is never mapped", func(t *testing.T) {
		fields := functionFields(catalog.FunctionInfo{
			FullName:          "main.sales.mask_ssn",
			RoutineDefinition: "SELECT 'zero-entropy-fixture-value'",
			ExternalName:      "mask_ssn",
		})
		for k, v := range fields {
			if strings.Contains(strings.ToLower(k), "definition") {
				t.Fatalf("field %q exposes the routine definition", k)
			}
			if s, ok := v.Value.(string); ok && strings.Contains(s, "zero-entropy-fixture-value") {
				t.Fatalf("field %q carries the routine definition body", k)
			}
		}
	})
}

// testWorkspaceClient builds a workspace client pointed at a local test server
// that serves one API path. The token is a fixed placeholder: personal access
// token auth sends it as a bearer header and makes no call of its own. Any
// path other than the one under test answers 404, so the client's own host
// metadata probe cannot be mistaken for a call the code under test made.
func testWorkspaceClient(t *testing.T, path string, handler http.HandlerFunc) *databricks.WorkspaceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error_code":"NOT_FOUND","message":"no handler"}`, http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ws, err := databricks.NewWorkspaceClient(&databricks.Config{
		Host:  srv.URL,
		Token: "placeholder-token",
	})
	if err != nil {
		t.Fatalf("NewWorkspaceClient() error = %v", err)
	}
	return ws
}

// functionsPath is the Unity Catalog functions listing endpoint.
const functionsPath = "/api/2.1/unity-catalog/functions"

func TestListFunctionsPagination(t *testing.T) {
	t.Run("walks every page and stops when the token is absent", func(t *testing.T) {
		var calls int
		ws := testWorkspaceClient(t, functionsPath, func(w http.ResponseWriter, r *http.Request) {
			calls++
			token := r.URL.Query().Get("page_token")
			resp := catalog.ListFunctionsResponse{}
			switch token {
			case "":
				resp.Functions = []catalog.FunctionInfo{{FullName: "main.sales.a"}}
				resp.NextPageToken = "p2"
			case "p2":
				// A page may be empty while still carrying a token. Treating an
				// empty page as the end would drop everything after it.
				resp.NextPageToken = "p3"
			case "p3":
				resp.Functions = []catalog.FunctionInfo{{FullName: "main.sales.b"}}
			default:
				t.Errorf("unexpected page token %q", token)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})

		got, err := listFunctions(context.Background(), ws, "main", "sales")
		if err != nil {
			t.Fatalf("listFunctions() error = %v", err)
		}
		if calls != 3 {
			t.Fatalf("made %d requests, want 3", calls)
		}
		if len(got) != 2 || got[0].FullName != "main.sales.a" || got[1].FullName != "main.sales.b" {
			t.Fatalf("listFunctions() = %v, want the functions from pages 1 and 3", got)
		}
	})

	t.Run("a cursor that never advances is reported, not walked forever", func(t *testing.T) {
		ws := testWorkspaceClient(t, functionsPath, func(w http.ResponseWriter, r *http.Request) {
			// An endpoint that ignores its own cursor. The SDK's iterator stops
			// only on an absent token, so without the guard this never returns.
			resp := catalog.ListFunctionsResponse{
				Functions:     make([]catalog.FunctionInfo, 25000),
				NextPageToken: "always-the-same",
			}
			for i := range resp.Functions {
				resp.Functions[i].FullName = fmt.Sprintf("main.sales.f%d", i)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})

		_, err := listFunctions(context.Background(), ws, "main", "sales")
		if err == nil {
			t.Fatal("listFunctions() returned no error on a stuck cursor")
		}
		if !strings.Contains(err.Error(), "not advancing") {
			t.Fatalf("listFunctions() error = %v, want it to name the stuck cursor", err)
		}
	})

	t.Run("an empty schema is an empty list, not an error", func(t *testing.T) {
		ws := testWorkspaceClient(t, functionsPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(catalog.ListFunctionsResponse{})
		})

		got, err := listFunctions(context.Background(), ws, "main", "sales")
		if err != nil {
			t.Fatalf("listFunctions() error = %v", err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("listFunctions() = %v, want an empty list", got)
		}
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testConn wires a RipplingConnection at a test server, bypassing OAuth.
func testConn(t *testing.T, h http.Handler) (*RipplingConnection, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := &RipplingConnection{
		apiBase:    srv.URL,
		httpClient: srv.Client(),
	}
	return c, srv.Close
}

// pageServer serves `total` synthetic employees over limit/offset paging.
// shortAt, when >= 0, makes the page starting at that offset come back
// shorter than pageSize while more records still follow.
func pageServer(total, shortAt int, hits *int32, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits++
		mu.Unlock()
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit == 0 {
			limit = pageSize
		}
		if offset == shortAt {
			limit = 3
		}
		// Written as raw JSON rather than marshaled structs: the date and
		// time wrappers decode Rippling's wire formats and have no matching
		// marshaler, so a struct round-trip would not represent the API.
		ids := []string{}
		for i := offset; i < offset+limit && i < total; i++ {
			ids = append(ids, `{"id":"emp-`+strconv.Itoa(i)+`"}`)
		}
		fmt.Fprint(w, "["+strings.Join(ids, ",")+"]")
	}
}

func TestGetPaginatedWalksEveryPage(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	c, closeFn := testConn(t, pageServer(250, -1, &hits, &mu))
	defer closeFn()

	got, err := getPaginated[Employee](context.Background(), c, "/platform/api/employees")
	if err != nil {
		t.Fatalf("getPaginated: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("got %d employees, want 250", len(got))
	}
	if got[0].ID != "emp-0" || got[249].ID != "emp-249" {
		t.Fatalf("unexpected boundaries: %q .. %q", got[0].ID, got[249].ID)
	}
	// 100 + 100 + 50 + one empty page to confirm the end.
	if hits != 4 {
		t.Fatalf("made %d requests, want 4", hits)
	}
}

// TestGetPaginatedShortPageMidStream is the regression test for the walk
// that stopped on the first page shorter than pageSize. The server hands
// back 3 records at offset 100 while 250 exist; the old
// `added < pageSize` termination silently returned 103 of them.
func TestGetPaginatedShortPageMidStream(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	c, closeFn := testConn(t, pageServer(250, 100, &hits, &mu))
	defer closeFn()

	got, err := getPaginated[Employee](context.Background(), c, "/platform/api/employees")
	if err != nil {
		t.Fatalf("getPaginated: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("got %d employees, want all 250", len(got))
	}
	if got[249].ID != "emp-249" {
		t.Fatalf("last record is %q, want emp-249", got[249].ID)
	}
}

// TestGetPaginatedStuckOffset covers an endpoint that ignores `offset` and
// keeps returning a full page. Without the page cap this loops forever.
func TestGetPaginatedStuckOffset(t *testing.T) {
	c, closeFn := testConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids := make([]string, pageSize)
		for i := range ids {
			ids[i] = `{"id":"stuck"}`
		}
		fmt.Fprint(w, "["+strings.Join(ids, ",")+"]")
	}))
	defer closeFn()

	_, err := getPaginated[Employee](context.Background(), c, "/platform/api/employees")
	if err == nil {
		t.Fatal("expected an error when the endpoint ignores offset, got nil")
	}
	if !strings.Contains(err.Error(), "ignoring the offset") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetPaginatedPropagatesHTTPError(t *testing.T) {
	c, closeFn := testConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"insufficient scope"}`)
	}))
	defer closeFn()

	got, err := getPaginated[Group](context.Background(), c, "/platform/api/groups")
	if err == nil {
		t.Fatal("a 403 must surface as an error, not an empty list")
	}
	if got != nil {
		t.Fatalf("got %v records alongside the error, want nil", len(got))
	}
}

// TestListsAreMemoized pins the fix for the per-row re-walk: every typed
// cross-reference resolves through these lists, so they must be fetched
// once per connection.
func TestListsAreMemoized(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	c, closeFn := testConn(t, pageServer(5, -1, &hits, &mu))
	defer closeFn()

	if _, err := c.ListEmployees(context.Background()); err != nil {
		t.Fatalf("ListEmployees: %v", err)
	}
	mu.Lock()
	afterFirst := hits
	mu.Unlock()

	for i := 0; i < 10; i++ {
		got, err := c.ListEmployees(context.Background())
		if err != nil {
			t.Fatalf("ListEmployees: %v", err)
		}
		if len(got) != 5 {
			t.Fatalf("call %d returned %d employees, want 5", i, len(got))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != afterFirst {
		t.Fatalf("10 further ListEmployees calls made %d extra requests, want 0", hits-afterFirst)
	}
}

// TestMemoizedErrorIsNotAnEmptyList makes sure a failed read keeps failing
// rather than degrading into "this company has none".
func TestMemoizedErrorIsNotAnEmptyList(t *testing.T) {
	c, closeFn := testConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer closeFn()

	for i := 0; i < 3; i++ {
		got, err := c.ListDepartments(context.Background())
		if err == nil {
			t.Fatalf("call %d: expected the error to persist, got %d records", i, len(got))
		}
	}
}

func TestEmployeeDecode(t *testing.T) {
	// Shaped like the documented /platform/api/employees record. The
	// roleState -> RoleStatus tag is the one a rename would silently blank.
	body := []byte(`[{
		"id": "emp-1",
		"employeeNumber": 42,
		"firstName": "Ada",
		"lastName": "Lovelace",
		"workEmail": "ada@example.com",
		"title": "Engineer",
		"employmentType": "FULL_TIME",
		"roleState": "TERMINATED",
		"startDate": "2020-03-01",
		"terminationDate": "2024-06-30",
		"terminationType": "VOLUNTARY",
		"createdAt": "2020-02-25T09:00:00Z",
		"manager": "emp-9",
		"department": "dept-1",
		"team": "team-1",
		"workLocation": "loc-1"
	}]`)

	var out []Employee
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	e := out[0]
	if e.RoleStatus != "TERMINATED" {
		t.Errorf("RoleStatus = %q, want TERMINATED (json tag is roleState, not roleStatus)", e.RoleStatus)
	}
	if e.EmployeeNumber != 42 {
		t.Errorf("EmployeeNumber = %d, want 42", e.EmployeeNumber)
	}
	if e.Manager != "emp-9" || e.Department != "dept-1" || e.Team != "team-1" || e.WorkLocation != "loc-1" {
		t.Errorf("cross-reference ids decoded wrong: %+v", e)
	}
	if want := time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC); !e.StartDate.Time.Equal(want) {
		t.Errorf("StartDate = %v, want %v", e.StartDate.Time, want)
	}
	if !e.EndDate.Time.IsZero() {
		t.Errorf("absent endDate must stay the zero time, got %v", e.EndDate.Time)
	}
}

// TestEmployeeDoesNotDecodePersonalContactFields guards the scope boundary:
// the provider models identity and org structure, not personal PII.
func TestEmployeeDoesNotDecodePersonalContactFields(t *testing.T) {
	for _, field := range []string{"PersonalEmail", "SSN", "SocialSecurityNumber", "HomeAddress", "Compensation", "Salary", "BankAccount"} {
		if hasJSONField(Employee{}, field) {
			t.Errorf("connection.Employee must not carry %s", field)
		}
	}
	if hasJSONField(Company{}, "Tin") {
		t.Error("connection.Company must not carry Tin (employer tax identification number)")
	}
}

func TestCompanyDecode(t *testing.T) {
	body := []byte(`[{
		"id": "co-1",
		"name": "Example",
		"legalName": "Example, Inc.",
		"primaryEmail": "it@example.com",
		"needsOnboarding": true,
		"createdAt": "2019-01-02T03:04:05Z",
		"address": {"streetLine1": "1 Main St", "city": "Springfield", "state": "IL", "zip": "62701", "country": "US"}
	}]`)
	var out []Company
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := out[0]
	if !c.NeedsOnboard {
		t.Error("NeedsOnboard = false, want true (json tag is needsOnboarding)")
	}
	if c.Address == nil || c.Address.City != "Springfield" {
		t.Errorf("nested address decoded wrong: %+v", c.Address)
	}
}

func TestCompanyDecodeWithoutAddress(t *testing.T) {
	var out []Company
	if err := json.Unmarshal([]byte(`[{"id":"co-1","name":"Example"}]`), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out[0].Address != nil {
		t.Errorf("absent address must stay nil, got %+v", out[0].Address)
	}
}

func TestRipplingTimeUnmarshal(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantSet bool
		want    time.Time
	}{
		{"rfc3339", `"2024-01-15T10:30:00Z"`, true, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)},
		// Go's time.Parse accepts a fractional second even when the layout
		// has none, so RFC3339 covers Rippling's millisecond timestamps.
		{"millis", `"2024-01-15T10:30:00.000Z"`, true, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)},
		{"nanos", `"2024-01-15T10:30:00.123456789Z"`, true, time.Date(2024, 1, 15, 10, 30, 0, 123456789, time.UTC)},
		{"offset", `"2024-01-15T10:30:00+02:00"`, true, time.Date(2024, 1, 15, 8, 30, 0, 0, time.UTC)},
		{"empty string", `""`, false, time.Time{}},
		{"null", `null`, false, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v ripplingTime
			if err := json.Unmarshal([]byte(c.in), &v); err != nil {
				t.Fatalf("unmarshal %s: %v", c.in, err)
			}
			if !c.wantSet {
				if !v.Time.IsZero() {
					t.Fatalf("absent timestamp must stay zero, got %v", v.Time)
				}
				return
			}
			if !v.Time.Equal(c.want) {
				t.Fatalf("got %v, want %v", v.Time, c.want)
			}
		})
	}
}

func TestRipplingDateUnmarshal(t *testing.T) {
	var v ripplingDate
	if err := json.Unmarshal([]byte(`"2021-12-31"`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if want := time.Date(2021, 12, 31, 0, 0, 0, 0, time.UTC); !v.Time.Equal(want) {
		t.Fatalf("got %v, want %v", v.Time, want)
	}
	for _, in := range []string{`""`, `null`} {
		var z ripplingDate
		if err := json.Unmarshal([]byte(in), &z); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		if !z.Time.IsZero() {
			t.Fatalf("%s must stay the zero time, got %v", in, z.Time)
		}
	}
}

func TestGroupDecode(t *testing.T) {
	var out []Group
	if err := json.Unmarshal([]byte(`[{"id":"g-1","name":"Admins","version":"7","users":["emp-1","emp-2"]}]`), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out[0].Users) != 2 {
		t.Fatalf("Users = %v, want 2 members", out[0].Users)
	}
}

// hasJSONField reports whether a decoded struct carries the named field at
// all. Used to keep out-of-scope PII from being reintroduced.
func hasJSONField(v any, name string) bool {
	_, ok := reflect.TypeOf(v).FieldByName(name)
	return ok
}

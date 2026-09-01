// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"no next", `<https://api.gusto.com/v1/companies?page=1>; rel="first"`, ""},
		{
			"single next",
			`<https://api.gusto.com/v1/companies?page=2>; rel="next"`,
			"https://api.gusto.com/v1/companies?page=2",
		},
		{
			"multiple rels",
			`<https://api.gusto.com/v1/companies?page=1>; rel="first", <https://api.gusto.com/v1/companies?page=3>; rel="next", <https://api.gusto.com/v1/companies?page=10>; rel="last"`,
			"https://api.gusto.com/v1/companies?page=3",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextPageURL(c.header); got != c.want {
				t.Fatalf("nextPageURL(%q) = %q, want %q", c.header, got, c.want)
			}
		})
	}
}

// TestGustoDateDecode pins the optional-date contract: a date Gusto did not
// send must stay invalid so callers render it null. Reporting the zero time
// would surface 0001-01-01 as a real hire or join date.
func TestGustoDateDecode(t *testing.T) {
	cases := []struct {
		name      string
		payload   string
		wantValid bool
		wantDate  string
	}{
		{"present", `{"join_date":"2019-04-18"}`, true, "2019-04-18"},
		{"null", `{"join_date":null}`, false, ""},
		{"empty string", `{"join_date":""}`, false, ""},
		{"absent key", `{}`, false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var company Company
			if err := json.Unmarshal([]byte(c.payload), &company); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if company.JoinDate.Valid != c.wantValid {
				t.Fatalf("Valid = %v, want %v", company.JoinDate.Valid, c.wantValid)
			}
			if !c.wantValid {
				if company.JoinDate.Ptr() != nil {
					t.Fatalf("Ptr() = %v, want nil for an absent date", company.JoinDate.Ptr())
				}
				return
			}
			if got := company.JoinDate.Format("2006-01-02"); got != c.wantDate {
				t.Fatalf("date = %q, want %q", got, c.wantDate)
			}
			if company.JoinDate.Ptr() == nil {
				t.Fatal("Ptr() = nil for a present date")
			}
		})
	}
}

// TestEmployeeDecode pins the struct tags against a payload shaped like the
// documented Gusto employee record. A mistyped tag decodes to the zero value,
// which would silently report every employee as active and un-onboarded.
func TestEmployeeDecode(t *testing.T) {
	payload := `{
		"uuid": "emp-1",
		"company_uuid": "co-1",
		"first_name": "Ada",
		"middle_initial": "B",
		"last_name": "Lovelace",
		"preferred_first_name": "Addie",
		"work_email": "ada@example.com",
		"email": "ada.personal@example.net",
		"phone": "555-0100",
		"current_employment_status": "full_time",
		"onboarded": true,
		"onboarding_status": "onboarding_completed",
		"terminated": true,
		"hired_at": "2021-07-01",
		"manager_uuid": "emp-2",
		"department_uuid": "dep-1"
	}`

	var e Employee
	if err := json.Unmarshal([]byte(payload), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"UUID", e.UUID, "emp-1"},
		{"CompanyUUID", e.CompanyUUID, "co-1"},
		{"FirstName", e.FirstName, "Ada"},
		{"MiddleInitial", e.MiddleInitial, "B"},
		{"LastName", e.LastName, "Lovelace"},
		{"PreferredFirstName", e.PreferredFirstName, "Addie"},
		{"WorkEmail", e.WorkEmail, "ada@example.com"},
		{"Email", e.Email, "ada.personal@example.net"},
		{"Phone", e.Phone, "555-0100"},
		{"CurrentEmploymentStatus", e.CurrentEmploymentStatus, "full_time"},
		{"Onboarded", e.Onboarded, true},
		{"OnboardingStatus", e.OnboardingStatus, "onboarding_completed"},
		{"Terminated", e.Terminated, true},
		{"ManagerUUID", e.ManagerUUID, "emp-2"},
		{"DepartmentUUID", e.DepartmentUUID, "dep-1"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if !e.HiredAt.Valid || e.HiredAt.Format("2006-01-02") != "2021-07-01" {
		t.Errorf("HiredAt = %v (valid %v), want 2021-07-01", e.HiredAt.Time, e.HiredAt.Valid)
	}
}

// TestContractorAndCompanyDecode pins the security-relevant booleans. is_active
// and is_suspended drive access audits, so a wrong tag would report every
// record as inactive or unsuspended.
func TestContractorAndCompanyDecode(t *testing.T) {
	var c Contractor
	if err := json.Unmarshal([]byte(`{
		"uuid": "con-1",
		"company_uuid": "co-1",
		"type": "Business",
		"is_active": true,
		"business_name": "Analytical Engines LLC",
		"email": "billing@example.com",
		"start_date": "2020-01-15",
		"onboarded": true,
		"onboarding_status": "onboarding_completed"
	}`), &c); err != nil {
		t.Fatalf("unmarshal contractor: %v", err)
	}
	if !c.IsActive || !c.Onboarded || c.Type != "Business" || c.BusinessName != "Analytical Engines LLC" {
		t.Errorf("contractor decoded wrong: %+v", c)
	}
	if !c.StartDate.Valid {
		t.Error("StartDate should be valid")
	}

	var co Company
	if err := json.Unmarshal([]byte(`{
		"uuid": "co-1",
		"name": "Example Co",
		"trade_name": "Example",
		"entity_type": "C-Corporation",
		"tier": "plus",
		"is_suspended": true,
		"company_status": "suspended",
		"slug": "example-co",
		"join_date": "2018-03-02"
	}`), &co); err != nil {
		t.Fatalf("unmarshal company: %v", err)
	}
	if !co.IsSuspended || co.CompanyStatus != "suspended" || co.Tier != "plus" || co.EntityType != "C-Corporation" {
		t.Errorf("company decoded wrong: %+v", co)
	}
}

// TestDepartmentDecode pins the department payload, including the nested uuid
// wrappers the department resource uses to resolve its members.
func TestDepartmentDecode(t *testing.T) {
	var d Department
	if err := json.Unmarshal([]byte(`{
		"uuid": "dep-1",
		"company_uuid": "co-1",
		"title": "Engineering",
		"employees": [{"uuid": "emp-1"}, {"uuid": "emp-2"}],
		"contractors": [{"uuid": "con-1"}]
	}`), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Title != "Engineering" {
		t.Errorf("Title = %q, want Engineering", d.Title)
	}
	if len(d.EmployeeRefs) != 2 || d.EmployeeRefs[0].UUID != "emp-1" {
		t.Errorf("EmployeeRefs = %+v", d.EmployeeRefs)
	}
	if len(d.ContractorRefs) != 1 || d.ContractorRefs[0].UUID != "con-1" {
		t.Errorf("ContractorRefs = %+v", d.ContractorRefs)
	}
}

func testConn(t *testing.T, srv *httptest.Server) *GustoConnection {
	t.Helper()
	return &GustoConnection{
		apiBase:    srv.URL,
		apiVersion: defaultAPIVersion,
		token:      "test-token",
		httpClient: srv.Client(),
	}
}

// TestListEmployeesQuery is a regression test for the employee filter. The
// Gusto "terminated" parameter is a filter, so terminated=true returned only
// terminated employees and hid the active workforce entirely. The request must
// carry no terminated filter, and must not ask for compensation data.
func TestListEmployeesQuery(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		fmt.Fprint(w, `[{"uuid":"emp-1","terminated":false}]`)
	}))
	defer srv.Close()

	employees, err := testConn(t, srv).ListEmployees(context.Background(), "co-1")
	if err != nil {
		t.Fatalf("ListEmployees: %v", err)
	}
	if len(employees) != 1 || employees[0].CompanyUUID != "co-1" {
		t.Fatalf("employees = %+v", employees)
	}
	if strings.Contains(gotURL, "terminated") {
		t.Errorf("request %q must not filter on terminated: it would hide active employees", gotURL)
	}
	if strings.Contains(gotURL, "all_compensations") || strings.Contains(gotURL, "include=") {
		t.Errorf("request %q must not request compensation or custom-field data", gotURL)
	}
	if gotURL != "/v1/companies/co-1/employees" {
		t.Errorf("request path = %q", gotURL)
	}
}

// TestGetPaginatedFollowsLinks walks a two-page response.
func TestGetPaginatedFollowsLinks(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing bearer token on %s", r.URL)
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `[{"uuid":"co-2"}]`)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/v1/me/companies?page=2>; rel="next"`, srv.URL))
		fmt.Fprint(w, `[{"uuid":"co-1"}]`)
	}))
	defer srv.Close()

	var out []Company
	if err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out); err != nil {
		t.Fatalf("getPaginated: %v", err)
	}
	if len(out) != 2 || out[0].UUID != "co-1" || out[1].UUID != "co-2" {
		t.Fatalf("out = %+v", out)
	}
}

// TestGetPaginatedStuckCursor makes sure a server that always advertises the
// same next page terminates instead of looping forever.
func TestGetPaginatedStuckCursor(t *testing.T) {
	var srv *httptest.Server
	var hits int
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Link", fmt.Sprintf(`<%s/v1/me/companies?page=2>; rel="next"`, srv.URL))
		fmt.Fprint(w, `[{"uuid":"co-1"}]`)
	}))
	defer srv.Close()

	var out []Company
	err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out)
	if err == nil {
		t.Fatal("expected an error when the cursor never advances")
	}
	if !strings.Contains(err.Error(), "pagination limit") {
		t.Fatalf("error = %v, want the pagination limit", err)
	}
	if hits != maxPages {
		t.Fatalf("made %d requests, want the %d-page cap", hits, maxPages)
	}
}

// TestGetPaginatedRefusesForeignHost makes sure the bearer token never follows
// a pagination link that leaves the configured API host.
func TestGetPaginatedRefusesForeignHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://attacker.example/v1/me/companies?page=2>; rel="next"`)
		fmt.Fprint(w, `[{"uuid":"co-1"}]`)
	}))
	defer srv.Close()

	var out []Company
	err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out)
	if err == nil {
		t.Fatal("expected an error for a cross-host pagination link")
	}
	if !strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("error = %v, want it to name the unexpected host", err)
	}
}

// TestGetPaginatedTruncatesErrorBody keeps an oversized error payload from
// being echoed wholesale into an error surfaced to users and logs.
func TestGetPaginatedTruncatesErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, strings.Repeat("x", maxErrBodySize*3))
	}))
	defer srv.Close()

	var out []Company
	err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out)
	if err == nil {
		t.Fatal("expected an error for a 401 response")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error was not truncated: %d bytes", len(err.Error()))
	}
	if len(err.Error()) > maxErrBodySize*2 {
		t.Fatalf("error message is %d bytes, want it bounded", len(err.Error()))
	}
}

// TestCachedListMemoizes proves the list cache collapses repeated lookups into
// one HTTP request. Resolving a resource by uuid walks every company, so an
// unmemoized list would re-fetch once per lookup.
func TestCachedListMemoizes(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `[{"uuid":"co-1"}]`)
	}))
	defer srv.Close()

	conn := testConn(t, srv)
	for i := 0; i < 3; i++ {
		if _, err := conn.ListCompanies(context.Background()); err != nil {
			t.Fatalf("ListCompanies: %v", err)
		}
	}
	if hits != 1 {
		t.Fatalf("made %d requests, want 1", hits)
	}
}

// TestGetPaginatedRetriesRateLimit pins that a 429 is retried rather than
// aborting the list. Before the retry existed, a single rate-limit response
// on any one page failed the whole scan.
func TestGetPaginatedRetriesRateLimit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"rate limited"}`)
			return
		}
		fmt.Fprint(w, `[{"uuid":"co-1"}]`)
	}))
	defer srv.Close()

	var out []Company
	if err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out); err != nil {
		t.Fatalf("getPaginated: %v", err)
	}
	if len(out) != 1 || out[0].UUID != "co-1" {
		t.Fatalf("out = %+v", out)
	}
	if hits != 2 {
		t.Fatalf("made %d requests, want 1 rate-limited attempt plus 1 retry", hits)
	}
}

// TestGetPaginatedRateLimitCap makes sure the retry is bounded: a server that
// answers 429 forever must produce an error instead of looping.
func TestGetPaginatedRateLimitCap(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"rate limited"}`)
	}))
	defer srv.Close()

	var out []Company
	err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out)
	if err == nil {
		t.Fatal("expected an error once the retry budget is spent")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("error = %v, want the 429 status", err)
	}
	if hits != maxRateLimitRetries+1 {
		t.Fatalf("made %d requests, want %d (first attempt plus %d retries)",
			hits, maxRateLimitRetries+1, maxRateLimitRetries)
	}
}

// TestGetPaginatedDoesNotRetryOtherErrors pins that the retry is scoped to
// 429. Retrying a 403 would multiply every permission failure by the budget.
func TestGetPaginatedDoesNotRetryOtherErrors(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	var out []Company
	if err := getPaginated(context.Background(), testConn(t, srv), "/v1/me/companies", &out); err == nil {
		t.Fatal("expected an error on 403")
	}
	if hits != 1 {
		t.Fatalf("made %d requests, want a single attempt", hits)
	}
}

func TestRetryDelay(t *testing.T) {
	cases := []struct {
		name       string
		retryAfter string
		attempt    int
		want       time.Duration
	}{
		{"absent falls back to backoff", "", 0, baseRetryBackoff},
		{"backoff doubles", "", 2, 4 * baseRetryBackoff},
		{"backoff is capped", "", 20, maxRetryAfter},
		{"unparseable falls back to backoff", "soon", 1, 2 * baseRetryBackoff},
		{"delay seconds honored", "3", 0, 3 * time.Second},
		{"zero seconds honored", "0", 3, 0},
		{"header is capped", "3600", 0, maxRetryAfter},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retryDelay(c.retryAfter, c.attempt); got != c.want {
				t.Fatalf("retryDelay(%q, %d) = %v, want %v", c.retryAfter, c.attempt, got, c.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	if d, ok := parseRetryAfter("  7 ", now); !ok || d != 7*time.Second {
		t.Errorf("delay-seconds: got %v, %v", d, ok)
	}
	if d, ok := parseRetryAfter("Mon, 31 Aug 2026 12:00:20 GMT", now); !ok || d != 20*time.Second {
		t.Errorf("http-date: got %v, %v", d, ok)
	}
	// A date already in the past must not become a negative wait.
	if d := clampDelay(mustParseRetryAfter(t, "Mon, 31 Aug 2026 11:59:00 GMT", now)); d != 0 {
		t.Errorf("past http-date clamped to %v, want 0", d)
	}
	if _, ok := parseRetryAfter("", now); ok {
		t.Error("empty header must report no value")
	}
	if _, ok := parseRetryAfter("later", now); ok {
		t.Error("unparseable header must report no value")
	}
}

func mustParseRetryAfter(t *testing.T, value string, now time.Time) time.Duration {
	t.Helper()
	d, ok := parseRetryAfter(value, now)
	if !ok {
		t.Fatalf("parseRetryAfter(%q) reported no value", value)
	}
	return d
}

// TestDepartmentMembershipNilVsEmpty pins the nil-vs-empty distinction the
// department resource relies on to tell "no contractors are assigned" from
// "the payload never reported membership". Without it, every department with
// zero contractors re-read the department list on each access.
func TestDepartmentMembershipNilVsEmpty(t *testing.T) {
	var reported Department
	if err := json.Unmarshal([]byte(`{"uuid":"dep-1","contractors":[]}`), &reported); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reported.ContractorRefs == nil {
		t.Error(`"contractors": [] must decode to a present, empty slice`)
	}
	if len(reported.ContractorRefs) != 0 {
		t.Errorf("ContractorRefs = %+v, want empty", reported.ContractorRefs)
	}

	for _, payload := range []string{`{"uuid":"dep-1"}`, `{"uuid":"dep-1","contractors":null}`} {
		var absent Department
		if err := json.Unmarshal([]byte(payload), &absent); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		if absent.ContractorRefs != nil {
			t.Errorf("%s decoded to %+v, want nil", payload, absent.ContractorRefs)
		}
	}
}

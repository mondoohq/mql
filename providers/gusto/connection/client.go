// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Company is a Gusto company as returned by /v1/companies/{id} and
// /v1/companies. Only the fields surfaced by the gusto.company MQL
// resource are decoded.
type Company struct {
	UUID          string    `json:"uuid"`
	Name          string    `json:"name"`
	TradeName     string    `json:"trade_name"`
	EntityType    string    `json:"entity_type"`
	Tier          string    `json:"tier"`
	IsSuspended   bool      `json:"is_suspended"`
	CompanyStatus string    `json:"company_status"`
	Slug          string    `json:"slug"`
	JoinDate      gustoDate `json:"join_date"`
}

// Employee is a Gusto employee. Compensation, jobs, garnishments, and
// other pay-related sub-objects are intentionally excluded.
type Employee struct {
	UUID                    string    `json:"uuid"`
	CompanyUUID             string    `json:"company_uuid"`
	FirstName               string    `json:"first_name"`
	MiddleInitial           string    `json:"middle_initial"`
	LastName                string    `json:"last_name"`
	PreferredFirstName      string    `json:"preferred_first_name"`
	WorkEmail               string    `json:"work_email"`
	Email                   string    `json:"email"`
	Phone                   string    `json:"phone"`
	CurrentEmploymentStatus string    `json:"current_employment_status"`
	Onboarded               bool      `json:"onboarded"`
	OnboardingStatus        string    `json:"onboarding_status"`
	Terminated              bool      `json:"terminated"`
	HiredAt                 gustoDate `json:"hired_at"`
	ManagerUUID             string    `json:"manager_uuid"`
	DepartmentUUID          string    `json:"department_uuid"`
}

// Contractor is a Gusto contractor. Wage rates and payment-method fields
// are intentionally excluded.
type Contractor struct {
	UUID             string    `json:"uuid"`
	CompanyUUID      string    `json:"company_uuid"`
	Type             string    `json:"type"`
	IsActive         bool      `json:"is_active"`
	FirstName        string    `json:"first_name"`
	MiddleInitial    string    `json:"middle_initial"`
	LastName         string    `json:"last_name"`
	BusinessName     string    `json:"business_name"`
	Email            string    `json:"email"`
	StartDate        gustoDate `json:"start_date"`
	Onboarded        bool      `json:"onboarded"`
	OnboardingStatus string    `json:"onboarding_status"`
}

// Department is a Gusto department.
type Department struct {
	UUID          string        `json:"uuid"`
	CompanyUUID   string        `json:"company_uuid"`
	Title         string        `json:"title"`
	EmployeeRefs  []uuidWrapper `json:"employees"`
	ContractorRef []uuidWrapper `json:"contractors"`
}

type uuidWrapper struct {
	UUID string `json:"uuid"`
}

// Location is a Gusto work address.
type Location struct {
	UUID           string `json:"uuid"`
	CompanyUUID    string `json:"company_uuid"`
	Street1        string `json:"street_1"`
	Street2        string `json:"street_2"`
	City           string `json:"city"`
	State          string `json:"state"`
	Zip            string `json:"zip"`
	Country        string `json:"country"`
	FilingAddress  bool   `json:"filing_address"`
	MailingAddress bool   `json:"mailing_address"`
	Active         bool   `json:"active"`
}

// Admin is an administrator of a Gusto company.
type Admin struct {
	UUID        string `json:"uuid"`
	CompanyUUID string `json:"company_uuid"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
}

// gustoDate is a YYYY-MM-DD date wrapper. Gusto omits these dates or sends
// them as null/empty, so Valid records whether a date was actually present.
// Callers must not surface an absent date as the zero time: 0001-01-01 would
// read as a real date in an audit.
type gustoDate struct {
	time.Time
	Valid bool
}

// Ptr returns the date as a *time.Time, or nil when Gusto did not supply one.
// Callers hand the result to llx.TimeDataPtr so an absent date stays null.
func (d gustoDate) Ptr() *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.Time
	return &t
}

func (d *gustoDate) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	d.Time = t
	d.Valid = true
	return nil
}

// listCache memoizes list-endpoint results for the lifetime of a
// connection. Resolving resources by uuid (e.g. gusto.employee(uuid: ...))
// walks every accessible company, so without memoization a single query
// can re-fetch the same lists O(companies × resources) times. A connection
// represents a point-in-time audit, so caching the lists is also correct.
type listCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

// cacheEntry holds one memoized list. Its own mutex serializes only the
// callers competing for that key, so a fetch of one list never blocks a
// fetch of an unrelated one.
type cacheEntry struct {
	mu    sync.Mutex
	value any
	set   bool
}

// cachedList returns the cached value for key, or runs fetch and stores
// the result. Only callers for the same key serialize; the global cache
// lock is held just long enough to find or create the per-key entry.
// Errors are never cached, so a failed fetch is retried on the next call.
func cachedList[T any](c *GustoConnection, key string, fetch func() ([]T, error)) ([]T, error) {
	c.cache.mu.Lock()
	if c.cache.entries == nil {
		c.cache.entries = map[string]*cacheEntry{}
	}
	entry, ok := c.cache.entries[key]
	if !ok {
		entry = &cacheEntry{}
		c.cache.entries[key] = entry
	}
	c.cache.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.set {
		return entry.value.([]T), nil
	}
	out, err := fetch()
	if err != nil {
		return nil, err
	}
	entry.value = out
	entry.set = true
	return out, nil
}

// ListCompanies returns every company the connecting token can access.
func (c *GustoConnection) ListCompanies(ctx context.Context) ([]Company, error) {
	return cachedList(c, "companies", func() ([]Company, error) {
		var out []Company
		if err := getPaginated(ctx, c, "/v1/me/companies", &out); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// ListEmployees returns every employee of a company.
func (c *GustoConnection) ListEmployees(ctx context.Context, companyUUID string) ([]Employee, error) {
	return cachedList(c, "employees/"+companyUUID, func() ([]Employee, error) {
		var out []Employee
		// No "terminated" query parameter: it is a filter, so terminated=true
		// would return only terminated employees and hide the active
		// workforce. Omitting it returns the full roster, and each record
		// carries its own "terminated" flag.
		path := fmt.Sprintf("/v1/companies/%s/employees", url.PathEscape(companyUUID))
		if err := getPaginated(ctx, c, path, &out); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].CompanyUUID = companyUUID
		}
		return out, nil
	})
}

// ListContractors returns every contractor of a company.
func (c *GustoConnection) ListContractors(ctx context.Context, companyUUID string) ([]Contractor, error) {
	return cachedList(c, "contractors/"+companyUUID, func() ([]Contractor, error) {
		var out []Contractor
		path := fmt.Sprintf("/v1/companies/%s/contractors", url.PathEscape(companyUUID))
		if err := getPaginated(ctx, c, path, &out); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].CompanyUUID = companyUUID
		}
		return out, nil
	})
}

// ListDepartments returns every department of a company.
func (c *GustoConnection) ListDepartments(ctx context.Context, companyUUID string) ([]Department, error) {
	return cachedList(c, "departments/"+companyUUID, func() ([]Department, error) {
		var out []Department
		path := fmt.Sprintf("/v1/companies/%s/departments", url.PathEscape(companyUUID))
		if err := getPaginated(ctx, c, path, &out); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].CompanyUUID = companyUUID
		}
		return out, nil
	})
}

// ListLocations returns every work location of a company.
func (c *GustoConnection) ListLocations(ctx context.Context, companyUUID string) ([]Location, error) {
	return cachedList(c, "locations/"+companyUUID, func() ([]Location, error) {
		var out []Location
		path := fmt.Sprintf("/v1/companies/%s/locations", url.PathEscape(companyUUID))
		if err := getPaginated(ctx, c, path, &out); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].CompanyUUID = companyUUID
		}
		return out, nil
	})
}

// ListAdmins returns every administrator of a company.
func (c *GustoConnection) ListAdmins(ctx context.Context, companyUUID string) ([]Admin, error) {
	return cachedList(c, "admins/"+companyUUID, func() ([]Admin, error) {
		var out []Admin
		path := fmt.Sprintf("/v1/companies/%s/admins", url.PathEscape(companyUUID))
		if err := getPaginated(ctx, c, path, &out); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].CompanyUUID = companyUUID
		}
		return out, nil
	})
}

// maxPages caps how many Link-header "next" pages getPaginated will follow.
// It guards against a misbehaving or malicious server that returns an
// unending pagination chain.
const maxPages = 500

// maxBodySize caps the bytes read from a single API response. It guards
// against an oversized or malicious body exhausting memory.
const maxBodySize = 50 << 20 // 50 MiB

// maxErrBodySize caps how much of an error response body is echoed into the
// returned error. Error bodies are surfaced to users and logs, so only a
// bounded snippet is included.
const maxErrBodySize = 512

// getPaginated executes GETs and appends every page into out, following RFC
// 5988 Link headers with rel="next". The bearer token is only ever sent to
// the configured API host: the initial URL and every "next" link are checked
// to stay on the same scheme+host as apiBase.
func getPaginated[T any](ctx context.Context, c *GustoConnection, path string, out *[]T) error {
	baseURL, err := url.Parse(c.apiBase)
	if err != nil {
		return err
	}

	// url.JoinPath would escape a query separator, so join the path portion
	// and re-attach any query string verbatim.
	basePath, query, hasQuery := strings.Cut(path, "?")
	next, err := url.JoinPath(c.apiBase, basePath)
	if err != nil {
		return err
	}
	if hasQuery {
		next += "?" + query
	}

	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return fmt.Errorf("gusto API %s exceeded the %d-page pagination limit", path, maxPages)
		}
		if err := sameOrigin(baseURL, next); err != nil {
			return fmt.Errorf("gusto API %s: %w", path, err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Gusto-API-Version", c.apiVersion)
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if int64(len(body)) > maxBodySize {
			return fmt.Errorf("gusto API %s response exceeded the %d-byte size limit", path, maxBodySize)
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("gusto API %s returned %d: %s", path, resp.StatusCode, errSnippet(body))
		}

		var pageItems []T
		if err := json.Unmarshal(body, &pageItems); err != nil {
			return err
		}
		*out = append(*out, pageItems...)

		next = nextPageURL(resp.Header.Get("Link"))
	}
	return nil
}

// sameOrigin reports an error when raw does not share base's scheme and host.
// Every request carries the bearer token, so a link that wanders to another
// origin must never be followed.
func sameOrigin(base *url.URL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("refusing to send credentials to unexpected host %q", u.Scheme+"://"+u.Host)
	}
	return nil
}

// errSnippet bounds an error response body so a large or sensitive payload is
// not echoed wholesale into an error message.
func errSnippet(body []byte) string {
	if len(body) > maxErrBodySize {
		return string(body[:maxErrBodySize]) + "... (truncated)"
	}
	return string(body)
}

// nextPageURL parses an RFC 5988 Link header and returns the URL marked
// rel="next", or empty string if none is present.
func nextPageURL(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		segments := strings.Split(strings.TrimSpace(part), ";")
		if len(segments) < 2 {
			continue
		}
		raw := strings.TrimSpace(segments[0])
		if !strings.HasPrefix(raw, "<") || !strings.HasSuffix(raw, ">") {
			continue
		}
		next := strings.TrimSuffix(strings.TrimPrefix(raw, "<"), ">")
		for _, attr := range segments[1:] {
			if strings.Contains(strings.ToLower(attr), `rel="next"`) {
				if _, err := url.Parse(next); err == nil {
					return next
				}
			}
		}
	}
	return ""
}

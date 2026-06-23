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
	UUID                           string    `json:"uuid"`
	CompanyUUID                    string    `json:"company_uuid"`
	FirstName                      string    `json:"first_name"`
	MiddleInitial                  string    `json:"middle_initial"`
	LastName                       string    `json:"last_name"`
	PreferredFirstName             string    `json:"preferred_first_name"`
	WorkEmail                      string    `json:"work_email"`
	Email                          string    `json:"email"`
	Phone                          string    `json:"phone"`
	CurrentEmployment              bool      `json:"current_employment_matches_filter"`
	Onboarded                      bool      `json:"onboarded"`
	OnboardingStatus               string    `json:"onboarding_status"`
	Terminated                     bool      `json:"terminated"`
	TwoFactorAuthenticationEnabled bool      `json:"two_factor_authentication_enabled"`
	CreatedAt                      time.Time `json:"created_at"`
	ManagerUUID                    string    `json:"manager_uuid"`
	DepartmentUUID                 string    `json:"department_uuid"`
	WorkLocationUUID               string    `json:"work_location_uuid"`
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
	SelfOnboarding   bool      `json:"self_onboarding"`
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

// gustoDate is a YYYY-MM-DD date wrapper that tolerates empty strings.
type gustoDate struct {
	time.Time
}

func (d *gustoDate) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	d.Time = t
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
		if err := c.getPaginated(ctx, "/v1/me/companies", &out); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// ListEmployees returns every employee of a company.
func (c *GustoConnection) ListEmployees(ctx context.Context, companyUUID string) ([]Employee, error) {
	return cachedList(c, "employees/"+companyUUID, func() ([]Employee, error) {
		var out []Employee
		path := fmt.Sprintf("/v1/companies/%s/employees?include=all_compensations,custom_fields&terminated=true", url.PathEscape(companyUUID))
		if err := c.getPaginated(ctx, path, &out); err != nil {
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
		if err := c.getPaginated(ctx, path, &out); err != nil {
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
		if err := c.getPaginated(ctx, path, &out); err != nil {
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
		if err := c.getPaginated(ctx, path, &out); err != nil {
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
		if err := c.getPaginated(ctx, path, &out); err != nil {
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

// getPaginated executes GETs and decodes every page into the *[]T pointed
// to by out, following RFC 5988 Link headers with rel="next". The bearer
// token is only ever sent to the configured API host: every "next" link is
// checked to stay on the same scheme+host as apiBase.
func (c *GustoConnection) getPaginated(ctx context.Context, path string, out any) error {
	baseURL, err := url.Parse(c.apiBase)
	if err != nil {
		return err
	}

	next := c.apiBase + path
	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return fmt.Errorf("gusto API %s exceeded the %d-page pagination limit", path, maxPages)
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
			return fmt.Errorf("gusto API %s returned %d: %s", path, resp.StatusCode, string(body))
		}
		if err := appendJSONPage(body, out); err != nil {
			return err
		}

		next = nextPageURL(resp.Header.Get("Link"))
		if next != "" {
			nextURL, err := url.Parse(next)
			if err != nil {
				return err
			}
			if nextURL.Scheme != baseURL.Scheme || nextURL.Host != baseURL.Host {
				return fmt.Errorf("gusto API %s pagination link points to unexpected host %q", path, nextURL.Scheme+"://"+nextURL.Host)
			}
		}
	}
	return nil
}

// appendJSONPage decodes a page of results and appends them to out.
//
// out must be a *[]T. The function decodes the body into a fresh []T and
// appends it to the destination slice. This is the only reflection use in
// the client — list endpoints all share the same shape, so the alternative
// would be a generic helper per resource type.
func appendJSONPage(body []byte, out any) error {
	switch dst := out.(type) {
	case *[]Company:
		var page []Company
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	case *[]Employee:
		var page []Employee
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	case *[]Contractor:
		var page []Contractor
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	case *[]Department:
		var page []Department
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	case *[]Location:
		var page []Location
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	case *[]Admin:
		var page []Admin
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		*dst = append(*dst, page...)
	default:
		return fmt.Errorf("unsupported destination type %T", out)
	}
	return nil
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

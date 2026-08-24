// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Me is the token-context payload returned by GET /platform/api/me. Only
// the fields used for asset identification are decoded.
type Me struct {
	CompanyID string `json:"company"`
	Role      string `json:"role"`
	RoleName  string `json:"roleName"`
}

// Company is a Rippling company as returned by GET /platform/api/companies.
// Only the fields surfaced by the rippling.company MQL resource are decoded.
type Company struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	LegalName    string         `json:"legalName"`
	WorkEmail    string         `json:"workEmail"`
	Phone        string         `json:"phone"`
	PrimaryEmail string         `json:"primaryEmail"`
	NeedsOnboard bool           `json:"needsOnboarding"`
	CreatedAt    ripplingTime   `json:"createdAt"`
	Address      *NestedAddress `json:"address"`
}

// NestedAddress is a Rippling address payload embedded in several
// resources (company, work location, employee).
type NestedAddress struct {
	StreetLine1 string `json:"streetLine1"`
	StreetLine2 string `json:"streetLine2"`
	City        string `json:"city"`
	State       string `json:"state"`
	Zip         string `json:"zip"`
	Country     string `json:"country"`
	Phone       string `json:"phone"`
}

// Employee is a Rippling employee. Compensation, benefits, garnishments
// and pay-related sub-objects are intentionally excluded; this struct
// only carries the identity and org-structure fields exposed by
// rippling.employee.
type Employee struct {
	ID                 string       `json:"id"`
	EmployeeNumber     int          `json:"employeeNumber"`
	FirstName          string       `json:"firstName"`
	MiddleName         string       `json:"middleName"`
	LastName           string       `json:"lastName"`
	PreferredFirstName string       `json:"preferredFirstName"`
	WorkEmail          string       `json:"workEmail"`
	PhoneNumber        string       `json:"phoneNumber"`
	Title              string       `json:"title"`
	EmploymentType     string       `json:"employmentType"`
	RoleStatus         string       `json:"roleState"`
	StartDate          ripplingDate `json:"startDate"`
	EndDate            ripplingDate `json:"endDate"`
	TerminationDate    ripplingDate `json:"terminationDate"`
	TerminationType    string       `json:"terminationType"`
	TerminationReason  string       `json:"terminationReason"`
	CreatedAt          ripplingTime `json:"createdAt"`
	UpdatedAt          ripplingTime `json:"updatedAt"`
	Manager            string       `json:"manager"`
	Department         string       `json:"department"`
	Team               string       `json:"team"`
	WorkLocation       string       `json:"workLocation"`
}

// Department is a Rippling department.
type Department struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Parent string `json:"parent"`
}

// Team is a Rippling team. Rippling teams are hierarchical and may have a
// parent team.
type Team struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ParentTeam string `json:"parentTeam"`
}

// WorkLocation is a Rippling work location (a physical office or hub).
type WorkLocation struct {
	ID       string         `json:"id"`
	Nickname string         `json:"nickname"`
	Phone    string         `json:"phone"`
	Address  *NestedAddress `json:"address"`
}

// Group is a Rippling group (used for app provisioning and access).
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Users   []string `json:"users"`
}

// ripplingTime is an ISO-8601 timestamp wrapper that tolerates empty strings.
type ripplingTime struct {
	time.Time
}

func (t *ripplingTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// ripplingDate is a YYYY-MM-DD date wrapper that tolerates empty strings.
type ripplingDate struct {
	time.Time
}

func (d *ripplingDate) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	d.Time = parsed
	return nil
}

// GetMe returns the token-context payload.
func (c *RipplingConnection) GetMe(ctx context.Context) (*Me, error) {
	var me Me
	if err := c.get(ctx, "/platform/api/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// GetCompany returns the single company associated with the token.
// Rippling exposes this as an array under /platform/api/companies even
// though the token is scoped to one company.
func (c *RipplingConnection) GetCompany(ctx context.Context) (*Company, error) {
	var companies []Company
	if err := c.get(ctx, "/platform/api/companies", &companies); err != nil {
		return nil, err
	}
	if len(companies) == 0 {
		return nil, errors.New("no company accessible with the configured Rippling token")
	}
	return &companies[0], nil
}

// ListEmployees returns every employee visible to the token.
//
// The result is memoized for the lifetime of the connection: every typed
// cross-reference into rippling.employee resolves through this list, so
// re-walking the endpoint per lookup would cost one full pagination walk
// per department, team, location, and group member. The returned slice is
// shared and must be treated as read-only.
func (c *RipplingConnection) ListEmployees(ctx context.Context) ([]Employee, error) {
	return c.employees.get(func() ([]Employee, error) {
		return getPaginated[Employee](ctx, c, "/platform/api/employees")
	})
}

// ListDepartments returns every department. Memoized like ListEmployees.
func (c *RipplingConnection) ListDepartments(ctx context.Context) ([]Department, error) {
	return c.departments.get(func() ([]Department, error) {
		return getPaginated[Department](ctx, c, "/platform/api/departments")
	})
}

// ListTeams returns every team. Memoized like ListEmployees.
func (c *RipplingConnection) ListTeams(ctx context.Context) ([]Team, error) {
	return c.teams.get(func() ([]Team, error) {
		return getPaginated[Team](ctx, c, "/platform/api/teams")
	})
}

// ListWorkLocations returns every work location. Memoized like ListEmployees.
func (c *RipplingConnection) ListWorkLocations(ctx context.Context) ([]WorkLocation, error) {
	return c.workLocations.get(func() ([]WorkLocation, error) {
		return getPaginated[WorkLocation](ctx, c, "/platform/api/work_locations")
	})
}

// ListGroups returns every group. Memoized like ListEmployees.
func (c *RipplingConnection) ListGroups(ctx context.Context) ([]Group, error) {
	return c.groups.get(func() ([]Group, error) {
		return getPaginated[Group](ctx, c, "/platform/api/groups")
	})
}

// get does a single authenticated GET and decodes the response into out.
func (c *RipplingConnection) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBase+path, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("rippling API %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

// pageSize is Rippling's standard page size for list endpoints.
const pageSize = 100

// maxPages bounds a limit/offset walk. Rippling's list endpoints return a
// bare JSON array with no cursor or total count, so there is nothing to
// compare a page against: an endpoint that ignored the offset parameter
// would hand back the same page forever. The cap turns that into a loud
// error instead of an unbounded loop.
const maxPages = 1000

// getPaginated walks the limit/offset pagination used by Rippling Platform
// API list endpoints and returns every record.
//
// Only an empty page ends the walk, and the offset advances by the number
// of records actually returned. A page shorter than pageSize is not treated
// as the last one: Rippling does not document that guarantee, and stopping
// there (or stepping a fixed pageSize past it) would silently drop every
// record that follows a short page.
func getPaginated[T any](ctx context.Context, c *RipplingConnection, path string) ([]T, error) {
	var out []T
	offset := 0
	for page := 0; page < maxPages; page++ {
		body, err := c.fetchPage(ctx, path, offset)
		if err != nil {
			return nil, err
		}
		var records []T
		if err := json.Unmarshal(body, &records); err != nil {
			return nil, fmt.Errorf("rippling API %s returned an undecodable page at offset %d: %w", path, offset, err)
		}
		if len(records) == 0 {
			return out, nil
		}
		out = append(out, records...)
		offset += len(records)
	}
	return nil, fmt.Errorf("rippling API %s exceeded %d pages after %d records; the endpoint may be ignoring the offset parameter", path, maxPages, len(out))
}

func (c *RipplingConnection) fetchPage(ctx context.Context, path string, offset int) ([]byte, error) {
	u := c.apiBase + path
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	u += sep + "limit=" + strconv.Itoa(pageSize) + "&offset=" + strconv.Itoa(offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("rippling API %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

// setHeaders sets the non-auth request headers. The Authorization header is
// added by the oauth2 transport on c.httpClient, which also refreshes the
// access token as needed.
func (c *RipplingConnection) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
}

// memo caches one list walk for the lifetime of a connection. A failed walk
// is cached alongside a successful one so a read that could not complete
// keeps reporting the error, rather than degrading into an empty list that
// is indistinguishable from "this company has none".
type memo[T any] struct {
	mu     sync.Mutex
	loaded bool
	value  []T
	err    error
}

func (m *memo[T]) get(load func() ([]T, error)) ([]T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		m.value, m.err = load()
		m.loaded = true
	}
	return m.value, m.err
}

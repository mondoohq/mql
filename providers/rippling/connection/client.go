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
	Tin          string         `json:"tin"`
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
	PersonalEmail      string       `json:"personalEmail"`
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

// ListEmployees returns every employee visible to the token, walking the
// limit/offset pagination supported by /platform/api/employees.
func (c *RipplingConnection) ListEmployees(ctx context.Context) ([]Employee, error) {
	var out []Employee
	if err := c.getPaginated(ctx, "/platform/api/employees", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDepartments returns every department.
func (c *RipplingConnection) ListDepartments(ctx context.Context) ([]Department, error) {
	var out []Department
	if err := c.getPaginated(ctx, "/platform/api/departments", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListTeams returns every team.
func (c *RipplingConnection) ListTeams(ctx context.Context) ([]Team, error) {
	var out []Team
	if err := c.getPaginated(ctx, "/platform/api/teams", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListWorkLocations returns every work location.
func (c *RipplingConnection) ListWorkLocations(ctx context.Context) ([]WorkLocation, error) {
	var out []WorkLocation
	if err := c.getPaginated(ctx, "/platform/api/work_locations", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListGroups returns every group.
func (c *RipplingConnection) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	if err := c.getPaginated(ctx, "/platform/api/groups", &out); err != nil {
		return nil, err
	}
	return out, nil
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

// getPaginated walks the limit/offset pagination scheme used by Rippling
// Platform API list endpoints and appends every page into the slice
// pointed to by out.
//
// out must be a *[]T. A page that returns fewer than pageSize records is
// treated as the final page.
func (c *RipplingConnection) getPaginated(ctx context.Context, path string, out any) error {
	offset := 0
	for {
		page, err := c.fetchPage(ctx, path, offset)
		if err != nil {
			return err
		}
		added, err := appendJSONPage(page, out)
		if err != nil {
			return err
		}
		if added < pageSize {
			return nil
		}
		offset += pageSize
	}
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

// appendJSONPage decodes a single page of results and appends them onto
// the destination slice. Returns the number of records decoded.
//
// out must be a *[]T. List endpoints all share the same shape, so this
// switch keeps the helper free of reflection at the cost of one case per
// resource type.
func appendJSONPage(body []byte, out any) (int, error) {
	switch dst := out.(type) {
	case *[]Employee:
		var page []Employee
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, err
		}
		*dst = append(*dst, page...)
		return len(page), nil
	case *[]Department:
		var page []Department
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, err
		}
		*dst = append(*dst, page...)
		return len(page), nil
	case *[]Team:
		var page []Team
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, err
		}
		*dst = append(*dst, page...)
		return len(page), nil
	case *[]WorkLocation:
		var page []WorkLocation
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, err
		}
		*dst = append(*dst, page...)
		return len(page), nil
	case *[]Group:
		var page []Group
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, err
		}
		*dst = append(*dst, page...)
		return len(page), nil
	default:
		return 0, fmt.Errorf("unsupported destination type %T", out)
	}
}

// nextOffset returns the offset to request after a page that returned
// the given number of records, or -1 if pagination is complete. Exposed
// at package scope so the pagination math can be unit-tested without
// standing up an HTTP server.
func nextOffset(currentOffset, returned int) int {
	if returned < pageSize {
		return -1
	}
	return currentOffset + pageSize
}

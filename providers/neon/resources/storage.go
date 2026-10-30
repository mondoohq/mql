// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/types"
)

// branchBasePath is the branch-scoped root the storage and function endpoints
// hang off.
func branchBasePath(projectID, branchID string) string {
	return "/projects/" + url.PathEscape(projectID) +
		"/branches/" + url.PathEscape(branchID)
}

// --- buckets --------------------------------------------------------------

// mqlNeonBucketInternal caches the branch the bucket is attached to.
type mqlNeonBucketInternal struct {
	cacheProjectID string
	cacheBranchID  string
}

type bucketRecord struct {
	Name        string   `json:"name"`
	AccessLevel string   `json:"access_level"`
	CreatedAt   neonTime `json:"created_at"`
}

func (b *mqlNeonBranch) buckets() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetList[bucketRecord](context.Background(), c,
		branchBasePath(b.cacheProjectID, b.Id.Data)+"/buckets", nil, "buckets")
	if err != nil {
		// Object storage is a plan-gated feature.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			b.Buckets = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// A bucket is named within its branch, so the cache key carries the
		// project and branch it was read from.
		bucket, err := CreateResource(b.MqlRuntime, "neon.bucket", map[string]*llx.RawData{
			"__id":        llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/bucket/" + rec.Name),
			"name":        llx.StringData(rec.Name),
			"accessLevel": llx.StringData(rec.AccessLevel),
			"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlBucket := bucket.(*mqlNeonBucket)
		mqlBucket.cacheProjectID = b.cacheProjectID
		mqlBucket.cacheBranchID = b.Id.Data
		res = append(res, mqlBucket)
	}
	return res, nil
}

// branch resolves the branch the bucket is attached to.
func (b *mqlNeonBucket) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(b.MqlRuntime, b.cacheProjectID, b.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		b.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// --- credentials ----------------------------------------------------------

// mqlNeonCredentialInternal caches the branch the credential is scoped to and
// the function it was minted for.
type mqlNeonCredentialInternal struct {
	cacheProjectID   string
	cacheBranchID    string
	cacheFunctionID  string
	cacheOwnerBranch string
}

// credentialRecord decodes the credential metadata the list endpoint returns.
// The bearer token and the object storage secret are returned only once, when
// the credential is issued, and neither has a field here.
type credentialRecord struct {
	TokenID       string   `json:"token_id"`
	TokenIDShort  string   `json:"token_id_short"`
	Name          *string  `json:"name"`
	Scopes        []string `json:"scopes"`
	BranchID      *string  `json:"branch_id"`
	PrincipalType string   `json:"principal_type"`
	FunctionID    *string  `json:"function_id"`
	CreatedAt     neonTime `json:"created_at"`
	LastUsedAt    neonTime `json:"last_used_at"`
	RevokedAt     neonTime `json:"revoked_at"`
	ExpiresAt     neonTime `json:"expires_at"`
}

func (b *mqlNeonBranch) credentials() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetList[credentialRecord](context.Background(), c,
		branchBasePath(b.cacheProjectID, b.Id.Data)+"/credentials", nil, "credentials")
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			b.Credentials = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]

		// The full credential identifier keys the cache but is not published
		// as a field.
		credential, err := CreateResource(b.MqlRuntime, "neon.credential", map[string]*llx.RawData{
			"__id":          llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/credential/" + rec.TokenID),
			"tokenIdShort":  llx.StringData(rec.TokenIDShort),
			"name":          optionalString(rec.Name),
			"scopes":        llx.ArrayData(strSliceToAny(rec.Scopes), types.String),
			"principalType": llx.StringData(rec.PrincipalType),
			"createdAt":     llx.TimeDataPtr(rec.CreatedAt.Time()),
			"lastUsedAt":    llx.TimeDataPtr(rec.LastUsedAt.Time()),
			"revokedAt":     llx.TimeDataPtr(rec.RevokedAt.Time()),
			"expiresAt":     llx.TimeDataPtr(rec.ExpiresAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlCredential := credential.(*mqlNeonCredential)
		mqlCredential.cacheProjectID = b.cacheProjectID
		mqlCredential.cacheBranchID = b.Id.Data
		mqlCredential.cacheOwnerBranch = strPtr(rec.BranchID)
		mqlCredential.cacheFunctionID = strPtr(rec.FunctionID)
		res = append(res, mqlCredential)
	}
	return res, nil
}

// branch resolves the branch the credential is scoped to.
func (c *mqlNeonCredential) branch() (*mqlNeonBranch, error) {
	branchID := c.cacheOwnerBranch
	if branchID == "" {
		branchID = c.cacheBranchID
	}
	if branchID == "" {
		c.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branch, err := branchByID(c.MqlRuntime, c.cacheProjectID, branchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		c.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// function resolves the function the credential was minted for. A credential an
// operator issued has none.
func (c *mqlNeonCredential) function() (*mqlNeonFunction, error) {
	if c.cacheFunctionID == "" {
		c.Function.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	branchID := c.cacheOwnerBranch
	if branchID == "" {
		branchID = c.cacheBranchID
	}

	branch, err := branchByID(c.MqlRuntime, c.cacheProjectID, branchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		c.Function.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// The branch's function list is read once and reused, rather than reading
	// the function endpoint once per credential that names one.
	functions := branch.GetFunctions()
	if functions.Error != nil {
		return nil, functions.Error
	}
	for _, it := range functions.Data {
		fn, ok := it.(*mqlNeonFunction)
		if ok && fn.Id.Data == c.cacheFunctionID {
			return fn, nil
		}
	}

	c.Function.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- functions ------------------------------------------------------------

// mqlNeonFunctionInternal caches the branch the function runs on and the two
// deployment payloads the function record carries inline.
type mqlNeonFunctionInternal struct {
	cacheProjectID string
	cacheBranchID  string

	cacheActive  *functionDeploymentRecord
	cacheCurrent *functionDeploymentRecord
}

type functionRecord struct {
	ID                string                    `json:"id"`
	Slug              string                    `json:"slug"`
	Name              string                    `json:"name"`
	InvocationURL     string                    `json:"invocation_url"`
	CurrentDeployment *functionDeploymentRecord `json:"current_deployment"`
	ActiveDeployment  *functionDeploymentRecord `json:"active_deployment"`
	CreatedAt         neonTime                  `json:"created_at"`
}

// functionDeploymentRecord decodes one build of a function. The environment
// list carries variable names only. Neon encrypts the values and never returns
// them.
type functionDeploymentRecord struct {
	ID          int64    `json:"id"`
	Status      string   `json:"status"`
	MemoryMib   *int64   `json:"memory_mib"`
	Runtime     string   `json:"runtime"`
	CreatedAt   neonTime `json:"created_at"`
	Environment []string `json:"environment"`
	Error       *string  `json:"error"`
}

func (b *mqlNeonBranch) functions() ([]any, error) {
	c := neonConn(b.MqlRuntime)

	records, err := connection.GetPagedCursor[functionRecord](context.Background(), c,
		branchBasePath(b.cacheProjectID, b.Id.Data)+"/functions", nil, "functions")
	if err != nil {
		// Functions are a plan-gated feature.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			b.Functions = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// Function identifiers are scoped to their branch, so the cache key
		// carries the project and branch it was read from.
		fn, err := CreateResource(b.MqlRuntime, "neon.function", map[string]*llx.RawData{
			"__id":          llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/function/" + rec.ID),
			"id":            llx.StringData(rec.ID),
			"slug":          llx.StringData(rec.Slug),
			"name":          llx.StringData(rec.Name),
			"invocationUrl": llx.StringData(rec.InvocationURL),
			"createdAt":     llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlFn := fn.(*mqlNeonFunction)
		mqlFn.cacheProjectID = b.cacheProjectID
		mqlFn.cacheBranchID = b.Id.Data
		mqlFn.cacheActive = rec.ActiveDeployment
		mqlFn.cacheCurrent = rec.CurrentDeployment
		res = append(res, mqlFn)
	}
	return res, nil
}

// branch resolves the branch the function is deployed on.
func (f *mqlNeonFunction) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(f.MqlRuntime, f.cacheProjectID, f.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		f.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

func (f *mqlNeonFunction) activeDeployment() (*mqlNeonFunctionDeployment, error) {
	if f.cacheActive == nil {
		f.ActiveDeployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f.newDeployment(f.cacheActive)
}

func (f *mqlNeonFunction) currentDeployment() (*mqlNeonFunctionDeployment, error) {
	if f.cacheCurrent == nil {
		f.CurrentDeployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f.newDeployment(f.cacheCurrent)
}

// newDeployment builds one build of the function. The build number is unique
// per function, so the cache key carries the function it belongs to, and the
// active and current slots share an instance when they name the same build.
func (f *mqlNeonFunction) newDeployment(rec *functionDeploymentRecord) (*mqlNeonFunctionDeployment, error) {
	res, err := CreateResource(f.MqlRuntime, "neon.function.deployment", map[string]*llx.RawData{
		"__id": llx.StringData(f.cacheProjectID + "/" + f.cacheBranchID +
			"/function/" + f.Id.Data + "/deployment/" + itoa(rec.ID)),
		"id":          llx.IntData(rec.ID),
		"status":      llx.StringData(rec.Status),
		"memoryMib":   llx.IntDataPtr(rec.MemoryMib),
		"runtime":     llx.StringData(rec.Runtime),
		"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
		"environment": llx.ArrayData(strSliceToAny(rec.Environment), types.String),
		"error":       optionalString(rec.Error),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNeonFunctionDeployment), nil
}

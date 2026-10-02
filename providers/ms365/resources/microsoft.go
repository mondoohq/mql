// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	betareports "github.com/microsoftgraph/msgraph-beta-sdk-go/reports"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/reports"
	"go.mondoo.com/mql/providers/ms365/connection"
)

var idxUsersById = &sync.RWMutex{}
var idxDevicesById = &sync.RWMutex{}

type mfaResp struct {
	// holds the error if that is what the request returned
	err    error
	mfaMap map[string]bool
}

type mqlMicrosoftInternal struct {
	permissionIndexer
	// index users by id
	idxUsersById map[string]*mqlMicrosoftUser
	// index devices by id
	idxDevicesById map[string]*mqlMicrosoftDevice
	// guards mfaResp; ensures the MFA registration fetch only runs once
	mfaOnce sync.Once
	// the response when asking for the user registration details
	mfaResp mfaResp
	// guards regDetails; the whole tenant's registration details, fetched once
	regOnce    sync.Once
	regDetails map[string]models.UserRegistrationDetailsable
	regErr     error
	// per-user fields resolved in one batched Graph call on first access
	userBatches userBatchCaches
	// per-service-principal fields resolved in one batched Graph call
	spBatches spBatchCaches
	// per-user audit-log fields resolved in one batched Graph call
	auditlogBatches auditlogBatchCaches
	// directory role id to role template id, read once for administrative units
	dirRoleTemplates directoryRoleTemplateCache
	// tenant-wide LAPS and BitLocker escrow listings, fetched once
	keyEscrow keyEscrowCache
}

// userBatchCaches holds one cache per per-user field that is resolved through
// the Graph $batch endpoint. The first accessor of a field triggers a single
// batched fetch covering every indexed user; the rest read from the cache.
type userBatchCaches struct {
	settings       batchFieldCache
	signInActivity batchFieldCache
	authMethods    batchFieldCache
	authRequires   batchFieldCache
	licenseDetails batchFieldCache
}

// spBatchCaches holds one cache per per-service-principal field resolved
// through the Graph $batch endpoint, working the same way as userBatchCaches.
type spBatchCaches struct {
	permissions batchFieldCache
	assignments batchFieldCache
}

// auditlogBatchCaches holds one cache per per-user audit-log field resolved
// through the Graph $batch endpoint, working the same way as userBatchCaches.
type auditlogBatchCaches struct {
	signins                  batchFieldCache
	lastNonInteractiveSignIn batchFieldCache
}

// batchFieldCache memoizes a bulk-loaded per-item field. It tracks which item
// keys have been resolved so items discovered after the first batch (for
// example a group member indexed while resolving group members) are still
// fetched on demand rather than silently returning a nil result.
type batchFieldCache struct {
	mu     sync.Mutex
	data   map[string]any
	errs   map[string]error
	loaded map[string]bool
	err    error
}

// resolve returns the bulk-loaded value for key. The first call for any
// not-yet-loaded key runs load over every id in allIDs still outstanding (so a
// query touching many items batches them in one call) plus key itself, and
// merges the outcome into the cache. A batch-wide failure or a per-item
// failure is surfaced as an error.
//
// load runs with the cache mutex held; it must not call back into resolve on
// the same cache.
func (c *batchFieldCache) resolve(
	key string,
	allIDs []string,
	load func(ids []string) (map[string]any, map[string]error, error),
) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if c.data == nil {
		c.data = map[string]any{}
		c.errs = map[string]error{}
		c.loaded = map[string]bool{}
	}
	if !c.loaded[key] {
		todo := make([]string, 0, len(allIDs)+1)
		seen := map[string]bool{}
		for _, id := range allIDs {
			if c.loaded[id] || seen[id] {
				continue
			}
			seen[id] = true
			todo = append(todo, id)
		}
		if !seen[key] {
			todo = append(todo, key)
		}
		data, errs, err := load(todo)
		if err != nil {
			c.err = err
			return nil, err
		}
		for _, id := range todo {
			c.loaded[id] = true
		}
		for id, v := range data {
			c.data[id] = v
		}
		for id, e := range errs {
			c.errs[id] = e
		}
	}
	if e := c.errs[key]; e != nil {
		return nil, e
	}
	return c.data[key], nil
}

// indexedUserIDs returns the ids of every user materialized so far. Users are
// indexed by microsoft.users.list, initMicrosoftUser, and group/application
// member resolution, so this is the set of users whose fields a batched query
// can ask for.
func (a *mqlMicrosoft) indexedUserIDs() []string {
	idxUsersById.RLock()
	defer idxUsersById.RUnlock()
	ids := make([]string, 0, len(a.idxUsersById))
	for id := range a.idxUsersById {
		ids = append(ids, id)
	}
	return ids
}

// loadMfaResp lazily fetches user MFA registration details from the beta
// Graph API and caches the result on a.mfaResp. It's called on demand by
// microsoft.user.mfaEnabled; the sync.Once ensures the whole-tenant fetch
// runs only once no matter how many users' mfaEnabled is accessed.
func (a *mqlMicrosoft) loadMfaResp() *mfaResp {
	a.mfaOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		betaClient, err := conn.BetaGraphClient()
		if err != nil {
			a.mfaResp = mfaResp{err: err}
			return
		}

		ctx := context.Background()
		top := int32(999)
		resp, err := betaClient.
			Reports().
			AuthenticationMethods().
			UserRegistrationDetails().
			Get(ctx, &betareports.AuthenticationMethodsUserRegistrationDetailsRequestBuilderGetRequestConfiguration{
				QueryParameters: &betareports.AuthenticationMethodsUserRegistrationDetailsRequestBuilderGetQueryParameters{
					Top: &top,
				},
			})
		// a failure here typically means the tenant lacks the required license;
		// store the error so mfaEnabled can surface it but don't fail callers.
		if err != nil {
			a.mfaResp = mfaResp{err: err}
			return
		}

		details, err := iterate[*betamodels.UserRegistrationDetails](ctx, resp, betaClient.GetAdapter(), betamodels.CreateUserRegistrationDetailsCollectionResponseFromDiscriminatorValue)
		if err != nil {
			a.mfaResp = mfaResp{err: err}
			return
		}

		mfaMap := map[string]bool{}
		for _, u := range details {
			if u.GetId() == nil || u.GetIsMfaRegistered() == nil {
				continue
			}
			mfaMap[*u.GetId()] = *u.GetIsMfaRegistered()
		}
		a.mfaResp = mfaResp{mfaMap: mfaMap}
	})
	return &a.mfaResp
}

// indexUser adds a user to the internal indexes. The map is created lazily
// under the write lock so concurrent indexing can't race on the nil check.
func (a *mqlMicrosoft) indexUser(user *mqlMicrosoftUser) {
	idxUsersById.Lock()
	if a.idxUsersById == nil {
		a.idxUsersById = make(map[string]*mqlMicrosoftUser)
	}
	a.idxUsersById[user.Id.Data] = user
	idxUsersById.Unlock()
}

// userById returns a user by id if it exists in the indexUser
func (a *mqlMicrosoft) userById(id string) (*mqlMicrosoftUser, bool) {
	idxUsersById.RLock()
	defer idxUsersById.RUnlock()
	if a.idxUsersById == nil {
		return nil, false
	}
	res, ok := a.idxUsersById[id]
	return res, ok
}

// indexDevice adds a device to the internal indexes. The map is created lazily
// under the write lock so concurrent indexing can't race on the nil check.
func (a *mqlMicrosoft) indexDevice(device *mqlMicrosoftDevice) {
	idxDevicesById.Lock()
	if a.idxDevicesById == nil {
		a.idxDevicesById = make(map[string]*mqlMicrosoftDevice)
	}
	a.idxDevicesById[device.Id.Data] = device
	idxDevicesById.Unlock()
}

// deviceById returns a device by id if it exists in the indexDevice
func (a *mqlMicrosoft) deviceById(id string) (*mqlMicrosoftDevice, bool) {
	idxDevicesById.RLock()
	defer idxDevicesById.RUnlock()
	if a.idxDevicesById == nil {
		return nil, false
	}
	res, ok := a.idxDevicesById[id]
	return res, ok
}

// loadRegistrationDetails reads every user's authentication-method registration
// record in one paginated pass and indexes it by user id.
//
// microsoft.user.authMethods.registrationDetails previously fetched its own
// record per user. Measured on this tenant: 50 per-user Gets against 4 $batch
// calls for the whole of authMethods, so the child cost roughly twelve times its
// parent and 86% of that query's traffic. The v1 request builder exposes a
// collection Get alongside the per-item one, and Graph returns the same record
// either way.
//
// Deliberately separate from loadMfaResp, which reads the same report through
// the beta client for mfaEnabled only. Unifying them means moving mfaEnabled to
// v1, which changes a field's data source and belongs in its own change.
func (a *mqlMicrosoft) loadRegistrationDetails() (map[string]models.UserRegistrationDetailsable, error) {
	a.regOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			a.regErr = err
			return
		}

		ctx := context.Background()
		top := int32(999)
		resp, err := graphClient.Reports().AuthenticationMethods().UserRegistrationDetails().
			Get(ctx, &reports.AuthenticationMethodsUserRegistrationDetailsRequestBuilderGetRequestConfiguration{
				QueryParameters: &reports.AuthenticationMethodsUserRegistrationDetailsRequestBuilderGetQueryParameters{
					Top: &top,
				},
			})
		if err != nil {
			a.regErr = transformError(err)
			return
		}

		details, err := iterate[models.UserRegistrationDetailsable](ctx, resp, graphClient.GetAdapter(),
			models.CreateUserRegistrationDetailsCollectionResponseFromDiscriminatorValue)
		if err != nil {
			a.regErr = transformError(err)
			return
		}

		idx := make(map[string]models.UserRegistrationDetailsable, len(details))
		for _, d := range details {
			if d == nil || d.GetId() == nil {
				continue
			}
			idx[*d.GetId()] = d
		}
		a.regDetails = idx
	})
	return a.regDetails, a.regErr
}

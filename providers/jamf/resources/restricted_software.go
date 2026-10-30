// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/jamf/connection"
)

// mqlJamfRestrictedSoftwareInternal caches the detail record. The list API
// returns only id and name, so the remaining fields are fetched once, on
// first access, via GetRestrictedSoftwareByID. detail is an atomic pointer so
// the lock-free fast path in fetchDetail can read it without racing the write
// under lock.
type mqlJamfRestrictedSoftwareInternal struct {
	detail atomic.Pointer[jamfpro.ResourceRestrictedSoftware]
	lock   sync.Mutex
}

func (r *mqlJamf) restrictedSoftware() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	list, err := client.GetRestrictedSoftwares()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, item := range list.RestrictedSoftware {
		mqlItem, err := CreateResource(r.MqlRuntime, "jamf.restrictedSoftware", map[string]*llx.RawData{
			"id":   llx.StringData(strconv.Itoa(item.ID)),
			"name": llx.StringData(item.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlItem)
	}

	return res, nil
}

func (r *mqlJamfRestrictedSoftware) id() (string, error) {
	return "jamf.restrictedSoftware/" + r.Id.Data, nil
}

func (r *mqlJamfRestrictedSoftware) fetchDetail() (*jamfpro.ResourceRestrictedSoftware, error) {
	if d := r.detail.Load(); d != nil {
		return d, nil
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	if d := r.detail.Load(); d != nil {
		return d, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	detail, err := conn.Client.GetRestrictedSoftwareByID(r.Id.Data)
	if err != nil {
		return nil, err
	}
	r.detail.Store(detail)
	return detail, nil
}

func (r *mqlJamfRestrictedSoftware) processName() (string, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return "", err
	}
	return detail.General.ProcessName, nil
}

func (r *mqlJamfRestrictedSoftware) matchExactProcessName() (bool, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.General.MatchExactProcessName, nil
}

func (r *mqlJamfRestrictedSoftware) sendNotification() (bool, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.General.SendNotification, nil
}

func (r *mqlJamfRestrictedSoftware) killProcess() (bool, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.General.KillProcess, nil
}

func (r *mqlJamfRestrictedSoftware) deleteExecutable() (bool, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.General.DeleteExecutable, nil
}

func (r *mqlJamfRestrictedSoftware) displayMessage() (string, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return "", err
	}
	return detail.General.DisplayMessage, nil
}

func (r *mqlJamfRestrictedSoftware) siteName() (string, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail.General.Site == nil {
		return "", nil
	}
	return detail.General.Site.Name, nil
}

func (r *mqlJamfRestrictedSoftware) allComputers() (bool, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return false, err
	}
	return detail.Scope.AllComputers, nil
}

func (r *mqlJamfRestrictedSoftware) scope() (any, error) {
	detail, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}

	entity := func(e jamfpro.RestrictedSoftwareSubsetScopeEntity) (any, string) {
		return int64(e.ID), e.Name
	}
	scope := detail.Scope
	return map[string]any{
		"allComputers":   scope.AllComputers,
		"computers":      jamfScopeEntities(scope.Computers, entity),
		"computerGroups": jamfScopeEntities(scope.ComputerGroups, entity),
		"buildings":      jamfScopeEntities(scope.Buildings, entity),
		"departments":    jamfScopeEntities(scope.Departments, entity),
		"exclusions": map[string]any{
			"computers":      jamfScopeEntities(scope.Exclusions.Computers, entity),
			"computerGroups": jamfScopeEntities(scope.Exclusions.ComputerGroups, entity),
			"buildings":      jamfScopeEntities(scope.Exclusions.Buildings, entity),
			"departments":    jamfScopeEntities(scope.Exclusions.Departments, entity),
			"users":          jamfScopeEntities(scope.Exclusions.Users, entity),
		},
	}, nil
}

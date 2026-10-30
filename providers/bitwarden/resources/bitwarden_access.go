// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitwarden/connection"
)

// mqlBitwardenCollectionMemberAccessInternal caches the collection and
// member IDs of a member-to-collection access grant, so the typed
// collection() and member() references resolve without an extra list call.
type mqlBitwardenCollectionMemberAccessInternal struct {
	cacheCollectionId string
	cacheMemberId     string
}

// mqlBitwardenCollectionGroupAccessInternal caches the collection and group
// IDs of a group-to-collection access grant, so the typed collection() and
// group() references resolve without an extra list call.
type mqlBitwardenCollectionGroupAccessInternal struct {
	cacheCollectionId string
	cacheGroupId      string
}

// newMqlBitwardenCollectionMemberAccess maps one member-to-collection grant
// to its MQL resource. The grant is the same edge whether reached from the
// collection or from the member, so both directions produce the same
// __id (collectionId/memberId) and share a cache entry.
func newMqlBitwardenCollectionMemberAccess(runtime *plugin.Runtime, collectionId, memberId string, sel connection.SelectionReadOnly) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitwarden.collectionMemberAccess", map[string]*llx.RawData{
		"__id":          llx.StringData(collectionId + "/" + memberId),
		"readOnly":      llx.BoolData(sel.ReadOnly),
		"hidePasswords": llx.BoolData(sel.HidePasswords),
		"manage":        llx.BoolData(sel.Manage),
	})
	if err != nil {
		return nil, err
	}
	e := res.(*mqlBitwardenCollectionMemberAccess)
	e.cacheCollectionId = collectionId
	e.cacheMemberId = memberId
	return e, nil
}

// collection resolves the collection this grant applies to.
func (a *mqlBitwardenCollectionMemberAccess) collection() (*mqlBitwardenCollection, error) {
	if a.cacheCollectionId == "" {
		a.Collection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "bitwarden.collection", map[string]*llx.RawData{"id": llx.StringData(a.cacheCollectionId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlBitwardenCollection), nil
}

// member resolves the member this grant is for.
func (a *mqlBitwardenCollectionMemberAccess) member() (*mqlBitwardenMember, error) {
	if a.cacheMemberId == "" {
		a.Member.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "bitwarden.member", map[string]*llx.RawData{"id": llx.StringData(a.cacheMemberId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlBitwardenMember), nil
}

// newMqlBitwardenCollectionGroupAccess maps one group-to-collection grant to
// its MQL resource. The grant is the same edge whether reached from the
// collection or from the group, so both directions produce the same
// __id (collectionId/groupId) and share a cache entry.
func newMqlBitwardenCollectionGroupAccess(runtime *plugin.Runtime, collectionId, groupId string, sel connection.SelectionReadOnly) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitwarden.collectionGroupAccess", map[string]*llx.RawData{
		"__id":          llx.StringData(collectionId + "/" + groupId),
		"readOnly":      llx.BoolData(sel.ReadOnly),
		"hidePasswords": llx.BoolData(sel.HidePasswords),
		"manage":        llx.BoolData(sel.Manage),
	})
	if err != nil {
		return nil, err
	}
	e := res.(*mqlBitwardenCollectionGroupAccess)
	e.cacheCollectionId = collectionId
	e.cacheGroupId = groupId
	return e, nil
}

// collection resolves the collection this grant applies to.
func (a *mqlBitwardenCollectionGroupAccess) collection() (*mqlBitwardenCollection, error) {
	if a.cacheCollectionId == "" {
		a.Collection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "bitwarden.collection", map[string]*llx.RawData{"id": llx.StringData(a.cacheCollectionId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlBitwardenCollection), nil
}

// group resolves the group this grant is for.
func (a *mqlBitwardenCollectionGroupAccess) group() (*mqlBitwardenGroup, error) {
	if a.cacheGroupId == "" {
		a.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "bitwarden.group", map[string]*llx.RawData{"id": llx.StringData(a.cacheGroupId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlBitwardenGroup), nil
}

// findCollectionSelection returns the access grant in sel that targets the
// given collection ID, if any.
func findCollectionSelection(sel []connection.SelectionReadOnly, id string) (connection.SelectionReadOnly, bool) {
	for _, s := range sel {
		if s.Id == id {
			return s, true
		}
	}
	return connection.SelectionReadOnly{}, false
}

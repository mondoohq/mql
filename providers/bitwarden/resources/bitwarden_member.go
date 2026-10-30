// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitwarden/connection"
)

// mqlBitwardenMemberInternal caches the collection access grants embedded in
// the member's Public API response, so collections() and collectionAccess()
// can resolve typed references and permission flags without an extra list
// call.
type mqlBitwardenMemberInternal struct {
	cacheCollections []connection.SelectionReadOnly
}

// newMqlBitwardenMember maps a single Public API member to its MQL resource.
func newMqlBitwardenMember(runtime *plugin.Runtime, m connection.Member) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitwarden.member", map[string]*llx.RawData{
		"__id":                  llx.StringData(m.Id),
		"id":                    llx.StringData(m.Id),
		"userId":                llx.StringDataPtr(m.UserId),
		"name":                  llx.StringDataPtr(m.Name),
		"email":                 llx.StringData(m.Email),
		"role":                  llx.StringData(connection.MemberRoleName(m.Type)),
		"status":                llx.StringData(connection.MemberStatusName(m.Status)),
		"twoFactorEnabled":      llx.BoolData(m.TwoFactorEnabled),
		"resetPasswordEnrolled": llx.BoolData(m.ResetPasswordEnrolled),
		"externalId":            llx.StringDataPtr(m.ExternalId),
	})
	if err != nil {
		return nil, err
	}
	mqlMember := res.(*mqlBitwardenMember)
	mqlMember.cacheCollections = m.Collections
	return mqlMember, nil
}

// initBitwardenMember resolves a member by its member (organization user) ID
// on demand, for typed references (e.g. bitwarden.group.members) and direct
// lookups.
func initBitwardenMember(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("bitwarden.member requires an id argument")
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("bitwarden.member requires a valid id")
	}

	conn := runtime.Connection.(*connection.BitwardenConnection)
	m, err := conn.Client().GetMember(context.Background(), id)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "bitwarden.member with id %q not found", id)
	}

	res, err := newMqlBitwardenMember(runtime, *m)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// collections resolves the collections a member has explicit access to, as
// typed bitwarden.collection references.
func (m *mqlBitwardenMember) collections() ([]any, error) {
	if len(m.cacheCollections) == 0 {
		return nil, nil
	}

	var all []any
	for _, sel := range m.cacheCollections {
		r, err := NewResource(m.MqlRuntime, "bitwarden.collection", map[string]*llx.RawData{"id": llx.StringData(sel.Id)})
		if err != nil {
			log.Warn().Err(err).Str("id", sel.Id).Msg("bitwarden: failed to resolve collection")
			continue
		}
		all = append(all, r)
	}
	return all, nil
}

// collectionAccess resolves the member's per-collection permission grants,
// each carrying the readOnly, hidePasswords, and manage flags recorded for
// the member-to-collection edge.
func (m *mqlBitwardenMember) collectionAccess() ([]any, error) {
	if len(m.cacheCollections) == 0 {
		return nil, nil
	}

	var all []any
	for _, sel := range m.cacheCollections {
		r, err := newMqlBitwardenCollectionMemberAccess(m.MqlRuntime, sel.Id, m.Id.Data, sel)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return all, nil
}

// groups resolves the groups a member belongs to, as typed bitwarden.group
// references. The Public API does not embed group membership on the member
// record; it requires a dedicated group-ids lookup.
func (m *mqlBitwardenMember) groups() ([]any, error) {
	conn := m.MqlRuntime.Connection.(*connection.BitwardenConnection)

	ids, err := conn.Client().GetMemberGroupIds(context.Background(), m.Id.Data)
	if err != nil {
		return nil, err
	}

	var all []any
	for _, id := range ids {
		r, err := NewResource(m.MqlRuntime, "bitwarden.group", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			log.Warn().Err(err).Str("id", id).Msg("bitwarden: failed to resolve group")
			continue
		}
		all = append(all, r)
	}
	return all, nil
}

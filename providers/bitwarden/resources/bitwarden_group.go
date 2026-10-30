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

// mqlBitwardenGroupInternal caches the collection access grants embedded in
// the group's Public API response, so collections() and collectionAccess()
// can resolve typed references and permission flags without an extra list
// call.
type mqlBitwardenGroupInternal struct {
	cacheCollections []connection.SelectionReadOnly
}

// newMqlBitwardenGroup maps a single Public API group to its MQL resource.
func newMqlBitwardenGroup(runtime *plugin.Runtime, g connection.Group) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitwarden.group", map[string]*llx.RawData{
		"__id":       llx.StringData(g.Id),
		"id":         llx.StringData(g.Id),
		"name":       llx.StringData(g.Name),
		"externalId": llx.StringDataPtr(g.ExternalId),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := res.(*mqlBitwardenGroup)
	mqlGroup.cacheCollections = g.Collections
	return mqlGroup, nil
}

// initBitwardenGroup resolves a group by its ID on demand, for typed
// references (e.g. bitwarden.member.groups, bitwarden.collection.groups)
// and direct lookups.
func initBitwardenGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("bitwarden.group requires an id argument")
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("bitwarden.group requires a valid id")
	}

	conn := runtime.Connection.(*connection.BitwardenConnection)
	g, err := conn.Client().GetGroup(context.Background(), id)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "bitwarden.group with id %q not found", id)
	}

	res, err := newMqlBitwardenGroup(runtime, *g)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// collections resolves the collections this group has access to, as typed
// bitwarden.collection references.
func (g *mqlBitwardenGroup) collections() ([]any, error) {
	if len(g.cacheCollections) == 0 {
		return nil, nil
	}

	var all []any
	for _, sel := range g.cacheCollections {
		r, err := NewResource(g.MqlRuntime, "bitwarden.collection", map[string]*llx.RawData{"id": llx.StringData(sel.Id)})
		if err != nil {
			log.Warn().Err(err).Str("id", sel.Id).Msg("bitwarden: failed to resolve collection")
			continue
		}
		all = append(all, r)
	}
	return all, nil
}

// collectionAccess resolves the group's per-collection permission grants,
// each carrying the readOnly, hidePasswords, and manage flags recorded for
// the group-to-collection edge. Every member of the group inherits these.
func (g *mqlBitwardenGroup) collectionAccess() ([]any, error) {
	if len(g.cacheCollections) == 0 {
		return nil, nil
	}

	var all []any
	for _, sel := range g.cacheCollections {
		r, err := newMqlBitwardenCollectionGroupAccess(g.MqlRuntime, sel.Id, g.Id.Data, sel)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return all, nil
}

// members resolves the members belonging to this group, as typed
// bitwarden.member references. The Public API does not embed membership on
// the group record; it requires a dedicated member-ids lookup.
func (g *mqlBitwardenGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.BitwardenConnection)

	ids, err := conn.Client().GetGroupMemberIds(context.Background(), g.Id.Data)
	if err != nil {
		return nil, err
	}

	var all []any
	for _, id := range ids {
		r, err := NewResource(g.MqlRuntime, "bitwarden.member", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			log.Warn().Err(err).Str("id", id).Msg("bitwarden: failed to resolve member")
			continue
		}
		all = append(all, r)
	}
	return all, nil
}

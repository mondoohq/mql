// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func aliasResourceID(serverID, name string) string {
	return serverID + "/alias/" + name
}

// aliases lists the collection aliases defined on the server. A server older
// than aliases answers 404, which means it has none.
func (r *mqlWeaviateInstance) aliases() ([]any, error) {
	client, err := weaviateConnection(r.MqlRuntime).Client()
	if err != nil {
		return nil, err
	}
	aliases, err := client.Alias().Getter().Do(weaviateContext())
	if err != nil {
		if isForbidden(err) || isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	list := make([]any, 0, len(aliases))
	for _, a := range aliases {
		res, err := newWeaviateAlias(r, a.Alias, a.Class)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func newWeaviateAlias(instance *mqlWeaviateInstance, name, collection string) (*mqlWeaviateAlias, error) {
	res, err := CreateResource(instance.MqlRuntime, "weaviate.alias", map[string]*llx.RawData{
		"__id": llx.StringData(aliasResourceID(instance.__id, name)),
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	a := res.(*mqlWeaviateAlias)
	a.cacheInstance = instance
	a.cacheCollection = collection
	return a, nil
}

// collection resolves the alias's target against the instance's collection
// list. A target the list does not hold, which a credential that may read
// aliases but not the schema produces, reads as null.
func (r *mqlWeaviateAlias) collection() (*mqlWeaviateCollection, error) {
	if r.cacheInstance != nil && r.cacheCollection != "" {
		byName, err := collectionsByName(r.cacheInstance)
		if err != nil {
			return nil, err
		}
		if col, ok := byName[r.cacheCollection]; ok {
			return col, nil
		}
	}
	r.Collection.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

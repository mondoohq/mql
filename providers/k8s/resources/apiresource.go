// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

func (k *mqlK8s) apiResources() ([]any, error) {
	kt, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}

	resources, err := kt.SupportedResourceTypes()
	if err != nil {
		return nil, err
	}

	// convert to MQL resources
	list := resources.Resources()
	resp := []any{}
	for i := range list {
		entry := list[i]

		mqlK8SResource, err := CreateResource(k.MqlRuntime, "k8s.apiresource", map[string]*llx.RawData{
			"name":         llx.StringData(entry.Resource.Name),
			"singularName": llx.StringData(entry.Resource.SingularName),
			"namespaced":   llx.BoolData(entry.Resource.Namespaced),
			"group":        llx.StringData(entry.GroupVersion.Group),
			"version":      llx.StringData(entry.GroupVersion.Version),
			"kind":         llx.StringData(entry.Resource.Kind),
			"shortNames":   llx.ArrayData(convert.SliceAnyToInterface(entry.Resource.ShortNames), types.String),
			"categories":   llx.ArrayData(convert.SliceAnyToInterface(entry.Resource.Categories), types.String),
		})
		if err != nil {
			return nil, err
		}
		resp = append(resp, mqlK8SResource)
	}

	return resp, nil
}

func (k *mqlK8sApiresource) id() (string, error) {
	// The group is part of the identity: "events" exists in both the core group
	// and events.k8s.io, and CRDs routinely share a plural across groups. Two
	// entries with the same __id collapse in the resource cache, so the list
	// reports the first one twice and the other disappears. Matches the
	// resource.version.group order of ApiResource.FullApiName().
	return fmt.Sprintf("%s.%s.%s", k.Name.Data, k.Version.Data, k.Group.Data), nil
}

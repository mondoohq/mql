// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// externalEndpointAddresses returns the addresses of endpoints in the slice that
// are not backed by an in-cluster pod. An endpoint is pod-backed when its
// targetRef points at a Pod; anything else (no targetRef, or a non-Pod kind) is
// a manually managed target that frequently lives outside the cluster.
func externalEndpointAddresses(es *discoveryv1.EndpointSlice) []string {
	if es == nil {
		return nil
	}
	var out []string
	for _, ep := range es.Endpoints {
		if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
			continue
		}
		out = append(out, ep.Addresses...)
	}
	return sortedUniqueStrings(out)
}

func (k *mqlK8sEndpointslice) externalAddresses() ([]any, error) {
	return convert.SliceAnyToInterface(externalEndpointAddresses(k.obj)), nil
}

// serviceExternalEndpointAddresses unions the external endpoint addresses across
// every EndpointSlice that backs the service.
func (k *mqlK8sService) serviceExternalEndpointAddresses() ([]string, error) {
	slices := k.GetEndpointSlices()
	if slices.Error != nil {
		return nil, slices.Error
	}
	var addrs []string
	for i := range slices.Data {
		es, ok := slices.Data[i].(*mqlK8sEndpointslice)
		if !ok {
			continue
		}
		addrs = append(addrs, externalEndpointAddresses(es.obj)...)
	}
	return sortedUniqueStrings(addrs), nil
}

func (k *mqlK8sService) externalEndpoints() ([]any, error) {
	addrs, err := k.serviceExternalEndpointAddresses()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(addrs), nil
}

func (k *mqlK8sService) routesToPublicEndpoint() (bool, error) {
	addrs, err := k.serviceExternalEndpointAddresses()
	if err != nil {
		return false, err
	}
	if slices.ContainsFunc(addrs, addressIsPublicNodeAddress) {
		return true, nil
	}
	return false, nil
}

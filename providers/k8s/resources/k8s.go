// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

type mqlK8sInternal struct {
	lock                   sync.Mutex
	nodesByName            map[string]*mqlK8sNode
	serviceAccountsByName  map[string]*mqlK8sServiceaccount
	runtimeImageLookupLock sync.Mutex
	runtimeImageLookup     *runtimeImageClusterLookup
}

func (k *mqlK8s) serverVersion() (any, error) {
	kt, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(kt.ServerVersion())
}

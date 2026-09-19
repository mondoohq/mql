// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

func FilterResource(resType *ApiResource, resourceObjects []runtime.Object, name string, namespace string) ([]runtime.Object, error) {
	// A cluster-scoped object carries no namespace, so a namespace filter can
	// never match one and would drop every StorageClass, PersistentVolume,
	// PriorityClass, RuntimeClass, ClusterRole and so on. Staged discovery sets
	// a namespace on every namespace asset, so without this guard those kinds
	// read as empty on all but the cluster asset and every policy over them
	// passes vacuously.
	if !resType.Resource.Namespaced {
		namespace = ""
	}

	// filter root resources
	roots := filterResource(resourceObjects, resType.Resource.Kind, name, namespace)
	return roots, nil
}

func filterResource(resources []runtime.Object, kind string, name string, namespace string) []runtime.Object {
	filtered := []runtime.Object{}

	for i := range resources {
		res := resources[i]

		if res.GetObjectKind().GroupVersionKind().Kind == kind {
			if len(name) > 0 || len(namespace) > 0 {
				o, err := meta.Accessor(res)
				if err != nil {
					log.Error().Err(err).Msgf("could not filter resource")
					continue
				}
				if len(namespace) > 0 && o.GetNamespace() != namespace {
					continue
				}
				if len(name) > 0 && o.GetName() != name {
					continue
				}
				filtered = append(filtered, res)
			} else if len(name) == 0 {
				filtered = append(filtered, res)
			}
		}
	}
	return filtered
}

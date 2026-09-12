// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

func FilterResource(resType *ApiResource, resourceObjects []runtime.Object, name string, namespace string) ([]runtime.Object, error) {
	// A namespace only selects among namespaced kinds. Cluster-scoped objects
	// (Nodes, ClusterRoles, PersistentVolumes, ...) carry an empty
	// metadata.namespace, so matching them against a requested namespace would
	// discard every one of them and report the kind as empty rather than
	// out of scope.
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

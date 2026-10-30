// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

type KubernetesObjectInfo struct {
	Kind              string
	Name              string
	Namespace         string
	ClusterIdentifier string
}

// PlatformIdOwnershipIndex indexes kubernetes object relationships by their constructed platform id
type PlatformIdOwnershipIndex struct {
	// a map that contains the owners of each resolved k8s object
	ownedBy map[string][]string
	// a map that contains the k8s data for each object, both directly resolved and ones resolved via owner references
	metadataMap       map[string]KubernetesObjectInfo
	clusterIdentifier string
}

func NewKubernetesObjectInfo(clusterIdentifier, workloadType, namespace, name string) KubernetesObjectInfo {
	return KubernetesObjectInfo{
		Kind:              workloadType,
		Name:              name,
		Namespace:         namespace,
		ClusterIdentifier: clusterIdentifier,
	}
}

func NewPlatformIdOwnershipIndex(clusterIdentifier string) *PlatformIdOwnershipIndex {
	return &PlatformIdOwnershipIndex{
		ownedBy:           make(map[string][]string),
		metadataMap:       make(map[string]KubernetesObjectInfo),
		clusterIdentifier: clusterIdentifier,
	}
}

func (od *PlatformIdOwnershipIndex) Add(basePlatformId string, obj runtime.Object) {
	k8sMeta, err := meta.Accessor(obj)
	if err != nil {
		log.Error().Err(err).Msg("could not access object meta attributes")
		return
	}
	objType, err := meta.TypeAccessor(obj)
	if err != nil {
		log.Error().Err(err).Msg("could not access object type attributes")
		return
	}

	objPlatformId := shared.NewWorkloadPlatformId(basePlatformId, od.clusterIdentifier, strings.ToLower(objType.GetKind()), k8sMeta.GetNamespace(), k8sMeta.GetName(), string(k8sMeta.GetUID()))
	objMeta := NewKubernetesObjectInfo(od.clusterIdentifier, objType.GetKind(), k8sMeta.GetNamespace(), k8sMeta.GetName())

	od.metadataMap[objPlatformId] = objMeta
	for _, ownerRef := range k8sMeta.GetOwnerReferences() {
		ownerPlatformId := shared.NewWorkloadPlatformId(basePlatformId, od.clusterIdentifier, strings.ToLower(ownerRef.Kind), k8sMeta.GetNamespace(), ownerRef.Name, "")
		ownerMeta := NewKubernetesObjectInfo(od.clusterIdentifier, ownerRef.Kind, k8sMeta.GetNamespace(), ownerRef.Name)
		od.metadataMap[ownerPlatformId] = ownerMeta

		if _, ok := od.ownedBy[objPlatformId]; !ok {
			od.ownedBy[objPlatformId] = []string{}
		}
		od.ownedBy[objPlatformId] = append(od.ownedBy[objPlatformId], ownerPlatformId)
	}
}

// OwnedBy returns platform identifiers that own the specified platform id
func (od *PlatformIdOwnershipIndex) OwnedBy(id string) []string {
	return od.ownedBy[id]
}

func (od *PlatformIdOwnershipIndex) GetKubernetesObjectData(id string) (KubernetesObjectInfo, bool) {
	entry, ok := od.metadataMap[id]
	return entry, ok
}

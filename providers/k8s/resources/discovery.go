// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
	admissionv1 "k8s.io/api/admission/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	DiscoveryAll              = "all"
	DiscoveryAuto             = "auto"
	DiscoveryClusters         = "clusters"
	DiscoveryPods             = "pods"
	DiscoveryJobs             = "jobs"
	DiscoveryCronJobs         = "cronjobs"
	DiscoveryStatefulSets     = "statefulsets"
	DiscoveryDeployments      = "deployments"
	DiscoveryReplicaSets      = "replicasets"
	DiscoveryDaemonSets       = "daemonsets"
	DiscoveryContainerImages  = "container-images"
	DiscoveryAdmissionReviews = "admissionreviews"
	DiscoveryIngresses        = "ingresses"
	DiscoveryNamespaces       = "namespaces"
	DiscoveryServices         = "services"
	DiscoveryKyverno          = "kyverno"
)

type FilterOpts struct {
	include []string
	exclude []string
}

func validateGlobs(patterns []string) error {
	for _, p := range patterns {
		if _, err := glob.Compile(p); err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		// Patterns are validated at construction time, so Compile cannot fail here.
		g, _ := glob.Compile(pattern)
		if g.Match(value) {
			return true
		}
	}
	return false
}

func (f *FilterOpts) skip(value string) bool {
	if len(f.include) > 0 {
		return !matchesAny(f.include, value)
	}
	return matchesAny(f.exclude, value)
}

// LabelSelectorFilters filters discovered Kubernetes objects by labels.
// Object selectors match the Kubernetes object being discovered; for container
// image discovery this is the pod that references the image, not the image asset.
type LabelSelectorFilters struct {
	namespace labels.Selector
	object    labels.Selector
}

func (f *LabelSelectorFilters) MatchNamespace(obj metav1.Object) bool {
	if f == nil || f.namespace == nil || f.namespace.Empty() {
		return true
	}
	return f.namespace.Matches(labels.Set(obj.GetLabels()))
}

func (f *LabelSelectorFilters) HasNamespaceSelector() bool {
	return f != nil && f.namespace != nil && !f.namespace.Empty()
}

func (f *LabelSelectorFilters) IsEmpty() bool {
	return f == nil || ((f.namespace == nil || f.namespace.Empty()) && (f.object == nil || f.object.Empty()))
}

func (f *LabelSelectorFilters) MatchObject(obj metav1.Object) bool {
	if f == nil || f.object == nil || f.object.Empty() {
		return true
	}
	return f.object.Matches(labels.Set(obj.GetLabels()))
}

// Discover routes to the appropriate discovery path based on whether the client
// has opted in to staged discovery via OPTION_STAGED_DISCOVERY.
// TODO(v15): remove discoverLegacy and OPTION_STAGED_DISCOVERY toggle. Staged
// discovery should be the only path.
func Discover(runtime *plugin.Runtime, features mql.Features) (*inventory.Inventory, error) {
	conn := runtime.Connection.(shared.Connection)
	invConfig := conn.InventoryConfig()

	// Check for staged discovery toggle
	if _, ok := invConfig.Options[plugin.OptionStagedDiscovery]; ok {
		// If a namespace is already set, we're in stage 2 (workload discovery
		// for that namespace). Otherwise it's stage 1 (cluster + namespaces).
		discoverKyverno := invConfig.Discover != nil && stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryKyverno)
		if nsName, ok := namespaceStageName(invConfig); ok && !discoverKyverno {
			return discoverNamespaceStage(runtime, conn, invConfig, features, nsName)
		}
		return discoverClusterStage(runtime, conn, invConfig, features)
	}

	// Legacy single-pass discovery (no toggle = old client)
	return discoverLegacy(runtime, conn, invConfig, features)
}

// discoverLegacy is the original single-pass discovery that discovers the cluster,
// namespaces, and all workloads in a single call. This is the default path for
// clients that do not set OPTION_STAGED_DISCOVERY.
// TODO(v15): remove this function once all clients use staged discovery.
func discoverLegacy(runtime *plugin.Runtime, conn shared.Connection, invConfig *inventory.Config, features mql.Features) (*inventory.Inventory, error) {
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	if (invConfig.Discover == nil || len(invConfig.Discover.Targets) == 0) && conn.Asset() != nil {
		in.Spec.Assets = append(in.Spec.Assets, conn.Asset())
		return in, nil
	}

	res, err := runtime.CreateResource(runtime, "k8s", nil)
	if err != nil {
		return nil, err
	}
	k8s := res.(*mqlK8s)

	nsFilter, err := setNamespaceFilters(invConfig)
	if err != nil {
		return nil, err
	}
	imgFilter, err := setImageFilters(invConfig)
	if err != nil {
		return nil, err
	}

	resFilters, err := resourceFilters(invConfig)
	if err != nil {
		return nil, err
	}

	labelFilters, err := labelSelectorFilters(invConfig)
	if err != nil {
		return nil, err
	}

	// If we can discover the cluster asset, then we use that as root and build all
	// platform IDs for the assets based on it. If we cannot discover the cluster, we
	// discover the individual namespaces according to the ns filter and then build
	// the platform IDs for the assets based on the namespace.
	discoverKyverno := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryKyverno)
	if len(nsFilter.include) == 0 && len(nsFilter.exclude) == 0 && labelFilters.IsEmpty() {
		assetId, err := conn.AssetId()
		if err == nil {
			root := &inventory.Asset{
				PlatformIds: []string{assetId},
				Name:        conn.Name(),
				Platform:    conn.Platform(),
				Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery())}, // pass-in the parent connection config
			}
			discoverCluster := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryAuto, DiscoveryAll, DiscoveryClusters) && resFilters.IsEmpty()
			if discoverCluster || discoverKyverno {
				in.Spec.Assets = append(in.Spec.Assets, root)
			}
		} else {
			log.Warn().Err(err).Msg("failed to discover cluster asset")
		}
	}
	nss, err := discoverNamespaces(conn, invConfig, "", nil, nsFilter, labelFilters)
	if err != nil {
		return nil, err
	}

	kyvernoNamespaceDiscovery := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryKyverno) && (len(nsFilter.include) > 0 || len(nsFilter.exclude) > 0)
	if resFilters.IsEmpty() {
		if kyvernoNamespaceDiscovery {
			for _, ns := range nss {
				nsConfig := invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))
				nsConfig.Options[shared.OPTION_NAMESPACE] = ns.Name
				ns.Connections = []*inventory.Config{nsConfig}
			}
		}

		if stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryNamespaces, DiscoveryAuto, DiscoveryAll) || kyvernoNamespaceDiscovery {
			in.Spec.Assets = append(in.Spec.Assets, nss...)
		}
	}

	// Discover the assets for each namespace and use the namespace platform ID as root
	for _, ns := range nss {
		// Plain namespace names always compile; ignore the impossible error.
		nsFilter, _ = newFilterOpts([]string{ns.Name}, nil)

		od := NewPlatformIdOwnershipIndex(ns.PlatformIds[0])

		// We don't want to discover the namespaces again since we have already done this above
		assets, err := discoverAssets(runtime, conn, invConfig, ns.PlatformIds[0], k8s, nsFilter, resFilters, labelFilters, od, imgFilter)
		if err != nil {
			return nil, err
		}
		setRelatedAssets(conn, ns, assets, od, features)
		in.Spec.Assets = append(in.Spec.Assets, assets...)
	}

	return in, nil
}

// discoverClusterStage is stage 1 of staged discovery: discovers the cluster
// asset and namespaces. Namespace assets are emitted WITH platform IDs (they
// are scannable) and WITH discovery targets. Each namespace's connection config
// is overridden with OPTION_NAMESPACE set, which causes stage 2 to run when
// the client connects to it. No WithParentConnectionId so each namespace gets
// its own resource cache.
func discoverClusterStage(runtime *plugin.Runtime, conn shared.Connection, invConfig *inventory.Config, features mql.Features) (*inventory.Inventory, error) {
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	if (invConfig.Discover == nil || len(invConfig.Discover.Targets) == 0) && conn.Asset() != nil {
		in.Spec.Assets = append(in.Spec.Assets, conn.Asset())
		return in, nil
	}

	nsFilter, err := setNamespaceFilters(invConfig)
	if err != nil {
		return nil, err
	}

	resFilters, err := resourceFilters(invConfig)
	if err != nil {
		return nil, err
	}

	labelFilters, err := labelSelectorFilters(invConfig)
	if err != nil {
		return nil, err
	}

	// If we can discover the cluster asset, then we use that as root and build all
	// platform IDs for the assets based on it. If we cannot discover the cluster, we
	// discover the individual namespaces according to the ns filter and then build
	// the platform IDs for the assets based on the namespace.
	discoverKyverno := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryKyverno)
	if len(nsFilter.include) == 0 && len(nsFilter.exclude) == 0 && labelFilters.IsEmpty() {
		assetId, err := conn.AssetId()
		if err == nil {
			root := &inventory.Asset{
				PlatformIds: []string{assetId},
				Name:        conn.Name(),
				Platform:    conn.Platform(),
				Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery())}, // pass-in the parent connection config
			}
			discoverCluster := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryAuto, DiscoveryAll, DiscoveryClusters) && resFilters.IsEmpty()
			if discoverCluster || discoverKyverno {
				in.Spec.Assets = append(in.Spec.Assets, root)
			}
		} else {
			log.Warn().Err(err).Msg("failed to discover cluster asset")
		}
	}

	namespaceTargets := discoveryTargetsWithout(invConfig.Discover.Targets, DiscoveryKyverno)
	if discoverKyverno && len(namespaceTargets) == 0 && len(nsFilter.include) == 0 && len(nsFilter.exclude) == 0 && labelFilters.IsEmpty() {
		return in, nil
	}

	// Discover namespaces and emit them as scannable assets with platform IDs
	// and discovery targets. Override each namespace's connection config to
	// route to stage 2 when the client connects to it later.
	nss, err := discoverNamespaces(conn, invConfig, "", nil, nsFilter, labelFilters)
	if err != nil {
		return nil, err
	}

	// Namespaces are only scannable if explicitly targeted. When they are
	// not a target, strip their platform IDs so the existing "no platform
	// IDs → skip" logic in AssetExplorer/scanner prevents them from being
	// scanned or added to the progress bar. They are still emitted so that
	// AssetExplorer connects to them (triggering stage 2 workload discovery).
	kyvernoNamespaceDiscovery := stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryKyverno) && (len(nsFilter.include) > 0 || len(nsFilter.exclude) > 0)
	nsIsScannable := stringx.ContainsAnyOf(invConfig.Discover.Targets,
		DiscoveryNamespaces, DiscoveryAuto, DiscoveryAll) || kyvernoNamespaceDiscovery

	for _, ns := range nss {
		// Clone without WithParentConnectionId so each namespace gets its own
		// resource cache. With a shared parent cache, the k8s MQL resource would
		// be created once (scoped to the first namespace's connection) and reused
		// by all other namespaces, returning stale data.
		nsConfig := invConfig.Clone() // Clone() copies Options, propagating OPTION_STAGED_DISCOVERY
		nsConfig.Options[shared.OPTION_NAMESPACE] = ns.Name
		if discoverKyverno {
			nsConfig.Discover.Targets = namespaceTargets
		}

		if !nsIsScannable {
			ns.PlatformIds = nil
		}

		// Override the connection config to route to stage 2, but keep the
		// namespace's platform, and labels from discoverNamespaces().
		ns.Connections = []*inventory.Config{nsConfig}
		in.Spec.Assets = append(in.Spec.Assets, ns)
	}

	return in, nil
}

// discoverNamespaceStage is stage 2 of staged discovery: discovers workloads
// within a single namespace. It is triggered when the client connects to a
// namespace asset emitted by stage 1.
//
// Only workloads are returned here — the namespace asset itself was already
// emitted by stage 1 with platform IDs and is already known to the client.
func discoverNamespaceStage(runtime *plugin.Runtime, conn shared.Connection, invConfig *inventory.Config, features mql.Features, nsName string) (*inventory.Inventory, error) {
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	if invConfig.Discover == nil || len(invConfig.Discover.Targets) == 0 {
		return in, nil
	}

	res, err := runtime.CreateResource(runtime, "k8s", nil)
	if err != nil {
		return nil, err
	}
	k8s := res.(*mqlK8s)

	nsFilter, _ := newFilterOpts([]string{nsName}, nil)
	imgFilter, err := setImageFilters(invConfig)
	if err != nil {
		return nil, err
	}

	resFilters, err := resourceFilters(invConfig)
	if err != nil {
		return nil, err
	}

	labelFilters, err := labelSelectorFilters(invConfig)
	if err != nil {
		return nil, err
	}

	// Resolve the namespace's platform ID for use as the ownership root
	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}
	nsObj, err := conn.Namespace(nsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace %q: %w", nsName, err)
	}
	if !labelFilters.MatchNamespace(nsObj) {
		return in, nil
	}
	namespacePlatformId := shared.NewNamespacePlatformId(basePlatformId, nsName, string(nsObj.UID))

	od := NewPlatformIdOwnershipIndex(namespacePlatformId)

	assets, err := discoverAssets(runtime, conn, invConfig, namespacePlatformId, k8s, nsFilter, resFilters, labelFilters, od, imgFilter)
	if err != nil {
		return nil, err
	}

	in.Spec.Assets = append(in.Spec.Assets, assets...)
	return in, nil
}

func discoverAssets(
	runtime *plugin.Runtime,
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	nsFilter FilterOpts,
	resFilters *ResourceFilters,
	labelFilters *LabelSelectorFilters,
	od *PlatformIdOwnershipIndex,
	imgFilter FilterOpts,
) ([]*inventory.Asset, error) {
	var assets []*inventory.Asset
	var err error
	for _, target := range invConfig.Discover.Targets {
		var list []*inventory.Asset
		if target == DiscoveryPods || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverPods(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryJobs || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverJobs(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryCronJobs || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverCronJobs(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryServices || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverServices(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryStatefulSets || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverStatefulSets(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryDeployments || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverDeployments(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryReplicaSets || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverReplicaSets(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryDaemonSets || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverDaemonSets(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryIngresses || target == DiscoveryAuto || target == DiscoveryAll {
			list, err = discoverIngresses(conn, invConfig, clusterId, k8s, od, nsFilter, resFilters, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryAdmissionReviews {
			list, err = discoverAdmissionReviews(conn, invConfig, clusterId, k8s, od, nsFilter, labelFilters)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
		if target == DiscoveryContainerImages || target == DiscoveryAll {
			list, err = discoverContainerImages(conn, runtime, invConfig, k8s, nsFilter, labelFilters, imgFilter)
			if err != nil {
				return nil, err
			}
			assets = append(assets, list...)
		}
	}
	return assets, nil
}

func discoverPods(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	pods := k8s.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("pod") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(pods.Data))
	for _, p := range pods.Data {
		pod := p.(*mqlK8sPod)

		if skip := nsFilter.skip(pod.Namespace.Data); skip {
			continue
		}

		k8sMeta, err := meta.Accessor(pod.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		if PodOwnerReferencesFilter(k8sMeta.GetOwnerReferences()) {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("pod", pod.Name.Data, pod.Namespace.Data) {
			continue
		}

		labels := map[string]string{}
		for k, v := range pod.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(pod.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "pod", pod.Namespace.Data, pod.Name.Data, pod.Uid.Data),
			},
			Name:        assetName(pod.Namespace.Data, pod.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, pod.obj)
	}
	return assetList, nil
}

func discoverJobs(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	jobs := k8s.GetJobs()
	if jobs.Error != nil {
		return nil, jobs.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("job") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(jobs.Data))
	for _, j := range jobs.Data {
		job := j.(*mqlK8sJob)

		if skip := nsFilter.skip(job.Namespace.Data); skip {
			continue
		}

		k8sMeta, err := meta.Accessor(job.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		if JobOwnerReferencesFilter(k8sMeta.GetOwnerReferences()) {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("job", job.Name.Data, job.Namespace.Data) {
			continue
		}

		labels := map[string]string{}
		for k, v := range job.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(job.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "job", job.Namespace.Data, job.Name.Data, job.Uid.Data),
			},
			Name:        assetName(job.Namespace.Data, job.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, job.obj)
	}
	return assetList, nil
}

func discoverServices(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	cjs := k8s.GetServices()
	if cjs.Error != nil {
		return nil, cjs.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("service") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(cjs.Data))
	for _, cj := range cjs.Data {
		serv := cj.(*mqlK8sService)

		if skip := nsFilter.skip(serv.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("service", serv.Name.Data, serv.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(serv.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range serv.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(serv.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "service", serv.Namespace.Data, serv.Name.Data, serv.Uid.Data),
			},
			Name:        assetName(serv.Namespace.Data, serv.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, serv.obj)
	}
	return assetList, nil
}

func discoverCronJobs(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	cjs := k8s.GetCronjobs()
	if cjs.Error != nil {
		return nil, cjs.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("cronjob") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(cjs.Data))
	for _, cj := range cjs.Data {
		cjob := cj.(*mqlK8sCronjob)

		if skip := nsFilter.skip(cjob.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("cronjob", cjob.Name.Data, cjob.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(cjob.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range cjob.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(cjob.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "cronjob", cjob.Namespace.Data, cjob.Name.Data, cjob.Uid.Data),
			},
			Name:        assetName(cjob.Namespace.Data, cjob.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, cjob.obj)
	}
	return assetList, nil
}

func discoverStatefulSets(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	ss := k8s.GetStatefulsets()
	if ss.Error != nil {
		return nil, ss.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("statefulset") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(ss.Data))
	for _, j := range ss.Data {
		statefulset := j.(*mqlK8sStatefulset)

		if skip := nsFilter.skip(statefulset.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("statefulset", statefulset.Name.Data, statefulset.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(statefulset.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range statefulset.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(statefulset.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "statefulset", statefulset.Namespace.Data, statefulset.Name.Data, statefulset.Uid.Data),
			},
			Name:        assetName(statefulset.Namespace.Data, statefulset.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, statefulset.obj)
	}
	return assetList, nil
}

func discoverDeployments(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	ds := k8s.GetDeployments()
	if ds.Error != nil {
		return nil, ds.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("deployment") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(ds.Data))
	for _, d := range ds.Data {
		deployment := d.(*mqlK8sDeployment)

		if skip := nsFilter.skip(deployment.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("deployment", deployment.Name.Data, deployment.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(deployment.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range deployment.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(deployment.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "deployment", deployment.Namespace.Data, deployment.Name.Data, deployment.Uid.Data),
			},
			Name:        assetName(deployment.Namespace.Data, deployment.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, deployment.obj)
	}
	return assetList, nil
}

func discoverReplicaSets(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	rs := k8s.GetReplicasets()
	if rs.Error != nil {
		return nil, rs.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("replicaset") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(rs.Data))
	for _, r := range rs.Data {
		replicaset := r.(*mqlK8sReplicaset)

		if skip := nsFilter.skip(replicaset.Namespace.Data); skip {
			continue
		}

		k8sMeta, err := meta.Accessor(replicaset.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		if ReplicaSetOwnerReferencesFilter(k8sMeta.GetOwnerReferences()) {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("replicaset", replicaset.Name.Data, replicaset.Namespace.Data) {
			continue
		}

		labels := map[string]string{}
		for k, v := range replicaset.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(replicaset.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "replicaset", replicaset.Namespace.Data, replicaset.Name.Data, replicaset.Uid.Data),
			},
			Name:        assetName(replicaset.Namespace.Data, replicaset.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, replicaset.obj)
	}
	return assetList, nil
}

func discoverDaemonSets(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	ds := k8s.GetDaemonsets()
	if ds.Error != nil {
		return nil, ds.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("daemonset") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(ds.Data))
	for _, d := range ds.Data {
		daemonset := d.(*mqlK8sDaemonset)

		if skip := nsFilter.skip(daemonset.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("daemonset", daemonset.Name.Data, daemonset.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(daemonset.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range daemonset.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(daemonset.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "daemonset", daemonset.Namespace.Data, daemonset.Name.Data, daemonset.Uid.Data),
			},
			Name:        assetName(daemonset.Namespace.Data, daemonset.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, daemonset.obj)
	}
	return assetList, nil
}

func discoverAdmissionReviews(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	admissionReviews, err := conn.AdmissionReviews()
	if err != nil {
		return nil, err
	}

	var assetList []*inventory.Asset
	for i := range admissionReviews {
		aReview := admissionReviews[i]

		asset, matched, err := assetFromAdmissionReview(conn, aReview, conn.Runtime(), invConfig, clusterId, nsFilter, labelFilters)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create asset from admission review")
		}
		if !matched {
			continue
		}

		log.Debug().Str("connection", asset.Connections[0].Host).Msg("resolved AdmissionReview")

		assetList = append(assetList, asset)
	}

	return assetList, nil
}

func discoverIngresses(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	k8s *mqlK8s,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	resFilter *ResourceFilters,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	is := k8s.GetIngresses()
	if is.Error != nil {
		return nil, is.Error
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	// If there is a resources filter we should only retrieve the workloads that are in the filter.
	if !resFilter.IsEmpty() && resFilter.IsEmptyForType("ingress") {
		return []*inventory.Asset{}, nil
	}

	assetList := make([]*inventory.Asset, 0, len(is.Data))
	for _, d := range is.Data {
		ingress := d.(*mqlK8sIngress)

		if skip := nsFilter.skip(ingress.Namespace.Data); skip {
			continue
		}

		if !resFilter.IsEmpty() && !resFilter.Match("ingress", ingress.Name.Data, ingress.Namespace.Data) {
			continue
		}

		k8sMeta, err := meta.Accessor(ingress.obj)
		if err != nil {
			continue
		}

		if !labelFilters.MatchObject(k8sMeta) {
			continue
		}

		labels := map[string]string{}
		for k, v := range ingress.GetLabels().Data {
			labels[k] = v.(string)
		}
		addMondooAssetLabels(labels, k8sMeta, clusterId)
		platform, err := createPlatformData(ingress.Kind.Data, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewWorkloadPlatformId(basePlatformId, clusterId, "ingress", ingress.Namespace.Data, ingress.Name.Data, ingress.Uid.Data),
			},
			Name:        assetName(ingress.Namespace.Data, ingress.Name.Data),
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		od.Add(basePlatformId, ingress.obj)
	}
	return assetList, nil
}

func discoverNamespaces(
	conn shared.Connection,
	invConfig *inventory.Config,
	clusterId string,
	od *PlatformIdOwnershipIndex,
	nsFilter FilterOpts,
	labelFilters *LabelSelectorFilters,
) ([]*inventory.Asset, error) {
	// We don't use MQL here since we need to handle k8s permission errors
	nss, err := conn.Namespaces()
	if err != nil {
		if k8sErrors.IsForbidden(err) {
			if len(nsFilter.include) > 0 {
				for _, ns := range nsFilter.include {
					n, err := conn.Namespace(ns)
					if err != nil {
						return nil, err
					}
					nss = append(nss, *n)
				}
			} else {
				return nil, errors.Wrap(err, "no permissions to list cluster namespaces, try specifying namespaces explicitly")
			}
		} else {
			return nil, errors.Wrap(err, "failed to list namespaces")
		}
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, err
	}

	assetList := make([]*inventory.Asset, 0, len(nss))
	for _, ns := range nss {
		if skip := nsFilter.skip(ns.Name); skip {
			continue
		}

		if !labelFilters.MatchNamespace(&ns) {
			continue
		}

		labels := map[string]string{}
		for k, v := range ns.Labels {
			labels[k] = v
		}
		addMondooAssetLabels(labels, &ns.ObjectMeta, clusterId)
		platform, err := createPlatformData(ns.Kind, conn.Runtime())
		if err != nil {
			return nil, err
		}
		assetList = append(assetList, &inventory.Asset{
			PlatformIds: []string{
				shared.NewNamespacePlatformId(basePlatformId, ns.Name, string(ns.UID)),
			},
			Name:        ns.Name,
			Platform:    platform,
			Labels:      labels,
			Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(invConfig.Id))}, // pass-in the parent connection config
			Category:    conn.Asset().Category,
		})
		if od != nil {
			od.Add(basePlatformId, &ns)
		}
	}
	return assetList, nil
}

func discoverContainerImages(conn shared.Connection, runtime *plugin.Runtime, invConfig *inventory.Config, k8s *mqlK8s, nsFilter FilterOpts, labelFilters *LabelSelectorFilters, imgFilter FilterOpts) ([]*inventory.Asset, error) {
	pods := k8s.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	runningImages := make(map[string]ContainerImage)
	for _, p := range pods.Data {
		pod := p.(*mqlK8sPod)

		if skip := nsFilter.skip(pod.Namespace.Data); skip {
			continue
		}

		podObj, err := pod.getPod()
		if err != nil {
			continue
		}
		if !labelFilters.MatchObject(podObj) {
			continue
		}

		podImages := UniqueImagesForPod(podObj, runtime)
		runningImages = types.MergeMaps(runningImages, podImages)
	}

	options := map[string]string{}
	if proxy, ok := invConfig.Options["container-proxy"]; ok && len(proxy) > 0 {
		options["container-proxy"] = proxy
	}
	if disableCache, ok := invConfig.Options["disable-cache"]; ok && len(disableCache) > 0 {
		options["disable-cache"] = disableCache
	}

	assetList := make([]*inventory.Asset, 0, len(runningImages))
	for _, i := range runningImages {
		if imgFilter.skip(i.resolvedImage) {
			continue
		}
		assetList = append(assetList, &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:    "registry-image",
					Host:    i.resolvedImage,
					Options: options,
				},
			},
			Category: conn.Asset().Category,
		})
	}

	return assetList, nil
}

func addMondooAssetLabels(assetLabels map[string]string, objMeta metav1.Object, clusterIdentifier string) {
	ns := objMeta.GetNamespace()
	if ns != "" {
		assetLabels["k8s.mondoo.com/namespace"] = ns
	}
	assetLabels["k8s.mondoo.com/name"] = objMeta.GetName()
	if string(objMeta.GetUID()) != "" {
		// objects discovered from manifest do not necessarily have a UID
		assetLabels["k8s.mondoo.com/uid"] = string(objMeta.GetUID())
	}
	objType, err := meta.TypeAccessor(objMeta)
	if err == nil {
		assetLabels["k8s.mondoo.com/kind"] = objType.GetKind()
		assetLabels["k8s.mondoo.com/apiVersion"] = objType.GetAPIVersion()
	}
	if objMeta.GetResourceVersion() != "" {
		// objects discovered from manifest do not necessarily have a resource version
		assetLabels["k8s.mondoo.com/resource-version"] = objMeta.GetResourceVersion()
	}
	assetLabels["k8s.mondoo.com/cluster-id"] = clusterIdentifier

	owners := objMeta.GetOwnerReferences()
	if len(owners) > 0 {
		owner := owners[0]
		assetLabels["k8s.mondoo.com/owner-kind"] = owner.Kind
		assetLabels["k8s.mondoo.com/owner-name"] = owner.Name
		assetLabels["k8s.mondoo.com/owner-uid"] = string(owner.UID)
	}
}

func assetFromAdmissionReview(conn shared.Connection, a admissionv1.AdmissionReview, runtime string, connection *inventory.Config, clusterIdentifier string, nsFilter FilterOpts, labelFilters *LabelSelectorFilters) (*inventory.Asset, bool, error) {
	// Use the meta from the request object.
	if a.Request == nil {
		return nil, false, errors.New("admission review request is nil")
	}
	if len(a.Request.Object.Raw) == 0 {
		return nil, false, errors.New("admission review request object is empty")
	}
	obj, err := resources.ResourcesFromManifest(bytes.NewReader(a.Request.Object.Raw))
	if err != nil {
		log.Error().Err(err).Msg("failed to parse object from admission review")
		return nil, false, err
	}
	if len(obj) == 0 {
		return nil, false, errors.New("admission review request object did not contain any resources")
	}
	objMeta, err := meta.Accessor(obj[0])
	if err != nil {
		log.Error().Err(err).Msg("could not access object attributes")
		return nil, false, err
	}
	objType, err := meta.TypeAccessor(obj[0])
	if err != nil {
		log.Error().Err(err).Msg("could not access object attributes")
		return nil, false, err
	}
	objNamespace := admissionReviewObjectNamespace(a, objMeta)
	if skip := nsFilter.skip(objNamespace); skip {
		return nil, false, nil
	}
	if labelFilters.HasNamespaceSelector() {
		switch {
		case objType.GetKind() == "Namespace":
			if !labelFilters.MatchNamespace(objMeta) {
				return nil, false, nil
			}
		case objNamespace != "":
			log.Warn().
				Str("namespace", objNamespace).
				Str("kind", objType.GetKind()).
				Str("object", objMeta.GetName()).
				Msg("skipping admission review object because namespace labels are unavailable for namespace-label-selector filtering")
			return nil, false, nil
		}
	}
	if !labelFilters.MatchObject(objMeta) {
		return nil, false, nil
	}

	basePlatformId, err := conn.BasePlatformId()
	if err != nil {
		return nil, false, err
	}

	objectKind := objType.GetKind()
	platformData := createAdmissionReviewObjectPlatformData(objectKind, runtime)
	platformData.Version = objType.GetAPIVersion()
	platformData.Build = objMeta.GetResourceVersion()
	platformData.Labels = map[string]string{
		"uid": string(objMeta.GetUID()),
	}

	assetLabels := objMeta.GetLabels()
	if assetLabels == nil {
		assetLabels = map[string]string{}
	}
	ns := objMeta.GetNamespace()
	var name string
	if ns != "" {
		name = ns + "/" + objMeta.GetName()
		platformData.Labels["namespace"] = ns
	} else {
		name = objMeta.GetName()
	}

	addMondooAssetLabels(assetLabels, objMeta, clusterIdentifier)

	asset := &inventory.Asset{
		PlatformIds: []string{shared.NewWorkloadPlatformId(basePlatformId, clusterIdentifier, strings.ToLower(objectKind), objMeta.GetNamespace(), objMeta.GetName(), string(objMeta.GetUID()))},
		Name:        name,
		Platform:    platformData,
		Connections: []*inventory.Config{connection},
		State:       inventory.State_STATE_ONLINE,
		Labels:      assetLabels,
		Category:    conn.Asset().Category,
	}

	return asset, true, nil
}

func createAdmissionReviewObjectPlatformData(objectKind, runtime string) *inventory.Platform {
	platformData, err := createPlatformData(objectKind, runtime)
	if err == nil {
		return platformData
	}

	platformName := "k8s-object"
	return &inventory.Platform{
		Family:                []string{"k8s"},
		Kind:                  "k8s-object",
		Runtime:               runtime,
		Name:                  platformName,
		Title:                 "Kubernetes " + objectKind,
		TechnologyUrlSegments: []string{"k8s", platformName},
	}
}

func admissionReviewObjectNamespace(a admissionv1.AdmissionReview, objMeta metav1.Object) string {
	if objMeta != nil && objMeta.GetNamespace() != "" {
		return objMeta.GetNamespace()
	}
	if a.Request != nil {
		return a.Request.Namespace
	}
	return ""
}

func createPlatformData(objectKind, runtime string) (*inventory.Platform, error) {
	platformData := &inventory.Platform{
		Family:  []string{"k8s"},
		Kind:    "k8s-object",
		Runtime: runtime,
	}

	switch objectKind {
	case "Node":
		platformData.Name = "k8s-node"
		platformData.Title = "Kubernetes Node"
	case "Pod":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-pod"
		platformData.Title = "Kubernetes Pod"
	case "CronJob":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-cronjob"
		platformData.Title = "Kubernetes CronJob"
	case "StatefulSet":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-statefulset"
		platformData.Title = "Kubernetes StatefulSet"
	case "Deployment":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-deployment"
		platformData.Title = "Kubernetes Deployment"
	case "Job":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-job"
		platformData.Title = "Kubernetes Job"
	case "ReplicaSet":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-replicaset"
		platformData.Title = "Kubernetes ReplicaSet"
	case "DaemonSet":
		platformData.Family = append(platformData.Family, "k8s-workload")
		platformData.Name = "k8s-daemonset"
		platformData.Title = "Kubernetes DaemonSet"
	case "AdmissionReview":
		platformData.Family = append(platformData.Family, "k8s-admission")
		platformData.Name = "k8s-admission"
		platformData.Title = "Kubernetes Admission Review"
	case "Ingress":
		platformData.Family = append(platformData.Family, "k8s-ingress")
		platformData.Name = "k8s-ingress"
		platformData.Title = "Kubernetes Ingress"
	case "Service":
		platformData.Family = append(platformData.Family, "k8s-service")
		platformData.Name = "k8s-service"
		platformData.Title = "Kubernetes Service"
	case "Namespace":
		platformData.Family = append(platformData.Family, "k8s-namespace")
		platformData.Name = "k8s-namespace"
		platformData.Title = "Kubernetes Namespace"
	default:
		return nil, fmt.Errorf("could not determine object kind %s", objectKind)
	}

	platformData.TechnologyUrlSegments = []string{"k8s", platformData.Name}

	return platformData, nil
}

func setRelatedAssets(conn shared.Connection, root *inventory.Asset, assets []*inventory.Asset, od *PlatformIdOwnershipIndex, features mql.Features) {
	// everything is connected to the root asset
	root.RelatedAssets = append(root.RelatedAssets, assets...)

	// build a lookup on the k8s uid to look up individual assets to link
	platformIdToAssetMap := map[string]*inventory.Asset{}
	for _, a := range assets {
		for _, platformId := range a.PlatformIds {
			platformIdToAssetMap[platformId] = a
		}
	}

	for id, a := range platformIdToAssetMap {
		ownedBy := od.OwnedBy(id)
		for _, ownerPlatformId := range ownedBy {
			if aa, ok := platformIdToAssetMap[ownerPlatformId]; ok {
				a.RelatedAssets = append(a.RelatedAssets, aa)
			} else {
				// If the owner object is not scanned we can still add an asset as we know most of the information
				// from the ownerReference field
				if platformEntry, ok := od.GetKubernetesObjectData(ownerPlatformId); ok {
					platformData, err := createPlatformData(platformEntry.Kind, conn.Runtime())
					if err != nil || (!features.IsActive(mql.K8sNodeDiscovery) && platformData.Name == "k8s-node") {
						continue
					}
					a.RelatedAssets = append(a.RelatedAssets, &inventory.Asset{
						PlatformIds: []string{ownerPlatformId},
						Platform:    platformData,
						Name:        assetName(platformEntry.Namespace, platformEntry.Name),
					})
				}
			}
		}
	}
}

type K8sResourceIdentifier struct {
	Type      string
	Namespace string
	Name      string
}

type ResourceFilters struct {
	identifiers map[string][]K8sResourceIdentifier
}

func (f *ResourceFilters) IsEmpty() bool {
	return len(f.identifiers) == 0
}

func (f *ResourceFilters) IsEmptyForType(resourceType string) bool {
	return len(f.identifiers[resourceType]) == 0
}

func (f *ResourceFilters) Match(typ, name, namespace string) bool {
	for _, res := range f.identifiers[typ] {
		if res.Name == name && res.Namespace == namespace {
			return true
		}
	}

	// If the filter isn't matching we skip
	return false
}

// resourceFilters parses the resource filters from the provider config
func resourceFilters(cfg *inventory.Config) (*ResourceFilters, error) {
	resourcesFilter := &ResourceFilters{identifiers: make(map[string][]K8sResourceIdentifier)}
	if fOpt, ok := cfg.Options["k8s-resources"]; ok {
		fs := strings.Split(fOpt, ",")
		for _, f := range fs {
			ids := strings.Split(strings.TrimSpace(f), ":")
			resType := ids[0]
			var ns, name string
			if _, ok := resourcesFilter.identifiers[resType]; !ok {
				resourcesFilter.identifiers[resType] = []K8sResourceIdentifier{}
			}

			switch len(ids) {
			case 3:
				// Namespaced resources have the format type:ns:name
				ns = ids[1]
				name = ids[2]
			case 2:
				// Non-namespaced resources have the format type:name
				name = ids[1]
			default:
				return nil, fmt.Errorf("invalid k8s resource filter: %s", f)
			}

			resourcesFilter.identifiers[resType] = append(
				resourcesFilter.identifiers[resType],
				K8sResourceIdentifier{Type: resType, Namespace: ns, Name: name},
			)
		}
	}
	return resourcesFilter, nil
}

func setImageFilters(cfg *inventory.Config) (FilterOpts, error) {
	includeVals := splitFilterValues(cfg.Options[shared.OPTION_IMAGES])
	excludeVals := splitFilterValues(cfg.Options[shared.OPTION_IMAGES_EXCLUDE])
	if len(includeVals) > 0 && len(excludeVals) > 0 {
		return FilterOpts{}, fmt.Errorf("--images and --images-exclude are mutually exclusive")
	}
	return newFilterOpts(includeVals, excludeVals)
}

func labelSelectorFilters(cfg *inventory.Config) (*LabelSelectorFilters, error) {
	filters := &LabelSelectorFilters{
		namespace: labels.Everything(),
		object:    labels.Everything(),
	}

	if raw, ok := cfg.Options[shared.OPTION_NAMESPACE_LABEL_SELECTOR]; ok {
		selector, err := parseLabelSelectorOption(shared.OPTION_NAMESPACE_LABEL_SELECTOR, raw)
		if err != nil {
			return nil, err
		}
		filters.namespace = selector
	}

	if raw, ok := cfg.Options[shared.OPTION_OBJECT_LABEL_SELECTOR]; ok {
		selector, err := parseLabelSelectorOption(shared.OPTION_OBJECT_LABEL_SELECTOR, raw)
		if err != nil {
			return nil, err
		}
		filters.object = selector
	}

	return filters, nil
}

func parseLabelSelectorOption(option, raw string) (labels.Selector, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return labels.Everything(), nil
	}

	selector, err := labels.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s label selector: %w", option, err)
	}
	return selector, nil
}

func setNamespaceFilters(cfg *inventory.Config) (FilterOpts, error) {
	return newFilterOpts(
		splitFilterValues(cfg.Options[shared.OPTION_NAMESPACE]),
		splitFilterValues(cfg.Options[shared.OPTION_NAMESPACE_EXCLUDE]),
	)
}

func newFilterOpts(include, exclude []string) (FilterOpts, error) {
	if err := validateGlobs(include); err != nil {
		return FilterOpts{}, err
	}
	if err := validateGlobs(exclude); err != nil {
		return FilterOpts{}, err
	}
	return FilterOpts{include: include, exclude: exclude}, nil
}

// namespaceStageName returns a namespace only when the config targets exactly
// one namespace, which indicates staged discovery should run the namespace stage.
// Empty, multi-namespace, or wildcard filters fall through to cluster-stage discovery.
func namespaceStageName(cfg *inventory.Config) (string, bool) {
	namespaces := splitFilterValues(cfg.Options[shared.OPTION_NAMESPACE])
	if len(namespaces) != 1 || strings.ContainsAny(namespaces[0], `*?[]{}\`) {
		return "", false
	}
	return namespaces[0], true
}

func discoveryTargetsWithout(targets []string, excluded string) []string {
	res := make([]string, 0, len(targets))
	for _, target := range targets {
		if target != excluded {
			res = append(res, target)
		}
	}
	return res
}

func splitFilterValues(value string) []string {
	values := strings.Split(value, ",")
	res := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			res = append(res, value)
		}
	}
	return res
}

func assetName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func OwnerReferencesFilter(refs []metav1.OwnerReference, filter ...string) bool {
	if len(refs) == 0 {
		return false
	}

	for _, ref := range refs {
		if stringx.Contains(filter, ref.Kind) {
			return true
		}
	}

	return false
}

func PodOwnerReferencesFilter(refs []metav1.OwnerReference) bool {
	return OwnerReferencesFilter(refs, "DaemonSet", "StatefulSet", "ReplicaSet", "Job")
}

func JobOwnerReferencesFilter(refs []metav1.OwnerReference) bool {
	return OwnerReferencesFilter(refs, "CronJob")
}

func ReplicaSetOwnerReferencesFilter(refs []metav1.OwnerReference) bool {
	return OwnerReferencesFilter(refs, "Deployment")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/providers/os/id/containerid"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
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
	DiscoveryRuntimeCache     = "runtime-cache-images"
	DiscoveryAdmissionReviews = "admissionreviews"
	DiscoveryIngresses        = "ingresses"
	DiscoveryNamespaces       = "namespaces"
	DiscoveryServices         = "services"
)

const (
	runtimeCacheOptionNodeName      = "runtime-cache-node-name"
	runtimeCacheOptionDelegatesFile = "runtime-cache-delegates-file"
	runtimeCacheOptionAllowPull     = "runtime-cache-allow-pull"
	runtimeCacheOptionScanOnlyInUse = "runtime-cache-scan-only-in-use"
	runtimeCacheOptionScannerPods   = "runtime-cache-scanner-pod-selector"

	runtimeImageConnectionType           = "runtime-image"
	runtimeImageOptionRef                = "runtime-cache-image-ref"
	runtimeImageOptionDigest             = "runtime-cache-image-digest"
	runtimeImageOptionKind               = "runtime-cache-kind"
	runtimeImageOptionDelegateID         = "runtime-cache-delegate-id"
	runtimeImageOptionDelegateCandidates = "runtime-cache-delegate-candidates"
	runtimeImageOptionEndpoint           = "runtime-cache-endpoint"
	runtimeImageOptionNamespaces         = "runtime-cache-namespaces"
	runtimeImageOptionAllowPull          = "runtime-cache-allow-pull"
	runtimeImageOptionMaxLayerReaders    = "runtime-cache-max-concurrent-layer-io"
	runtimeImageOptionMaxConcurrentImage = "runtime-cache-max-concurrent-images"
)

type runtimeCacheDelegatesFile struct {
	RuntimeImageCache runtimeCacheSettings `json:"runtimeImageCache"`
}

type runtimeCacheSettings struct {
	AllowPull                 bool                   `json:"allowPull"`
	ScanOnlyInUse             bool                   `json:"scanOnlyInUse"`
	MaxConcurrentImageScans   int                    `json:"maxConcurrentImageScans"`
	MaxConcurrentLayerReaders int                    `json:"maxConcurrentLayerReaders"`
	Delegates                 []runtimeCacheDelegate `json:"delegates"`
}

type runtimeCacheDelegate struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Endpoint   string   `json:"endpoint"`
	Priority   int      `json:"priority"`
	Namespaces []string `json:"namespaces"`
	ReadOnly   bool     `json:"readonly"`
}

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
		if nsName, ok := namespaceStageName(invConfig); ok {
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
	if len(nsFilter.include) == 0 && len(nsFilter.exclude) == 0 && labelFilters.IsEmpty() {
		assetId, err := conn.AssetId()
		if err == nil {
			root := &inventory.Asset{
				PlatformIds: []string{assetId},
				Name:        conn.Name(),
				Platform:    conn.Platform(),
				Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery())}, // pass-in the parent connection config
			}
			if stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryAuto, DiscoveryAll, DiscoveryClusters) && resFilters.IsEmpty() {
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

	if resFilters.IsEmpty() && stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryNamespaces, DiscoveryAuto, DiscoveryAll) {
		in.Spec.Assets = append(in.Spec.Assets, nss...)
	}

	legacyTargets := invConfig.Discover.Targets
	if stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryRuntimeCache) {
		assets, err := discoverRuntimeCacheImages(conn, invConfig, k8s, nsFilter)
		if err != nil {
			return nil, err
		}
		in.Spec.Assets = append(in.Spec.Assets, assets...)
		legacyTargets = namespaceStageDiscoveryTargets(invConfig.Discover.Targets)
		if len(legacyTargets) == 0 {
			return in, nil
		}
	}

	assetInvConfig := invConfig
	if len(legacyTargets) != len(invConfig.Discover.Targets) {
		assetInvConfig = invConfig.Clone()
		assetInvConfig.Discover = &inventory.Discovery{Targets: legacyTargets}
	}

	// Discover the assets for each namespace and use the namespace platform ID as root
	for _, ns := range nss {
		// Plain namespace names always compile; ignore the impossible error.
		nsFilter, _ = newFilterOpts([]string{ns.Name}, nil)

		od := NewPlatformIdOwnershipIndex(ns.PlatformIds[0])

		// We don't want to discover the namespaces again since we have already done this above
		assets, err := discoverAssets(runtime, conn, assetInvConfig, ns.PlatformIds[0], k8s, nsFilter, resFilters, labelFilters, od, imgFilter)
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
	if len(nsFilter.include) == 0 && len(nsFilter.exclude) == 0 && labelFilters.IsEmpty() {
		assetId, err := conn.AssetId()
		if err == nil {
			root := &inventory.Asset{
				PlatformIds: []string{assetId},
				Name:        conn.Name(),
				Platform:    conn.Platform(),
				Connections: []*inventory.Config{invConfig.Clone(inventory.WithoutDiscovery())}, // pass-in the parent connection config
			}
			if stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryAuto, DiscoveryAll, DiscoveryClusters) && resFilters.IsEmpty() {
				in.Spec.Assets = append(in.Spec.Assets, root)
			}
		} else {
			log.Warn().Err(err).Msg("failed to discover cluster asset")
		}
	}

	namespaceTargets := namespaceStageDiscoveryTargets(invConfig.Discover.Targets)
	if stringx.ContainsAnyOf(invConfig.Discover.Targets, DiscoveryRuntimeCache) {
		res, err := runtime.CreateResource(runtime, "k8s", nil)
		if err != nil {
			return nil, err
		}
		k8s := res.(*mqlK8s)
		assets, err := discoverRuntimeCacheImages(conn, invConfig, k8s, nsFilter)
		if err != nil {
			return nil, err
		}
		in.Spec.Assets = append(in.Spec.Assets, assets...)
	}
	if len(namespaceTargets) == 0 {
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
	nsIsScannable := stringx.ContainsAnyOf(namespaceTargets,
		DiscoveryNamespaces, DiscoveryAuto, DiscoveryAll)

	for _, ns := range nss {
		// Clone without WithParentConnectionId so each namespace gets its own
		// resource cache. With a shared parent cache, the k8s MQL resource would
		// be created once (scoped to the first namespace's connection) and reused
		// by all other namespaces, returning stale data.
		nsConfig := invConfig.Clone() // Clone() copies Options, propagating OPTION_STAGED_DISCOVERY
		nsConfig.Discover = &inventory.Discovery{Targets: namespaceTargets}
		nsConfig.Options[shared.OPTION_NAMESPACE] = ns.Name

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

func namespaceStageDiscoveryTargets(targets []string) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == DiscoveryRuntimeCache {
			continue
		}
		out = append(out, target)
	}
	return out
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
		if target == DiscoveryRuntimeCache {
			list, err = discoverRuntimeCacheImages(conn, invConfig, k8s, nsFilter)
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

func discoverRuntimeCacheImages(conn shared.Connection, invConfig *inventory.Config, k8s *mqlK8s, nsFilter FilterOpts) ([]*inventory.Asset, error) {
	nodeName, err := runtimeCacheResolveInventoryTemplateOption(invConfig.Options[runtimeCacheOptionNodeName])
	if err != nil {
		return nil, fmt.Errorf("failed to render %s: %w", runtimeCacheOptionNodeName, err)
	}
	if nodeName == "" {
		return nil, fmt.Errorf("%s is required for %s discovery", runtimeCacheOptionNodeName, DiscoveryRuntimeCache)
	}

	settings, err := loadRuntimeCacheSettings(invConfig)
	if err != nil {
		return nil, err
	}
	if runtimeCacheBoolOption(invConfig, runtimeCacheOptionAllowPull, settings.AllowPull) {
		return nil, fmt.Errorf("%s discovery does not support registry pulls", DiscoveryRuntimeCache)
	}
	if !runtimeCacheBoolOption(invConfig, runtimeCacheOptionScanOnlyInUse, settings.ScanOnlyInUse) {
		return nil, fmt.Errorf("%s discovery currently supports in-use images only", DiscoveryRuntimeCache)
	}

	delegates := runtimeCacheDelegatesByKind(settings.Delegates)
	if len(delegates["containerd"]) == 0 {
		return nil, fmt.Errorf("%s discovery requires at least one containerd delegate", DiscoveryRuntimeCache)
	}

	pods := k8s.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	podObjects := make([]*corev1.Pod, 0, len(pods.Data))
	for _, p := range pods.Data {
		pod := p.(*mqlK8sPod)
		podObj, err := pod.getPod()
		if err != nil {
			continue
		}
		podObjects = append(podObjects, podObj)
	}
	activeScannerNodes, scannerNodesConstrained, err := runtimeCacheActiveScannerNodeNames(podObjects, invConfig.Options[runtimeCacheOptionScannerPods])
	if err != nil {
		return nil, err
	}

	type imageAsset struct {
		ref                string
		digest             string
		nodeName           string
		delegate           runtimeCacheDelegate
		delegateCandidates []runtimeCacheDelegate
		ownerKey           string
		containers         map[string]struct{}
		namespaces         map[string]struct{}
		nodes              map[string]struct{}
		delegates          map[string]struct{}
	}

	byImage := map[string]*imageAsset{}
	for _, podObj := range podObjects {
		if skip := nsFilter.skip(podObj.Namespace); skip {
			continue
		}
		if strings.TrimSpace(podObj.Spec.NodeName) == "" {
			continue
		}
		if !runtimeCachePodEligibleForRuntimeCacheNode(podObj.Spec.NodeName, nodeName, activeScannerNodes, scannerNodesConstrained) {
			continue
		}

		for _, status := range runtimeCacheContainerStatuses(podObj) {
			if strings.TrimSpace(status.ContainerID) == "" {
				continue
			}
			ref, digest := runtimeCacheImageReference(status)
			if ref == "" {
				continue
			}
			delegateCandidates := runtimeCacheDelegatesForStatus(delegates, status)
			if len(delegateCandidates) == 0 {
				continue
			}
			delegate := delegateCandidates[0]
			key := runtimeCacheImageDedupeKey(podObj.Spec.NodeName, delegate.ID, ref, digest)
			ownerKey := runtimeCacheImageOwnerKey(podObj.Spec.NodeName, delegate.ID, ref)
			entry := byImage[key]
			if entry == nil {
				entry = &imageAsset{
					ref:                ref,
					digest:             digest,
					nodeName:           podObj.Spec.NodeName,
					delegate:           delegate,
					delegateCandidates: delegateCandidates,
					ownerKey:           ownerKey,
					containers:         map[string]struct{}{},
					namespaces:         map[string]struct{}{},
					nodes:              map[string]struct{}{},
					delegates:          map[string]struct{}{},
				}
				byImage[key] = entry
			} else if ownerKey < entry.ownerKey {
				entry.ref = ref
				entry.digest = digest
				entry.nodeName = podObj.Spec.NodeName
				entry.delegate = delegate
				entry.delegateCandidates = delegateCandidates
				entry.ownerKey = ownerKey
			} else if runtimeCacheStringEqual(ownerKey, entry.ownerKey) && len(digest) > 0 && (len(entry.digest) == 0 || ref < entry.ref) {
				entry.ref = ref
				entry.digest = digest
			}
			if status.ContainerID != "" {
				entry.containers[status.ContainerID] = struct{}{}
			}
			if podObj.Namespace != "" {
				entry.namespaces[podObj.Namespace] = struct{}{}
			}
			entry.nodes[podObj.Spec.NodeName] = struct{}{}
			for _, candidate := range delegateCandidates {
				entry.delegates[candidate.ID] = struct{}{}
			}
		}
	}

	keys := make([]string, 0, len(byImage))
	for key := range byImage {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assetList := make([]*inventory.Asset, 0, len(keys))
	for _, key := range keys {
		img := byImage[key]
		if img.nodeName != nodeName {
			continue
		}
		options := map[string]string{
			runtimeImageOptionRef:           img.ref,
			runtimeImageOptionDigest:        img.digest,
			runtimeImageOptionKind:          img.delegate.Kind,
			runtimeImageOptionDelegateID:    img.delegate.ID,
			runtimeImageOptionEndpoint:      img.delegate.Endpoint,
			runtimeImageOptionNamespaces:    strings.Join(img.delegate.Namespaces, ","),
			runtimeImageOptionAllowPull:     "false",
			runtimeCacheOptionNodeName:      nodeName,
			runtimeCacheOptionScanOnlyInUse: "true",
		}
		runtimeCacheApplyConcurrencyOptions(options, settings, invConfig.Options)
		if len(img.delegateCandidates) > 1 {
			raw, err := json.Marshal(img.delegateCandidates)
			if err != nil {
				return nil, err
			}
			options[runtimeImageOptionDelegateCandidates] = string(raw)
		}
		if disableCache := invConfig.Options["disable-cache"]; disableCache != "" {
			options["disable-cache"] = disableCache
		}

		labels := map[string]string{
			"mondoo.com/scan":                     "runtime-cache",
			"mondoo.com/runtime-image-ref":        img.ref,
			"mondoo.com/runtime-cache-owner-node": img.nodeName,
			"k8s.mondoo.com/node":                 img.nodeName,
		}
		if img.digest != "" {
			labels["mondoo.com/runtime-image-digest"] = img.digest
		}

		var category inventory.AssetCategory
		if conn.Asset() != nil {
			category = conn.Asset().Category
		}
		asset := &inventory.Asset{
			Name: runtimeCacheImageAssetName(img.nodeName, img.ref, img.digest),
			Connections: []*inventory.Config{
				{
					Type:    runtimeImageConnectionType,
					Host:    img.ref,
					Options: options,
				},
			},
			Category: category,
			Labels:   labels,
			Annotations: map[string]string{
				"mondoo.com/runtime-cache-containers": strings.Join(sortedStringSet(img.containers), ","),
				"mondoo.com/runtime-cache-namespaces": strings.Join(sortedStringSet(img.namespaces), ","),
				"mondoo.com/runtime-cache-nodes":      strings.Join(sortedStringSet(img.nodes), ","),
				"mondoo.com/runtime-cache-delegates":  strings.Join(sortedStringSet(img.delegates), ","),
			},
		}
		if img.digest != "" {
			asset.PlatformIds = []string{containerid.MondooContainerImageID(img.digest)}
		}
		assetList = append(assetList, asset)
	}

	return assetList, nil
}

func runtimeCacheApplyConcurrencyOptions(options map[string]string, settings *runtimeCacheSettings, invOptions map[string]string) {
	if settings != nil && settings.MaxConcurrentLayerReaders > 0 {
		options[runtimeImageOptionMaxLayerReaders] = strconv.Itoa(settings.MaxConcurrentLayerReaders)
	} else if maxLayerReaders := invOptions[runtimeImageOptionMaxLayerReaders]; maxLayerReaders != "" {
		options[runtimeImageOptionMaxLayerReaders] = maxLayerReaders
	}
	if settings != nil && settings.MaxConcurrentImageScans > 0 {
		options[runtimeImageOptionMaxConcurrentImage] = strconv.Itoa(settings.MaxConcurrentImageScans)
	} else if maxImages := invOptions[runtimeImageOptionMaxConcurrentImage]; maxImages != "" {
		options[runtimeImageOptionMaxConcurrentImage] = maxImages
	}
}

func runtimeCacheImageDedupeKey(nodeName, delegateID, ref, digest string) string {
	identity := strings.TrimSpace(digest)
	if identity != "" {
		return strings.Join([]string{"digest", identity}, "\x00")
	}
	return strings.Join([]string{"ref", strings.TrimSpace(nodeName), strings.TrimSpace(delegateID), strings.TrimSpace(ref)}, "\x00")
}

func runtimeCacheImageOwnerKey(nodeName, delegateID, ref string) string {
	return strings.Join([]string{strings.TrimSpace(nodeName), strings.TrimSpace(delegateID), strings.TrimSpace(ref)}, "\x00")
}

func runtimeCacheImageAssetName(nodeName, ref, digest string) string {
	if strings.TrimSpace(digest) != "" {
		return fmt.Sprintf("%s@%s", ref, containerid.ShortContainerImageID(digest))
	}
	return fmt.Sprintf("%s/%s", nodeName, ref)
}

func runtimeCacheStringEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func runtimeCacheActiveScannerNodeNames(pods []*corev1.Pod, selector string) (map[string]struct{}, bool, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, false, nil
	}
	required, err := labels.Parse(selector)
	if err != nil {
		return nil, false, fmt.Errorf("invalid %s %q: %w", runtimeCacheOptionScannerPods, selector, err)
	}

	active := map[string]struct{}{}
	for _, pod := range pods {
		if pod == nil || strings.TrimSpace(pod.Spec.NodeName) == "" {
			continue
		}
		if !runtimeCacheScannerPodIsActive(pod) {
			continue
		}
		if required.Matches(labels.Set(pod.Labels)) {
			active[pod.Spec.NodeName] = struct{}{}
		}
	}
	if len(active) == 0 {
		return nil, false, nil
	}
	return active, true, nil
}

func runtimeCachePodEligibleForRuntimeCacheNode(podNodeName, currentNodeName string, scannerNodes map[string]struct{}, scannerNodesConstrained bool) bool {
	podNodeName = strings.TrimSpace(podNodeName)
	if podNodeName == "" {
		return false
	}
	if scannerNodesConstrained {
		_, ok := scannerNodes[podNodeName]
		return ok
	}
	return podNodeName == strings.TrimSpace(currentNodeName)
}

func runtimeCacheScannerPodIsActive(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func loadRuntimeCacheSettings(invConfig *inventory.Config) (*runtimeCacheSettings, error) {
	path := strings.TrimSpace(invConfig.Options[runtimeCacheOptionDelegatesFile])
	if path == "" {
		return nil, fmt.Errorf("%s is required for %s discovery", runtimeCacheOptionDelegatesFile, DiscoveryRuntimeCache)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read runtime cache delegates file %q: %w", path, err)
	}
	var cfg runtimeCacheDelegatesFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse runtime cache delegates file %q: %w", path, err)
	}
	if len(cfg.RuntimeImageCache.Delegates) == 0 {
		return nil, fmt.Errorf("runtime cache delegates file %q does not define delegates", path)
	}
	return &cfg.RuntimeImageCache, nil
}

func runtimeCacheSettingsFromRuntime(rt *plugin.Runtime) (*runtimeCacheSettings, error) {
	if rt == nil || rt.Connection == nil {
		return nil, nil
	}
	conn, ok := rt.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil {
		return nil, nil
	}
	for _, cfg := range conn.Asset().Connections {
		if cfg == nil || cfg.Options == nil {
			continue
		}
		if strings.TrimSpace(cfg.Options[runtimeCacheOptionDelegatesFile]) == "" {
			continue
		}
		return loadRuntimeCacheSettings(cfg)
	}
	return nil, nil
}

func runtimeCacheBoolOption(invConfig *inventory.Config, key string, fallback bool) bool {
	raw := strings.TrimSpace(invConfig.Options[key])
	if raw == "" {
		return fallback
	}
	return strings.EqualFold(raw, "true")
}

func runtimeCacheResolveInventoryTemplateOption(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "{{") {
		return value, nil
	}

	tpl, err := template.New("runtime-cache-option").Funcs(template.FuncMap{
		"getenv": os.Getenv,
	}).Parse(value)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	if err := tpl.Execute(&out, nil); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func runtimeCacheDelegatesByKind(delegates []runtimeCacheDelegate) map[string][]runtimeCacheDelegate {
	byKind := map[string][]runtimeCacheDelegate{}
	for _, delegate := range delegates {
		delegate.Kind = strings.TrimSpace(delegate.Kind)
		delegate.Endpoint = strings.TrimSpace(delegate.Endpoint)
		if delegate.Kind == "" || delegate.Endpoint == "" || !delegate.ReadOnly {
			continue
		}
		if delegate.ID == "" {
			delegate.ID = delegate.Kind
		}
		if len(delegate.Namespaces) == 0 {
			delegate.Namespaces = []string{"k8s.io"}
		}
		byKind[delegate.Kind] = append(byKind[delegate.Kind], delegate)
	}
	for kind := range byKind {
		sort.SliceStable(byKind[kind], func(i, j int) bool {
			if byKind[kind][i].Priority == byKind[kind][j].Priority {
				return byKind[kind][i].ID < byKind[kind][j].ID
			}
			return byKind[kind][i].Priority < byKind[kind][j].Priority
		})
	}
	return byKind
}

func runtimeCacheContainerStatuses(pod *corev1.Pod) []corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	out := make([]corev1.ContainerStatus, 0,
		len(pod.Status.InitContainerStatuses)+len(pod.Status.ContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	out = append(out, pod.Status.InitContainerStatuses...)
	out = append(out, pod.Status.ContainerStatuses...)
	out = append(out, pod.Status.EphemeralContainerStatuses...)
	return out
}

func runtimeCacheImageReference(status corev1.ContainerStatus) (string, string) {
	var digest string
	if strings.Contains(status.ImageID, "@sha256:") {
		digest = normalizeRuntimeImageID(status.ImageID)
		if !strings.HasPrefix(digest, "sha256:") {
			digest = ""
		}
	}
	ref := strings.TrimSpace(status.Image)
	if ref == "" {
		ref = digest
		if ref == "" {
			ref = normalizeRuntimeImageID(status.ImageID)
		}
	}
	return ref, digest
}

func runtimeCacheDelegateForStatus(delegates map[string][]runtimeCacheDelegate, status corev1.ContainerStatus) (runtimeCacheDelegate, bool) {
	items := runtimeCacheDelegatesForStatus(delegates, status)
	if len(items) == 0 {
		return runtimeCacheDelegate{}, false
	}
	return items[0], true
}

func runtimeCacheDelegatesForStatus(delegates map[string][]runtimeCacheDelegate, status corev1.ContainerStatus) []runtimeCacheDelegate {
	kind := runtimeKindFromContainerID(status.ContainerID)
	if kind == "" {
		return nil
	}
	items := delegates[kind]
	if len(items) == 0 {
		return nil
	}
	return items
}

func sortedStringSet(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for v := range in {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
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
// Empty or multi-namespace filters fall through to cluster-stage discovery.
func namespaceStageName(cfg *inventory.Config) (string, bool) {
	namespaces := splitFilterValues(cfg.Options[shared.OPTION_NAMESPACE])
	if len(namespaces) != 1 {
		return "", false
	}
	return namespaces[0], true
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

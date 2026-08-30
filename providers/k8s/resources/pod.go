// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sPodInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sPod) getPod() (*corev1.Pod, error) {
	p, ok := k.obj.(*corev1.Pod)
	if ok {
		return p, nil
	}
	return nil, errors.New("invalid k8s pod")
}

func (k *mqlK8s) pods() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("pods")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.pod", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"apiVersion":      llx.StringData(objT.GetAPIVersion()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sPod).obj = resource
		return r, nil
	})
}

func (k *mqlK8sPod) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sPod) podSpec() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	podSpec, err := resources.GetPodSpec(pod)
	if err != nil {
		return nil, err
	}
	dict, err := convert.JsonToDict(podSpec)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (k *mqlK8sPod) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sPod(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sPod](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPods() })
}

func (k *mqlK8sPod) initContainers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sPod) ephemeralContainers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, EphemeralContainerType)
}

func (k *mqlK8sPod) containers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sPod) containerStatuses() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}

	return containerStatusResources(k.MqlRuntime, pod, pod.Status.ContainerStatuses, "containerstatus")
}

func (k *mqlK8sPod) initContainerStatuses() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}

	return containerStatusResources(k.MqlRuntime, pod, pod.Status.InitContainerStatuses, "initcontainerstatus")
}

func (k *mqlK8sPod) ephemeralContainerStatuses() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}

	return containerStatusResources(k.MqlRuntime, pod, pod.Status.EphemeralContainerStatuses, "ephemeralcontainerstatus")
}

func containerStatusResources(runtime *plugin.Runtime, pod *corev1.Pod, statuses []corev1.ContainerStatus, idPart string) ([]any, error) {
	resp := []any{}
	for _, c := range statuses {
		state, err := convert.JsonToDict(c.State)
		if err != nil {
			return nil, err
		}
		lastState, err := convert.JsonToDict(c.LastTerminationState)
		if err != nil {
			return nil, err
		}
		statusResources, err := convert.JsonToDict(c.Resources)
		if err != nil {
			return nil, err
		}
		started := false
		if c.Started != nil {
			started = *c.Started
		}

		args := map[string]*llx.RawData{
			"__id":         llx.StringData(string(pod.GetUID()) + "-" + idPart + "-" + c.Name),
			"name":         llx.StringData(c.Name),
			"ready":        llx.BoolData(c.Ready),
			"started":      llx.BoolData(started),
			"restartCount": llx.IntData(int64(c.RestartCount)),
			"image":        llx.StringData(c.Image),
			"imageId":      llx.StringData(c.ImageID),
			"containerId":  llx.StringData(c.ContainerID),
			"state":        llx.DictData(state),
			"lastState":    llx.DictData(lastState),
			"resources":    llx.DictData(statusResources),
		}
		mqlContainer, err := CreateResource(runtime, ResourceK8sContainerStatus, args)
		if err != nil {
			return nil, err
		}
		resp = append(resp, mqlContainer)
	}
	return resp, nil
}

func (k *mqlK8sContainerStatus) runtimeImage() (plugin.Resource, error) {
	status, matches, err := k.runtimeImageStatusAndMatches()
	if err != nil {
		return nil, err
	}
	if status != "matched" {
		k.RuntimeImage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return matches[0], nil
}

func (k *mqlK8sContainerStatus) runtimeImageStatus() (string, error) {
	status, _, err := k.runtimeImageStatusAndMatches()
	return status, err
}

func (k *mqlK8sContainerStatus) runtimeImageStatusAndMatches() (string, []plugin.Resource, error) {
	if k.ImageId.Data == "" && k.Image.Data == "" {
		return "notPresent", nil, nil
	}
	matches, runtimeAvailable, err := k.runtimeImageMatches()
	if err != nil {
		return "", nil, err
	}
	if !runtimeAvailable {
		return "runtimeUnavailable", nil, nil
	}
	switch len(matches) {
	case 0:
		return "notPresent", nil, nil
	case 1:
		return "matched", matches, nil
	default:
		return "ambiguous", matches, nil
	}
}

func (k *mqlK8sContainerStatus) runtimeImageMatches() ([]plugin.Resource, bool, error) {
	podUID := containerStatusPodUID(k.__id)
	if podUID == "" {
		return nil, false, nil
	}
	k8sRaw, err := CreateResource(k.MqlRuntime, "k8s", nil)
	if err != nil {
		return nil, false, err
	}
	k8s := k8sRaw.(*mqlK8s)
	lookup, err := k8s.getRuntimeImageClusterLookup()
	if err != nil {
		return nil, false, err
	}
	nodeName, podFound := lookup.podNodeNames[podUID]
	if !podFound || nodeName == "" {
		return nil, true, nil
	}

	node, ok := lookup.nodes[nodeName]
	if !ok {
		return nil, false, nil
	}
	delegates := node.GetRuntimeDelegates()
	if delegates.Error != nil {
		return nil, false, delegates.Error
	}
	if !runtimeDelegateAvailable(k.MqlRuntime, delegates.Data, runtimeKindFromContainerID(k.ContainerId.Data)) {
		return nil, false, nil
	}

	images := node.GetRuntimeImages()
	if images.Error != nil {
		return nil, true, images.Error
	}
	digestKeys := runtimeImageDigestMatchKeys(k.ImageId.Data)
	var keys map[string]struct{}
	if len(digestKeys) == 0 {
		keys = runtimeImageMatchKeys(k.Image.Data, k.ImageId.Data)
	}
	matches := []plugin.Resource{}
	for _, item := range images.Data {
		image, ok := item.(plugin.Resource)
		if !ok {
			continue
		}
		imageKeys := runtimeImageResourceMatchKeys(k.MqlRuntime, image)
		if len(digestKeys) > 0 {
			if runtimeImageKeysIntersect(digestKeys, imageKeys) {
				matches = append(matches, image)
			}
			continue
		}
		if runtimeImageKeysIntersect(keys, imageKeys) {
			matches = append(matches, image)
		}
	}
	return matches, true, nil
}

type runtimeImageClusterLookup struct {
	podNodeNames map[string]string
	nodes        map[string]*mqlK8sNode
}

func (k *mqlK8s) getRuntimeImageClusterLookup() (*runtimeImageClusterLookup, error) {
	k.runtimeImageLookupLock.Lock()
	defer k.runtimeImageLookupLock.Unlock()
	if k.runtimeImageLookup != nil {
		return k.runtimeImageLookup, nil
	}

	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	nodes := k.GetNodes()
	if nodes.Error != nil {
		return nil, nodes.Error
	}
	lookup, err := newRuntimeImageClusterLookup(pods.Data, nodes.Data)
	if err != nil {
		return nil, err
	}
	k.runtimeImageLookup = lookup
	return lookup, nil
}

func newRuntimeImageClusterLookup(pods, nodes []any) (*runtimeImageClusterLookup, error) {
	lookup := &runtimeImageClusterLookup{
		podNodeNames: make(map[string]string, len(pods)),
		nodes:        make(map[string]*mqlK8sNode, len(nodes)),
	}
	for _, item := range pods {
		pod, ok := item.(*mqlK8sPod)
		if !ok || pod.Uid.Data == "" {
			continue
		}
		nodeName := pod.GetNodeName()
		if nodeName.Error != nil {
			return nil, nodeName.Error
		}
		lookup.podNodeNames[pod.Uid.Data] = nodeName.Data
	}
	for _, item := range nodes {
		node, ok := item.(*mqlK8sNode)
		if !ok || node.Name.Data == "" {
			continue
		}
		lookup.nodes[node.Name.Data] = node
	}
	return lookup, nil
}

func containerStatusPodUID(id string) string {
	for _, marker := range []string{"-containerstatus-", "-initcontainerstatus-", "-ephemeralcontainerstatus-"} {
		if podUID, _, ok := strings.Cut(id, marker); ok && podUID != "" {
			return podUID
		}
	}
	return ""
}

func runtimeDelegateAvailable(runtime *plugin.Runtime, delegates []any, runtimeKind string) bool {
	for _, item := range delegates {
		delegate, ok := item.(plugin.Resource)
		if !ok {
			continue
		}
		if runtimeDelegateMatchesKind(runtime, delegate, runtimeKind) && runtimeDelegateConfiguredForScan(runtime, delegate) {
			return true
		}
	}
	return false
}

func runtimeDelegateMatchesKind(runtime *plugin.Runtime, delegate plugin.Resource, runtimeKind string) bool {
	if runtimeKind == "" || delegate.MqlID() == runtimeKind {
		return true
	}
	if identity, ok := delegate.(runtimeDelegateIdentityResource); ok && identity.GetKind().Data == runtimeKind {
		return true
	}
	if kind, ok := sharedRuntimeStringField(runtime, delegate, "kind"); ok && kind == runtimeKind {
		return true
	}
	return false
}

func runtimeDelegateConfiguredForScan(runtime *plugin.Runtime, delegate plugin.Resource) bool {
	endpoint := ""
	if v, ok := delegate.(runtimeDelegateEndpointResource); ok {
		endpoint = v.GetEndpoint().Data
	} else if v, ok := sharedRuntimeStringField(runtime, delegate, "endpoint"); ok {
		endpoint = v
	}
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	if readonly, ok := runtimeDelegateReadonly(runtime, delegate); ok && !readonly {
		return false
	}
	if allowPull, ok := runtimeDelegateAllowPull(runtime, delegate); ok && allowPull {
		return false
	}
	statusValue := ""
	if status, ok := delegate.(runtimeDelegateStatusResource); ok {
		statusValue = status.GetStatus().Data
	} else if status, ok := sharedRuntimeStringField(runtime, delegate, "status"); ok {
		statusValue = status
	}
	switch strings.ToLower(strings.TrimSpace(statusValue)) {
	case "", "ready":
		return true
	default:
		return false
	}
}

func runtimeDelegateReadonly(runtime *plugin.Runtime, delegate plugin.Resource) (bool, bool) {
	if readonly, ok := delegate.(runtimeDelegateReadonlyResource); ok {
		return readonly.GetReadonly().Data, true
	}
	return sharedRuntimeBoolField(runtime, delegate, "readonly")
}

func runtimeDelegateAllowPull(runtime *plugin.Runtime, delegate plugin.Resource) (bool, bool) {
	if allowPull, ok := delegate.(runtimeDelegateAllowPullResource); ok {
		return allowPull.GetAllowPull().Data, true
	}
	return sharedRuntimeBoolField(runtime, delegate, "allowPull")
}

type runtimeDelegateIdentityResource interface {
	plugin.Resource
	GetKind() *plugin.TValue[string]
}

type runtimeDelegateEndpointResource interface {
	plugin.Resource
	GetEndpoint() *plugin.TValue[string]
}

type runtimeDelegateReadonlyResource interface {
	plugin.Resource
	GetReadonly() *plugin.TValue[bool]
}

type runtimeDelegateAllowPullResource interface {
	plugin.Resource
	GetAllowPull() *plugin.TValue[bool]
}

type runtimeDelegateStatusResource interface {
	plugin.Resource
	GetStatus() *plugin.TValue[string]
}

type runtimeImageIdentityResource interface {
	plugin.Resource
	GetImageId() *plugin.TValue[string]
	GetRepoTags() *plugin.TValue[[]any]
	GetRepoDigests() *plugin.TValue[[]any]
	GetResolvedDigest() *plugin.TValue[string]
	GetTargetDigest() *plugin.TValue[string]
}

func runtimeImageMatchKeys(image, imageID string) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, candidate := range []string{imageID, image} {
		addRuntimeImageMatchKey(keys, candidate)
	}
	return keys
}

func runtimeImageDigestMatchKeys(imageID string) map[string]struct{} {
	keys := map[string]struct{}{}
	normalized := normalizeRuntimeImageID(imageID)
	if !strings.HasPrefix(normalized, "sha256:") {
		return keys
	}
	addRuntimeImageMatchKey(keys, imageID)
	addRuntimeImageMatchKey(keys, normalized)
	return keys
}

func runtimeImageResourceMatchKeys(runtime *plugin.Runtime, image plugin.Resource) map[string]struct{} {
	keys := runtimeImageMatchKeys("", image.MqlID())
	if identity, ok := image.(runtimeImageIdentityResource); ok {
		for _, candidate := range []string{
			identity.GetImageId().Data,
			identity.GetResolvedDigest().Data,
			identity.GetTargetDigest().Data,
		} {
			addRuntimeImageMatchKey(keys, candidate)
		}
		for _, candidate := range identity.GetRepoTags().Data {
			addRuntimeImageMatchKey(keys, runtimeImageStringFromAny(candidate))
		}
		for _, candidate := range identity.GetRepoDigests().Data {
			addRuntimeImageMatchKey(keys, runtimeImageStringFromAny(candidate))
		}
	}
	for _, field := range []string{"imageId", "resolvedDigest", "targetDigest"} {
		if candidate, ok := sharedRuntimeStringField(runtime, image, field); ok {
			addRuntimeImageMatchKey(keys, candidate)
		}
	}
	for _, field := range []string{"repoTags", "repoDigests"} {
		for _, candidate := range sharedRuntimeStringArrayField(runtime, image, field) {
			addRuntimeImageMatchKey(keys, candidate)
		}
	}
	return keys
}

func sharedRuntimeStringField(runtime *plugin.Runtime, resource plugin.Resource, field string) (string, bool) {
	raw, ok := sharedRuntimeField(runtime, resource, field)
	if !ok {
		return "", false
	}
	value, ok := raw.Value.(string)
	return value, ok
}

func sharedRuntimeBoolField(runtime *plugin.Runtime, resource plugin.Resource, field string) (bool, bool) {
	raw, ok := sharedRuntimeField(runtime, resource, field)
	if !ok {
		return false, false
	}
	value, ok := raw.Value.(bool)
	return value, ok
}

func sharedRuntimeStringArrayField(runtime *plugin.Runtime, resource plugin.Resource, field string) []string {
	raw, ok := sharedRuntimeField(runtime, resource, field)
	if !ok {
		return nil
	}
	switch values := raw.Value.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s := runtimeImageStringFromAny(value); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return values
	default:
		return nil
	}
}

func sharedRuntimeField(runtime *plugin.Runtime, resource plugin.Resource, field string) (*llx.RawData, bool) {
	if runtime == nil || resource == nil || strings.TrimSpace(resource.MqlName()) == "" || strings.TrimSpace(resource.MqlID()) == "" {
		return nil, false
	}
	raw, err := runtime.GetSharedData(resource.MqlName(), resource.MqlID(), field)
	if err != nil {
		log.Warn().
			Err(err).
			Str("resource", resource.MqlName()).
			Str("resource-id", resource.MqlID()).
			Str("field", field).
			Msg("could not read shared runtime field")
		return nil, false
	}
	if raw == nil {
		return nil, false
	}
	if raw.Error != nil {
		log.Warn().
			Err(raw.Error).
			Str("resource", resource.MqlName()).
			Str("resource-id", resource.MqlID()).
			Str("field", field).
			Msg("shared runtime field contains an error")
		return nil, false
	}
	return raw, true
}

func addRuntimeImageMatchKey(keys map[string]struct{}, candidate string) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return
	}
	keys[candidate] = struct{}{}
	normalized := normalizeRuntimeImageID(candidate)
	if normalized != "" {
		keys[normalized] = struct{}{}
	}
}

func runtimeImageKeysIntersect(left, right map[string]struct{}) bool {
	if len(left) > len(right) {
		left, right = right, left
	}
	for key := range left {
		if _, ok := right[key]; ok {
			return true
		}
	}
	return false
}

func runtimeImageStringFromAny(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func (k *mqlK8sPod) annotations() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(pod.GetAnnotations()), nil
}

func (k *mqlK8sPod) labels() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(pod.GetLabels()), nil
}

func (k *mqlK8sPod) node() (*mqlK8sNode, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	podSpec, err := resources.GetPodSpec(pod)
	if err != nil {
		return nil, err
	}

	// Unscheduled pods have no node assigned yet.
	if podSpec.NodeName == "" {
		k.Node.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	node, err := NewResource(k.MqlRuntime, "k8s.node", map[string]*llx.RawData{
		"name": llx.StringData(podSpec.NodeName),
	})
	if err != nil {
		// Nodes are cluster-scoped, so they aren't loaded when queried
		// from a namespace-scoped asset, and a scheduled node can also be
		// drained or removed. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Node.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	return node.(*mqlK8sNode), nil
}

func (k *mqlK8sPod) podSpecTyped() (*corev1.PodSpec, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return &pod.Spec, nil
}

func (k *mqlK8sPod) nodeName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.NodeName, nil
}

func (k *mqlK8sPod) nodeSelector() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(spec.NodeSelector), nil
}

func (k *mqlK8sPod) tolerations() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.Tolerations)
}

func (k *mqlK8sPod) topologySpreadConstraints() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.TopologySpreadConstraints)
}

func (k *mqlK8sPod) affinity() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.Affinity)
}

func (k *mqlK8sPod) priorityClassName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.PriorityClassName, nil
}

func (k *mqlK8sPod) priorityClass() (*mqlK8sPriorityclass, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	if spec.PriorityClassName == "" {
		k.PriorityClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pc, err := NewResource(k.MqlRuntime, "k8s.priorityclass", map[string]*llx.RawData{
		"name": llx.StringData(spec.PriorityClassName),
	})
	if err != nil {
		// PriorityClass is cluster-scoped, so it isn't loaded when queried
		// from a namespace-scoped asset, and a referenced PriorityClass
		// may have been deleted. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.PriorityClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return pc.(*mqlK8sPriorityclass), nil
}

func (k *mqlK8sPod) preemptionPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	if spec.PreemptionPolicy == nil {
		return "", nil
	}
	return string(*spec.PreemptionPolicy), nil
}

func (k *mqlK8sPod) schedulerName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.SchedulerName, nil
}

func (k *mqlK8sPod) runtimeClassName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	if spec.RuntimeClassName == nil {
		return "", nil
	}
	return *spec.RuntimeClassName, nil
}

// runtimeClass resolves the pod's runtimeClassName to the RuntimeClass
// object. It scans the already-fetched class list rather than calling
// NewResource per pod, which would run the target's init before the runtime
// cache is consulted and turn one list call into one per pod.
func (k *mqlK8sPod) runtimeClass() (*mqlK8sRuntimeclass, error) {
	name := k.GetRuntimeClassName()
	if name.Error != nil {
		return nil, name.Error
	}
	if name.Data == "" {
		k.RuntimeClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	classes := o.(*mqlK8s).GetRuntimeClasses()
	if classes.Error != nil {
		return nil, classes.Error
	}

	for i := range classes.Data {
		rc, ok := classes.Data[i].(*mqlK8sRuntimeclass)
		if !ok {
			continue
		}
		if rc.Name.Data == name.Data {
			return rc, nil
		}
	}

	// The pod names a class the cluster does not have (it was deleted, or the
	// scan cannot read the kind). That is a real state, not an error.
	k.RuntimeClass.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (k *mqlK8sPod) serviceAccountName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.ServiceAccountName, nil
}

func (k *mqlK8sPod) serviceAccount() (*mqlK8sServiceaccount, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	if pod.Spec.ServiceAccountName == "" {
		k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	sa, err := NewResource(k.MqlRuntime, "k8s.serviceaccount", map[string]*llx.RawData{
		"name":      llx.StringData(pod.Spec.ServiceAccountName),
		"namespace": llx.StringData(pod.Namespace),
	})
	if err != nil {
		// A referenced ServiceAccount may have been deleted. Resolve to
		// null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return sa.(*mqlK8sServiceaccount), nil
}

func (k *mqlK8sPod) automountServiceAccountToken() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sPod) hostNetwork() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostNetwork, nil
}

func (k *mqlK8sPod) hostPID() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostPID, nil
}

func (k *mqlK8sPod) hostIPC() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostIPC, nil
}

func (k *mqlK8sPod) shareProcessNamespace() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	if spec.ShareProcessNamespace == nil {
		return false, nil
	}
	return *spec.ShareProcessNamespace, nil
}

func (k *mqlK8sPod) securityContext() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.SecurityContext)
}

func (k *mqlK8sPod) dnsPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return string(spec.DNSPolicy), nil
}

func (k *mqlK8sPod) dnsConfig() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.DNSConfig)
}

func (k *mqlK8sPod) hostname() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.Hostname, nil
}

func (k *mqlK8sPod) subdomain() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.Subdomain, nil
}

func (k *mqlK8sPod) hostAliases() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.HostAliases)
}

func (k *mqlK8sPod) restartPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return string(spec.RestartPolicy), nil
}

func (k *mqlK8sPod) terminationGracePeriodSeconds() (int64, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return 0, err
	}
	if spec.TerminationGracePeriodSeconds == nil {
		return 0, nil
	}
	return *spec.TerminationGracePeriodSeconds, nil
}

func (k *mqlK8sPod) activeDeadlineSeconds() (int64, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return 0, err
	}
	if spec.ActiveDeadlineSeconds == nil {
		return 0, nil
	}
	return *spec.ActiveDeadlineSeconds, nil
}

func (k *mqlK8sPod) readinessGates() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.ReadinessGates)
}

func (k *mqlK8sPod) enableServiceLinks() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	if spec.EnableServiceLinks == nil {
		// Defaults to true when unset.
		return true, nil
	}
	return *spec.EnableServiceLinks, nil
}

func (k *mqlK8sPod) imagePullSecrets() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.ImagePullSecrets)
}

func (k *mqlK8sPod) overhead() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	if spec.Overhead == nil {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(spec.Overhead))
	for name, qty := range spec.Overhead {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sPod) os() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.OS)
}

func (k *mqlK8sPod) phase() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return string(pod.Status.Phase), nil
}

func (k *mqlK8sPod) qosClass() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return string(pod.Status.QOSClass), nil
}

func (k *mqlK8sPod) podIP() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.PodIP, nil
}

func (k *mqlK8sPod) podIPs() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(pod.Status.PodIPs))
	for i, ip := range pod.Status.PodIPs {
		out[i] = ip.IP
	}
	return out, nil
}

func (k *mqlK8sPod) hostIP() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.HostIP, nil
}

func (k *mqlK8sPod) nominatedNodeName() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.NominatedNodeName, nil
}

func (k *mqlK8sPod) startTime() (*time.Time, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	if pod.Status.StartTime == nil {
		k.StartTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := pod.Status.StartTime.Time
	return &t, nil
}

func (k *mqlK8sPod) conditions() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(pod.Status.Conditions)
}

func (k *mqlK8sPod) reason() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.Reason, nil
}

func (k *mqlK8sPod) message() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.Message, nil
}

func (k *mqlK8sPod) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPod) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// ownerOfKind looks up the first owner reference matching kind and returns the
// (namespace, name) pair, or empty strings if not found.
func (k *mqlK8sPod) ownerOfKind(kind string) (string, string, bool) {
	pod, err := k.getPod()
	if err != nil {
		return "", "", false
	}
	for _, o := range pod.OwnerReferences {
		if o.Kind == kind {
			return pod.Namespace, o.Name, true
		}
	}
	return "", "", false
}

func (k *mqlK8sPod) replicaSet() (*mqlK8sReplicaset, error) {
	ns, name, ok := k.ownerOfKind("ReplicaSet")
	if !ok {
		k.ReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.replicaset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		// Pods can survive their owner mid-deletion or be re-parented to a
		// new ReplicaSet. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sReplicaset), nil
}

func (k *mqlK8sPod) statefulSet() (*mqlK8sStatefulset, error) {
	ns, name, ok := k.ownerOfKind("StatefulSet")
	if !ok {
		k.StatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.statefulset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.StatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sStatefulset), nil
}

func (k *mqlK8sPod) daemonSet() (*mqlK8sDaemonset, error) {
	ns, name, ok := k.ownerOfKind("DaemonSet")
	if !ok {
		k.DaemonSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.daemonset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.DaemonSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sDaemonset), nil
}

func (k *mqlK8sPod) job() (*mqlK8sJob, error) {
	ns, name, ok := k.ownerOfKind("Job")
	if !ok {
		k.Job.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.job", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.Job.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sJob), nil
}

func (k *mqlK8sPod) deployment() (*mqlK8sDeployment, error) {
	// Pods are owned by a ReplicaSet, which is owned by a Deployment.
	rs, err := k.replicaSet()
	if err != nil || rs == nil {
		k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, err
	}
	rsTyped, err := rs.getReplicaSet()
	if err != nil {
		return nil, err
	}
	for _, o := range rsTyped.OwnerReferences {
		if o.Kind == "Deployment" {
			r, err := NewResource(k.MqlRuntime, "k8s.deployment", map[string]*llx.RawData{
				"name":      llx.StringData(o.Name),
				"namespace": llx.StringData(rsTyped.Namespace),
			})
			if err != nil {
				// A Deployment can be deleted while its ReplicaSet and
				// pods are still mid-cleanup. Resolve to null; surface
				// other errors (per PR #7884, type-assertion failures
				// inside getReplicaSet() above still propagate).
				if errors.Is(err, ErrResourceNotFound) {
					k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
					return nil, nil
				}
				return nil, err
			}
			return r.(*mqlK8sDeployment), nil
		}
	}
	k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

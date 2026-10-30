// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ErrResourceNotFound is returned by the resource init helpers when a lookup
// by id or name/namespace finds no match in the cluster snapshot. Callers can
// distinguish this case from transient errors with errors.Is. The literal
// "not found" message is also matched by cnspec, so don't change the text.
var ErrResourceNotFound = errors.New("not found")

func k8sProvider(t plugin.Connection) (shared.Connection, error) {
	at, ok := t.(shared.Connection)
	if !ok {
		return nil, errors.New("k8s resource is not supported on this provider")
	}
	return at, nil
}

type resourceConvertFn func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error)

func gvkString(gvk schema.GroupVersionKind) string {
	return gvk.Kind + "." + gvk.Version + "." + gvk.Group
}

func k8sResourceToMql(r *plugin.Runtime, kind string, fn resourceConvertFn) ([]any, error) {
	kt, err := k8sProvider(r.Connection)
	if err != nil {
		return nil, err
	}

	// TODO: check if we are running in a namespace scope and retrieve the ns from the provider
	result, err := kt.Resources(kind, "", "")
	if err != nil {
		return nil, err
	}

	resp := []any{}
	for i := range result.Resources {
		resource := result.Resources[i]

		obj, err := meta.Accessor(resource)
		if err != nil {
			log.Error().Err(err).Msg("could not access object attributes")
			return nil, err
		}
		objT, err := meta.TypeAccessor(resource)
		if err != nil {
			log.Error().Err(err).Msg("could not access object attributes")
			return nil, err
		}

		mqlK8sResource, err := fn(kind, resource, obj, objT)
		if err != nil {
			return nil, err
		}

		// Attach the manifest source location (no-op for non-manifest scans and
		// for resources the manifest doesn't contain).
		if err := setK8sSourceContext(r, kt, obj, objT, mqlK8sResource); err != nil {
			return nil, err
		}

		resp = append(resp, mqlK8sResource)
	}

	return resp, nil
}

// k8sOptionalResourceToMql maps a kind the cluster does not have to serve.
//
// A cluster that predates the API, a feature gate that is off, or an RBAC rule
// that hides the kind yields an empty list rather than failing the query. Any
// other error is returned unchanged.
func k8sOptionalResourceToMql(r *plugin.Runtime, kind string, fn resourceConvertFn) ([]any, error) {
	resources, err := k8sResourceToMql(r, kind, fn)
	if err != nil {
		if optionalResourceUnavailable(err) {
			log.Debug().Err(err).Str("kind", kind).Msg("skipping optional Kubernetes resource")
			return []any{}, nil
		}
		return nil, err
	}
	return resources, nil
}

func getNameAndNamespace(runtime *plugin.Runtime) (string, string, error) {
	asset := runtime.Connection.(shared.Connection).Asset()
	return asset.Labels["k8s.mondoo.com/name"], asset.Labels["k8s.mondoo.com/namespace"], nil
}

type K8sNamespacedObject interface {
	K8sObject
	GetNamespace() *plugin.TValue[string]
}

type K8sObject interface {
	plugin.Resource
	GetId() *plugin.TValue[string]
	GetKind() *plugin.TValue[string]
	GetName() *plugin.TValue[string]
}

func objId(o runtime.Object, meta metav1.Object) (string, error) {
	kind := o.GetObjectKind().GroupVersionKind().Kind
	name := meta.GetName()
	namespace := meta.GetNamespace()

	return objIdFromFields(kind, namespace, name), nil
}

func objIdFromK8sObj(o metav1.Object, objT metav1.Type) string {
	return objIdFromFields(objT.GetKind(), o.GetNamespace(), o.GetName())
}

func objIdFromFields(kind, namespace, name string) string {
	// Kind is usually capitalized. Make it all lower case for readability
	if namespace == "" {
		return fmt.Sprintf("%s:%s", strings.ToLower(kind), name)
	}
	return fmt.Sprintf("%s:%s:%s", strings.ToLower(kind), namespace, name)
}

func initNamespacedResource[T K8sNamespacedObject](
	runtime *plugin.Runtime, args map[string]*llx.RawData, r func(k8s *mqlK8s) *plugin.TValue[[]any],
) (map[string]*llx.RawData, plugin.Resource, error) {
	// pass-through if all args are already provided
	if len(args) > 2 {
		return args, nil, nil
	}

	// get platform identifier infos
	identifierName, identifierNamespace, err := getNameAndNamespace(runtime)
	if err != nil {
		return args, nil, nil
	}

	// search for existing resources if id or name/namespace is provided
	obj, err := CreateResource(runtime, "k8s", nil)
	if err != nil {
		return args, nil, err
	}
	k8s := obj.(*mqlK8s)

	nsResources := r(k8s)
	if nsResources.Error != nil {
		return args, nil, nsResources.Error
	}

	var matchFn func(nsR T) bool

	var idRaw string
	if _, ok := args["id"]; ok {
		idRaw = args["id"].Value.(string)
	}

	if idRaw != "" {
		matchFn = func(nsR T) bool {
			return nsR.GetId().Data == idRaw
		}
	}

	var nameRaw string
	var namespaceRaw string
	if _, ok := args["name"]; ok {
		nameRaw = args["name"].Value.(string)
	}
	if _, ok := args["namespace"]; ok {
		namespaceRaw = args["namespace"].Value.(string)
	}
	if nameRaw == "" {
		nameRaw = identifierName
		namespaceRaw = identifierNamespace
	}
	if nameRaw != "" {
		matchFn = func(nsR T) bool {
			name := nsR.GetName().Data
			namespace := nsR.GetNamespace().Data
			return name == nameRaw && namespace == namespaceRaw
		}
	}

	if matchFn == nil {
		return args, nil, fmt.Errorf("cannot use resource without specifying id or name/namespace")
	}

	for i := range nsResources.Data {
		nsR := nsResources.Data[i].(T)
		if matchFn(nsR) {
			return args, nsR, nil
		}
	}

	// the error message must stay "not found" — cnspec matches on this text
	return args, nil, ErrResourceNotFound
}

func initResource[T K8sObject](
	runtime *plugin.Runtime, args map[string]*llx.RawData, r func(k8s *mqlK8s) *plugin.TValue[[]any],
) (map[string]*llx.RawData, plugin.Resource, error) {
	// pass-through if all args are already provided
	if len(args) > 1 {
		return args, nil, nil
	}

	// get platform identifier infos
	identifierName, _, err := getNameAndNamespace(runtime)
	if err != nil {
		return args, nil, nil
	}

	// search for existing resources if id or name is provided
	obj, err := CreateResource(runtime, "k8s", nil)
	if err != nil {
		return args, nil, err
	}
	k8s := obj.(*mqlK8s)

	k8sResources := r(k8s)
	if k8sResources.Error != nil {
		return nil, nil, k8sResources.Error
	}

	var matchFn func(entry T) bool

	idRaw := args["id"]
	if idRaw != nil {
		matchFn = func(entry T) bool {
			if entry.GetId().Data == idRaw.Value.(string) {
				return true
			}
			return false
		}
	}

	var nameRaw string
	if _, ok := args["name"]; ok {
		nameRaw = args["name"].Value.(string)
	}
	if nameRaw == "" {
		nameRaw = identifierName
	}
	if nameRaw != "" {
		matchFn = func(nsR T) bool {
			return nsR.GetName().Data == nameRaw
		}
	}

	if matchFn == nil {
		return args, *new(T), fmt.Errorf("cannot use resource without specifying id or name")
	}

	for i := range k8sResources.Data {
		entry := k8sResources.Data[i].(T)
		if matchFn(entry) {
			return nil, entry, nil
		}
	}

	// the error message must stay "not found" — cnspec matches on this text
	return nil, nil, ErrResourceNotFound
}

// filterByNamespace returns the items from the k8s root accessor `all` whose
// Namespace matches `namespace`. Powers the typed `k8s.namespace.<kind>s()`
// accessors so users can write `k8s.namespace("prod").pods` instead of
// `k8s.pods.where(namespace == "prod")`.
func filterByNamespace[T K8sNamespacedObject](runtime *plugin.Runtime, namespace string, all func(k *mqlK8s) *plugin.TValue[[]any]) ([]any, error) {
	o, err := CreateResource(runtime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	items := all(o.(*mqlK8s))
	if items.Error != nil {
		return nil, items.Error
	}
	out := []any{}
	for i := range items.Data {
		nsR, ok := items.Data[i].(T)
		if !ok {
			continue
		}
		if nsR.GetNamespace().Data == namespace {
			out = append(out, nsR)
		}
	}
	return out, nil
}

// podsMatchingSelector returns the modeled k8s.pod resources in the given
// namespace whose labels match the supplied LabelSelector. Workloads use this
// to expose a typed `pods()` accessor.
func podsMatchingSelector(runtime *plugin.Runtime, selector *metav1.LabelSelector, namespace string) ([]any, error) {
	if selector == nil {
		return []any{}, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(runtime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	pods := o.(*mqlK8s).GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	out := []any{}
	for i := range pods.Data {
		p, ok := pods.Data[i].(*mqlK8sPod)
		if !ok {
			continue
		}
		if namespace != "" && p.Namespace.Data != namespace {
			continue
		}
		podLabels := p.GetLabels()
		if podLabels.Error != nil {
			continue
		}
		stringLabels := make(map[string]string, len(podLabels.Data))
		for k, v := range podLabels.Data {
			if s, ok := v.(string); ok {
				stringLabels[k] = s
			}
		}
		if sel.Matches(labels.Set(stringLabels)) {
			out = append(out, p)
		}
	}
	return out, nil
}

// k8sOwnerReferences builds typed k8s.ownerReference resources from any
// Kubernetes object's metadata.ownerReferences. obj may be a runtime.Object or
// a metav1.Object — meta.Accessor normalizes both.
func k8sOwnerReferences(runtime *plugin.Runtime, obj any) ([]any, error) {
	m, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	parentUID := string(m.GetUID())
	refs := m.GetOwnerReferences()
	out := make([]any, 0, len(refs))
	for i := range refs {
		ref := refs[i]

		// Scope the cache key to the owning object. The same referent UID can
		// appear on different objects with different controller/blockOwnerDeletion
		// values, so a parent-scoped key avoids a silent cache collision. Fall
		// back to kind:name only for the rare reference that omits the uid.
		refKey := string(ref.UID)
		if refKey == "" {
			refKey = strings.ToLower(ref.Kind) + ":" + ref.Name
		}

		r, err := CreateResource(runtime, "k8s.ownerReference", map[string]*llx.RawData{
			"__id":               llx.StringData(parentUID + "/ownerref/" + refKey),
			"apiVersion":         llx.StringData(ref.APIVersion),
			"kind":               llx.StringData(ref.Kind),
			"name":               llx.StringData(ref.Name),
			"uid":                llx.StringData(string(ref.UID)),
			"controller":         llx.BoolDataPtr(ref.Controller),
			"blockOwnerDeletion": llx.BoolDataPtr(ref.BlockOwnerDeletion),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// k8sManagedFields builds typed k8s.managedField resources from any Kubernetes
// object's metadata.managedFields (server-side apply authorship records).
func k8sManagedFields(runtime *plugin.Runtime, obj any) ([]any, error) {
	m, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}

	objUID := string(m.GetUID())
	fields := m.GetManagedFields()
	out := make([]any, 0, len(fields))
	for i := range fields {
		f := fields[i]

		data := map[string]*llx.RawData{
			// Kubernetes keys managed-field entries by
			// (manager, operation, apiVersion, subresource), so the synthetic
			// id must include all four to avoid silently deduplicating entries
			// that differ only by apiVersion.
			"__id":        llx.StringData(objUID + "/managedfield/" + f.Manager + "/" + string(f.Operation) + "/" + f.APIVersion + "/" + f.Subresource),
			"manager":     llx.StringData(f.Manager),
			"operation":   llx.StringData(string(f.Operation)),
			"apiVersion":  llx.StringData(f.APIVersion),
			"subresource": llx.StringData(f.Subresource),
			"fieldsType":  llx.StringData(f.FieldsType),
			"time":        llx.NilData,
			"fieldsV1":    llx.NilData,
		}
		if f.Time != nil {
			data["time"] = llx.TimeData(f.Time.Time)
		}
		if f.FieldsV1 != nil {
			if raw := f.FieldsV1.GetRawBytes(); len(raw) > 0 {
				var fv any
				if err := json.Unmarshal(raw, &fv); err != nil {
					return nil, err
				}
				data["fieldsV1"] = llx.DictData(fv)
			}
		}

		r, err := CreateResource(runtime, "k8s.managedField", data)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// namespacedByName indexes an already-fetched k8s root collection by
// namespace and name so callers can resolve a reference without a per-item
// NewResource lookup. NewResource runs the target's init before the runtime
// cache is consulted, so resolving one parent per child would turn a single
// list into one lookup per reference.
func namespacedByName[T K8sNamespacedObject](
	runtime *plugin.Runtime, all func(k *mqlK8s) *plugin.TValue[[]any],
) (map[string]T, error) {
	o, err := CreateResource(runtime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	items := all(o.(*mqlK8s))
	if items.Error != nil {
		return nil, items.Error
	}
	out := make(map[string]T, len(items.Data))
	for i := range items.Data {
		item, ok := items.Data[i].(T)
		if !ok {
			continue
		}
		out[item.GetNamespace().Data+"/"+item.GetName().Data] = item
	}
	return out, nil
}

// resolveNamespaced returns the modeled resources named by refs in the given
// namespace, in the order the references appear. A reference whose object is
// gone (or that the scan had no permission to read) is skipped rather than
// failing the accessor, and duplicate references resolve once.
func resolveNamespaced[T K8sNamespacedObject](
	runtime *plugin.Runtime, namespace string, refs []string, all func(k *mqlK8s) *plugin.TValue[[]any],
) ([]any, error) {
	out := []any{}
	if len(refs) == 0 {
		return out, nil
	}
	index, err := namespacedByName[T](runtime, all)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(refs))
	for _, name := range refs {
		if name == "" {
			continue
		}
		key := namespace + "/" + name
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		item, ok := index[key]
		if !ok {
			log.Debug().Str("namespace", namespace).Str("name", name).Msg("referenced Kubernetes object not found")
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

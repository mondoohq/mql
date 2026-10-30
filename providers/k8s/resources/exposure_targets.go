// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// serviceKey identifies a Service by namespace and name, used to deduplicate
// backend references when resolving ingress and gateway routing targets.
type serviceKey struct {
	namespace string
	name      string
}

func k8sCluster(runtime *plugin.Runtime) (*mqlK8s, error) {
	o, err := CreateResource(runtime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return o.(*mqlK8s), nil
}

// pods returns the pods selected by the service's label selector. Selectorless
// services (including ExternalName) select no pods.
func (k *mqlK8sService) pods() ([]any, error) {
	svc, err := k.getService()
	if err != nil {
		return nil, err
	}
	if len(svc.Spec.Selector) == 0 {
		return []any{}, nil
	}
	return podsMatchingSelector(k.MqlRuntime, &metav1.LabelSelector{MatchLabels: svc.Spec.Selector}, svc.Namespace)
}

// services returns the services in the pod's namespace whose label selector
// matches the pod, the reverse of k8s.service.pods.
func (k *mqlK8sPod) services() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	cluster, err := k8sCluster(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svcs := cluster.GetServices()
	if svcs.Error != nil {
		return nil, svcs.Error
	}

	podLabels := labels.Set(pod.Labels)
	out := []any{}
	for i := range svcs.Data {
		s, ok := svcs.Data[i].(*mqlK8sService)
		if !ok {
			continue
		}
		svc, err := s.getService()
		if err != nil {
			return nil, err
		}
		if svc.Namespace != pod.Namespace || len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(svc.Spec.Selector).Matches(podLabels) {
			out = append(out, s)
		}
	}
	return out, nil
}

// exposures returns the network exposures that route to this pod, the inverse of
// k8s.networkExposure.pods. It lets a query pivot from a risky workload to the
// internet exposure that reaches it.
func (k *mqlK8sPod) exposures() ([]any, error) {
	cluster, err := k8sCluster(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	exps := cluster.GetNetworkExposures()
	if exps.Error != nil {
		return nil, exps.Error
	}

	podID := k.MqlID()
	out := []any{}
	for i := range exps.Data {
		exp, ok := exps.Data[i].(*mqlK8sNetworkExposure)
		if !ok {
			continue
		}
		pods, err := exp.pods()
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			if mp, ok := p.(*mqlK8sPod); ok && mp.MqlID() == podID {
				out = append(out, exp)
				break
			}
		}
	}
	return out, nil
}

// exposuresForPods returns the network exposures that route to any of the
// given pods, in the cluster's stable exposure order, deduplicated by
// exposure. It is the shared fold behind the workload-level exposures
// accessors: a workload is exposed exactly when one of its pods is.
func exposuresForPods(runtime *plugin.Runtime, pods []any) ([]any, error) {
	if len(pods) == 0 {
		return []any{}, nil
	}
	want := make(map[string]struct{}, len(pods))
	for _, p := range pods {
		if mp, ok := p.(*mqlK8sPod); ok {
			want[mp.MqlID()] = struct{}{}
		}
	}

	cluster, err := k8sCluster(runtime)
	if err != nil {
		return nil, err
	}
	exps := cluster.GetNetworkExposures()
	if exps.Error != nil {
		return nil, exps.Error
	}

	out := []any{}
	for i := range exps.Data {
		exp, ok := exps.Data[i].(*mqlK8sNetworkExposure)
		if !ok {
			continue
		}
		expPods, err := exp.pods()
		if err != nil {
			return nil, err
		}
		for _, p := range expPods {
			if mp, ok := p.(*mqlK8sPod); ok {
				if _, hit := want[mp.MqlID()]; hit {
					out = append(out, exp)
					break
				}
			}
		}
	}
	return out, nil
}

// exposures returns the network exposures that route to any pod backing this
// deployment. This is what lets a controller-managed workload be attributed
// the internet exposure its pods serve: the pods themselves are represented
// by their controller, so the exposure has to surface here.
func (k *mqlK8sDeployment) exposures() ([]any, error) {
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	return exposuresForPods(k.MqlRuntime, pods.Data)
}

// exposures returns the network exposures that route to any pod backing this
// DaemonSet.
func (k *mqlK8sDaemonset) exposures() ([]any, error) {
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	return exposuresForPods(k.MqlRuntime, pods.Data)
}

// exposures returns the network exposures that route to any pod backing this
// StatefulSet.
func (k *mqlK8sStatefulset) exposures() ([]any, error) {
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	return exposuresForPods(k.MqlRuntime, pods.Data)
}

// exposures returns the network exposures that route to any pod backing this
// ReplicaSet.
func (k *mqlK8sReplicaset) exposures() ([]any, error) {
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	return exposuresForPods(k.MqlRuntime, pods.Data)
}

// pods returns the pods behind the ingress, resolved through the services its
// rules and default backend route to.
func (k *mqlK8sIngress) pods() ([]any, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	cluster, err := k8sCluster(k.MqlRuntime)
	if err != nil {
		return nil, err
	}

	keys := map[serviceKey]struct{}{}
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		keys[serviceKey{ing.Namespace, ing.Spec.DefaultBackend.Service.Name}] = struct{}{}
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				keys[serviceKey{ing.Namespace, path.Backend.Service.Name}] = struct{}{}
			}
		}
	}
	return podsForServiceKeys(cluster, keys)
}

// pods returns the pods behind the gateway, resolved through the HTTPRoutes and
// GRPCRoutes attached to it and the services their backend references route to.
// Layer-4 routes (TCPRoute, TLSRoute, UDPRoute) are not folded in.
func (k *mqlK8sGateway) pods() ([]any, error) {
	gw := k.obj
	cluster, err := k8sCluster(k.MqlRuntime)
	if err != nil {
		return nil, err
	}

	keys := map[serviceKey]struct{}{}

	httpRoutes := cluster.GetHttpRoutes()
	if httpRoutes.Error != nil {
		return nil, httpRoutes.Error
	}
	for i := range httpRoutes.Data {
		hr, ok := httpRoutes.Data[i].(*mqlK8sHttproute)
		if !ok || hr.obj == nil {
			continue
		}
		if !routeTargetsGateway(hr.obj.Spec.ParentRefs, hr.obj.Namespace, gw.Namespace, gw.Name) {
			continue
		}
		for _, rule := range hr.obj.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				addBackendServiceKey(keys, ref.BackendObjectReference, hr.obj.Namespace)
			}
		}
	}

	grpcRoutes := cluster.GetGrpcRoutes()
	if grpcRoutes.Error != nil {
		return nil, grpcRoutes.Error
	}
	for i := range grpcRoutes.Data {
		gr, ok := grpcRoutes.Data[i].(*mqlK8sGrpcroute)
		if !ok || gr.obj == nil {
			continue
		}
		if !routeTargetsGateway(gr.obj.Spec.ParentRefs, gr.obj.Namespace, gw.Namespace, gw.Name) {
			continue
		}
		for _, rule := range gr.obj.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				addBackendServiceKey(keys, ref.BackendObjectReference, gr.obj.Namespace)
			}
		}
	}

	return podsForServiceKeys(cluster, keys)
}

// pods returns the pods behind a normalized network exposure by resolving its
// source object (Service, Ingress, or Gateway) to the workloads behind it.
func (k *mqlK8sNetworkExposure) pods() ([]any, error) {
	cluster, err := k8sCluster(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ns := k.Namespace.Data
	name := k.Name.Data

	switch k.SourceKind.Data {
	case "Service":
		svcs := cluster.GetServices()
		if svcs.Error != nil {
			return nil, svcs.Error
		}
		for i := range svcs.Data {
			s, ok := svcs.Data[i].(*mqlK8sService)
			if !ok {
				continue
			}
			if s.Namespace.Data == ns && s.Name.Data == name {
				return s.pods()
			}
		}
	case "Ingress":
		ingresses := cluster.GetIngresses()
		if ingresses.Error != nil {
			return nil, ingresses.Error
		}
		for i := range ingresses.Data {
			ing, ok := ingresses.Data[i].(*mqlK8sIngress)
			if !ok {
				continue
			}
			if ing.Namespace.Data == ns && ing.Name.Data == name {
				return ing.pods()
			}
		}
	case "Gateway":
		gateways := cluster.GetGateways()
		if gateways.Error != nil {
			return nil, gateways.Error
		}
		for i := range gateways.Data {
			gw, ok := gateways.Data[i].(*mqlK8sGateway)
			if !ok {
				continue
			}
			if gw.Namespace.Data == ns && gw.Name.Data == name {
				return gw.pods()
			}
		}
	case "Pod":
		// Host-network and hostPort exposures are sourced from the pod itself.
		k8sPods := cluster.GetPods()
		if k8sPods.Error != nil {
			return nil, k8sPods.Error
		}
		for i := range k8sPods.Data {
			p, ok := k8sPods.Data[i].(*mqlK8sPod)
			if !ok {
				continue
			}
			if p.Namespace.Data == ns && p.Name.Data == name {
				return []any{p}, nil
			}
		}
	}

	// HBN and other non-Kubernetes sources have no in-cluster workload to
	// resolve, and a source object can have been deleted while the exposure
	// record lingers.
	return []any{}, nil
}

// routeTargetsGateway reports whether any of the route's parentRefs binds it to
// the given Gateway, applying the Gateway API defaults for the optional kind,
// group, and namespace fields.
func routeTargetsGateway(parentRefs []gatewayv1.ParentReference, routeNamespace, gatewayNamespace, gatewayName string) bool {
	for _, ref := range parentRefs {
		if ref.Kind != nil && string(*ref.Kind) != "Gateway" {
			continue
		}
		if ref.Group != nil && string(*ref.Group) != "" && string(*ref.Group) != "gateway.networking.k8s.io" {
			continue
		}
		if string(ref.Name) != gatewayName {
			continue
		}
		ns := routeNamespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		if ns == gatewayNamespace {
			return true
		}
	}
	return false
}

// addBackendServiceKey records a backend reference as a Service key when it
// points at a core-group Service, defaulting the namespace to the route's.
func addBackendServiceKey(keys map[serviceKey]struct{}, ref gatewayv1.BackendObjectReference, routeNamespace string) {
	if ref.Kind != nil && string(*ref.Kind) != "Service" {
		return
	}
	if ref.Group != nil && string(*ref.Group) != "" {
		return
	}
	if ref.Name == "" {
		return
	}
	ns := routeNamespace
	if ref.Namespace != nil {
		ns = string(*ref.Namespace)
	}
	keys[serviceKey{ns, string(ref.Name)}] = struct{}{}
}

// podsForServiceKeys unions the pods of every service whose key is in the set,
// deduplicating by pod id. It iterates the cluster's services in their stable
// order so the result is deterministic.
func podsForServiceKeys(cluster *mqlK8s, keys map[serviceKey]struct{}) ([]any, error) {
	if len(keys) == 0 {
		return []any{}, nil
	}
	svcs := cluster.GetServices()
	if svcs.Error != nil {
		return nil, svcs.Error
	}

	seen := map[string]struct{}{}
	out := []any{}
	for i := range svcs.Data {
		s, ok := svcs.Data[i].(*mqlK8sService)
		if !ok {
			continue
		}
		svc, err := s.getService()
		if err != nil {
			return nil, err
		}
		if _, want := keys[serviceKey{svc.Namespace, svc.Name}]; !want {
			continue
		}
		pods, err := s.pods()
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			pod, ok := p.(*mqlK8sPod)
			if !ok {
				continue
			}
			id := pod.MqlID()
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

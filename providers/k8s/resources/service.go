// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sServiceInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sService) getService() (*corev1.Service, error) {
	s, ok := k.obj.(*corev1.Service)
	if ok {
		return s, nil
	}
	return nil, errors.New("invalid k8s service")
}

func (k *mqlK8s) services() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("services")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.service", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sService).obj = resource
		return r, nil
	})
}

func (k *mqlK8sService) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sService) spec() (map[string]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	dict, err := convert.JsonToDict(s.Spec)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (k *mqlK8sService) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sService](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetServices() })
}

func (k *mqlK8sService) annotations() (map[string]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(s.GetAnnotations()), nil
}

func (k *mqlK8sService) labels() (map[string]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(s.GetLabels()), nil
}

func (k *mqlK8sService) compute_type() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	return string(s.Spec.Type), nil
}

func (k *mqlK8sService) clusterIP() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	return s.Spec.ClusterIP, nil
}

func (k *mqlK8sService) clusterIPs() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.Spec.ClusterIPs), nil
}

func (k *mqlK8sService) externalIPs() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.Spec.ExternalIPs), nil
}

func (k *mqlK8sService) externalName() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	return s.Spec.ExternalName, nil
}

func (k *mqlK8sService) externalTrafficPolicy() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	if s.Spec.ExternalTrafficPolicy == "" {
		// Only defaulted for NodePort and LoadBalancer services.
		k.ExternalTrafficPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(s.Spec.ExternalTrafficPolicy), nil
}

func (k *mqlK8sService) internalTrafficPolicy() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	if s.Spec.InternalTrafficPolicy == nil {
		k.InternalTrafficPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*s.Spec.InternalTrafficPolicy), nil
}

func (k *mqlK8sService) sessionAffinity() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	return string(s.Spec.SessionAffinity), nil
}

func (k *mqlK8sService) sessionAffinityConfig() (map[string]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	if s.Spec.SessionAffinityConfig == nil {
		// convert.JsonToDict(nil) yields {}, which reads as a configured but
		// empty affinity config rather than an absent one.
		k.SessionAffinityConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.JsonToDict(s.Spec.SessionAffinityConfig)
}

func (k *mqlK8sService) ipFamilies() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(s.Spec.IPFamilies))
	for i, f := range s.Spec.IPFamilies {
		out[i] = string(f)
	}
	return out, nil
}

func (k *mqlK8sService) ipFamilyPolicy() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	if s.Spec.IPFamilyPolicy == nil {
		k.IpFamilyPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*s.Spec.IPFamilyPolicy), nil
}

func (k *mqlK8sService) loadBalancerClass() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	if s.Spec.LoadBalancerClass == nil {
		k.LoadBalancerClass.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.Spec.LoadBalancerClass, nil
}

func (k *mqlK8sService) loadBalancerSourceRanges() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.Spec.LoadBalancerSourceRanges), nil
}

func (k *mqlK8sService) loadBalancerIP() (string, error) {
	s, err := k.getService()
	if err != nil {
		return "", err
	}
	return s.Spec.LoadBalancerIP, nil
}

func (k *mqlK8sService) allocateLoadBalancerNodePorts() (bool, error) {
	s, err := k.getService()
	if err != nil {
		return false, err
	}
	if s.Spec.AllocateLoadBalancerNodePorts == nil {
		if s.Spec.Type != corev1.ServiceTypeLoadBalancer {
			// The field only has meaning for type LoadBalancer, and the API
			// server leaves it unset for every other type. Defaulting it to
			// true here reported an allocation decision that was never made.
			k.AllocateLoadBalancerNodePorts.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		// A LoadBalancer manifest that omits the field defaults to true.
		return true, nil
	}
	return *s.Spec.AllocateLoadBalancerNodePorts, nil
}

func (k *mqlK8sService) publishNotReadyAddresses() (bool, error) {
	s, err := k.getService()
	if err != nil {
		return false, err
	}
	return s.Spec.PublishNotReadyAddresses, nil
}

func (k *mqlK8sService) healthCheckNodePort() (int64, error) {
	s, err := k.getService()
	if err != nil {
		return 0, err
	}
	if s.Spec.HealthCheckNodePort == 0 {
		// Only allocated for a LoadBalancer with externalTrafficPolicy: Local.
		// Reporting 0 is indistinguishable from a real port reading.
		k.HealthCheckNodePort.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(s.Spec.HealthCheckNodePort), nil
}

func (k *mqlK8sService) selector() (map[string]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(s.Spec.Selector), nil
}

func (k *mqlK8sService) ports() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(s.Spec.Ports)
}

func (k *mqlK8sService) loadBalancerIngress() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(s.Status.LoadBalancer.Ingress)
}

func (k *mqlK8sService) endpointSlices() ([]any, error) {
	s, err := k.getService()
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	slices := o.(*mqlK8s).GetEndpointSlices()
	if slices.Error != nil {
		return nil, slices.Error
	}

	out := []any{}
	for i := range slices.Data {
		es, ok := slices.Data[i].(*mqlK8sEndpointslice)
		if !ok {
			continue
		}
		if es.Namespace.Data != s.Namespace {
			continue
		}
		labels := es.GetLabels()
		if labels.Error != nil {
			continue
		}
		svcName, _ := labels.Data["kubernetes.io/service-name"].(string)
		if svcName != s.Name {
			continue
		}
		out = append(out, es)
	}
	return out, nil
}

func (k *mqlK8sService) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sService) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

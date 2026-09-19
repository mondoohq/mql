// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sHorizontalpodautoscalerInternal struct {
	lock sync.Mutex
	obj  *autoscalingv2.HorizontalPodAutoscaler
}

func (k *mqlK8s) horizontalPodAutoscalers() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(autoscalingv2.SchemeGroupVersion.WithKind("horizontalpodautoscalers")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		hpa, ok := resource.(*autoscalingv2.HorizontalPodAutoscaler)
		if !ok {
			return nil, errors.New("not a k8s horizontalpodautoscaler")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.horizontalpodautoscaler", map[string]*llx.RawData{
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
		r.(*mqlK8sHorizontalpodautoscaler).obj = hpa
		return r, nil
	})
}

func (k *mqlK8sHorizontalpodautoscaler) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sHorizontalpodautoscaler) spec() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec)
}

func (k *mqlK8sHorizontalpodautoscaler) status() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status)
}

func (k *mqlK8sHorizontalpodautoscaler) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sHorizontalpodautoscaler(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sHorizontalpodautoscaler](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetHorizontalPodAutoscalers() })
}

func (k *mqlK8sHorizontalpodautoscaler) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sHorizontalpodautoscaler) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetApiVersion() (string, error) {
	return k.obj.Spec.ScaleTargetRef.APIVersion, nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetKind() (string, error) {
	return k.obj.Spec.ScaleTargetRef.Kind, nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetName() (string, error) {
	return k.obj.Spec.ScaleTargetRef.Name, nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetDeployment() (*mqlK8sDeployment, error) {
	if k.obj.Spec.ScaleTargetRef.Kind != "Deployment" || k.obj.Spec.ScaleTargetRef.Name == "" {
		k.ScaleTargetDeployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.deployment", map[string]*llx.RawData{
		"name":      llx.StringData(k.obj.Spec.ScaleTargetRef.Name),
		"namespace": llx.StringData(k.obj.Namespace),
	})
	if err != nil {
		// HPAs can survive their scale target mid-deletion. Resolve to
		// null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ScaleTargetDeployment.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sDeployment), nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetStatefulSet() (*mqlK8sStatefulset, error) {
	if k.obj.Spec.ScaleTargetRef.Kind != "StatefulSet" || k.obj.Spec.ScaleTargetRef.Name == "" {
		k.ScaleTargetStatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.statefulset", map[string]*llx.RawData{
		"name":      llx.StringData(k.obj.Spec.ScaleTargetRef.Name),
		"namespace": llx.StringData(k.obj.Namespace),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.ScaleTargetStatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sStatefulset), nil
}

func (k *mqlK8sHorizontalpodautoscaler) scaleTargetReplicaSet() (*mqlK8sReplicaset, error) {
	if k.obj.Spec.ScaleTargetRef.Kind != "ReplicaSet" || k.obj.Spec.ScaleTargetRef.Name == "" {
		k.ScaleTargetReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.replicaset", map[string]*llx.RawData{
		"name":      llx.StringData(k.obj.Spec.ScaleTargetRef.Name),
		"namespace": llx.StringData(k.obj.Namespace),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.ScaleTargetReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sReplicaset), nil
}

func (k *mqlK8sHorizontalpodautoscaler) minReplicas() (int64, error) {
	if k.obj.Spec.MinReplicas == nil {
		return 1, nil
	}
	return int64(*k.obj.Spec.MinReplicas), nil
}

func (k *mqlK8sHorizontalpodautoscaler) maxReplicas() (int64, error) {
	return int64(k.obj.Spec.MaxReplicas), nil
}

func (k *mqlK8sHorizontalpodautoscaler) metrics() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.Metrics)
}

func (k *mqlK8sHorizontalpodautoscaler) behavior() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.Behavior)
}

func (k *mqlK8sHorizontalpodautoscaler) observedGeneration() (int64, error) {
	if k.obj.Status.ObservedGeneration == nil {
		k.ObservedGeneration.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *k.obj.Status.ObservedGeneration, nil
}

func (k *mqlK8sHorizontalpodautoscaler) lastScaleTime() (*time.Time, error) {
	if k.obj.Status.LastScaleTime == nil {
		k.LastScaleTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := k.obj.Status.LastScaleTime.Time
	return &t, nil
}

func (k *mqlK8sHorizontalpodautoscaler) currentReplicas() (int64, error) {
	return int64(k.obj.Status.CurrentReplicas), nil
}

func (k *mqlK8sHorizontalpodautoscaler) desiredReplicas() (int64, error) {
	return int64(k.obj.Status.DesiredReplicas), nil
}

func (k *mqlK8sHorizontalpodautoscaler) currentMetrics() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.CurrentMetrics)
}

func (k *mqlK8sHorizontalpodautoscaler) conditions() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.Conditions)
}

func (k *mqlK8sHorizontalpodautoscaler) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sHorizontalpodautoscaler) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

type mqlK8sApiserviceInternal struct {
	lock sync.Mutex
	obj  *apiregistrationv1.APIService
}

func (k *mqlK8s) apiServices() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(apiregistrationv1.SchemeGroupVersion.WithKind("APIService")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		as, ok := resource.(*apiregistrationv1.APIService)
		if !ok {
			return nil, errors.New("not a k8s apiservice")
		}

		insecureSkipTLSVerify := as.Spec.InsecureSkipTLSVerify
		caBundle := string(as.Spec.CABundle)

		var serviceName, serviceNamespace string
		var servicePort int64
		if as.Spec.Service != nil {
			serviceName = as.Spec.Service.Name
			serviceNamespace = as.Spec.Service.Namespace
			if as.Spec.Service.Port != nil {
				servicePort = int64(*as.Spec.Service.Port)
			}
		}

		conditions, err := convert.JsonToDictSlice(as.Status.Conditions)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.apiservice", map[string]*llx.RawData{
			"id":                    llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                   llx.StringData(string(obj.GetUID())),
			"resourceVersion":       llx.StringData(obj.GetResourceVersion()),
			"name":                  llx.StringData(obj.GetName()),
			"kind":                  llx.StringData(objT.GetKind()),
			"created":               llx.TimeData(ts.Time),
			"group":                 llx.StringData(as.Spec.Group),
			"version":               llx.StringData(as.Spec.Version),
			"insecureSkipTLSVerify": llx.BoolData(insecureSkipTLSVerify),
			"caBundle":              llx.StringData(caBundle),
			"groupPriorityMinimum":  llx.IntData(int64(as.Spec.GroupPriorityMinimum)),
			"versionPriority":       llx.IntData(int64(as.Spec.VersionPriority)),
			"serviceName":           llx.StringData(serviceName),
			"serviceNamespace":      llx.StringData(serviceNamespace),
			"servicePort":           llx.IntData(servicePort),
			"conditions":            llx.ArrayData(conditions, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sApiservice).obj = as
		return r, nil
	})
}

func (k *mqlK8sApiservice) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sApiservice) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sApiservice) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sApiservice) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sApiservice) service() (*mqlK8sService, error) {
	name := k.ServiceName.Data
	namespace := k.ServiceNamespace.Data
	if name == "" || namespace == "" {
		k.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	services := o.(*mqlK8s).GetServices()
	if services.Error != nil {
		return nil, services.Error
	}

	for i := range services.Data {
		svc, ok := services.Data[i].(*mqlK8sService)
		if !ok {
			continue
		}
		if svc.Name.Data == name && svc.Namespace.Data == namespace {
			return svc, nil
		}
	}

	k.Service.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func initK8sApiservice(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sApiservice](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetApiServices() })
}

func (k *mqlK8sApiservice) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sApiservice) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

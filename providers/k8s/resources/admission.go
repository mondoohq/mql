// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sAdmissionrequestInternal struct {
	lock sync.Mutex
	obj  *admissionv1.AdmissionRequest
}

func (k *mqlK8sAdmissionreview) request() (*mqlK8sAdmissionrequest, error) {
	kt, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}

	result, err := kt.AdmissionReviews()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		k.Request.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// At the moment we don't support scanning >1 admission review at a time.
	if len(result) > 1 {
		return nil, fmt.Errorf("received more than 1 admission review")
	}

	aRequest := result[0].Request
	if aRequest == nil {
		k.Request.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"name":      llx.StringData(aRequest.Name),
		"namespace": llx.StringData(aRequest.Namespace),
		"operation": llx.StringData(string(aRequest.Operation)),
	}

	// The incoming object is empty on DELETE requests (the object lives in
	// oldObject instead), so guard against an empty parse result rather than
	// indexing obj[0] unconditionally.
	obj, err := resources.ResourcesFromManifest(bytes.NewReader(aRequest.Object.Raw))
	if err != nil {
		return nil, err
	}
	if len(obj) == 1 {
		objDict, err := convert.JsonToDict(obj[0])
		if err != nil {
			return nil, err
		}
		args["object"] = llx.DictData(objDict)
	} else {
		args["object"] = llx.NilData
	}

	args["oldObject"] = llx.NilData
	if len(aRequest.OldObject.Raw) > 0 {
		oldObj, err := resources.ResourcesFromManifest(bytes.NewReader(aRequest.OldObject.Raw))
		if err != nil {
			return nil, err
		}
		if len(oldObj) == 1 {
			oldObjDict, err := convert.JsonToDict(oldObj[0])
			if err != nil {
				return nil, err
			}
			args["oldObject"] = llx.DictData(oldObjDict)
		}
	}

	r, err := CreateResource(k.MqlRuntime, "k8s.admissionrequest", args)
	if err != nil {
		return nil, err
	}
	admReqRes := r.(*mqlK8sAdmissionrequest)
	admReqRes.obj = aRequest

	return admReqRes, nil
}

func (k *mqlK8sAdmissionrequest) userInfo() (*mqlK8sUserinfo, error) {
	userInfo := k.obj.UserInfo
	r, err := CreateResource(k.MqlRuntime, "k8s.userinfo", map[string]*llx.RawData{
		"username": llx.StringData(userInfo.Username),
		"uid":      llx.StringData(userInfo.UID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlK8sUserinfo), nil
}

func (k *mqlK8sAdmissionrequest) id() (string, error) {
	return k.Name.Data, nil
}

func (k *mqlK8sUserinfo) id() (string, error) {
	return k.Username.Data, nil
}

type mqlK8sAdmissionValidatingwebhookconfigurationInternal struct {
	lock sync.Mutex
	obj  *admissionregistrationv1.ValidatingWebhookConfiguration
}

func (k *mqlK8s) validatingWebhookConfigurations() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		vwc, ok := resource.(*admissionregistrationv1.ValidatingWebhookConfiguration)
		if !ok {
			return nil, errors.New("not a k8s validatingwebhookconfiguration")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.admission.validatingwebhookconfiguration", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sAdmissionValidatingwebhookconfiguration).obj = vwc
		return r, nil
	})
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) webhooks() ([]any, error) {
	dict, err := convert.JsonToDictSlice(k.obj.Webhooks)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

// failsOpen reports whether any webhook has failurePolicy: Ignore, meaning
// admission proceeds when the webhook is unreachable or errors — the guardrail
// can be bypassed by making it fail. An unset failurePolicy defaults to Fail.
func (k *mqlK8sAdmissionValidatingwebhookconfiguration) failsOpen() (bool, error) {
	for i := range k.obj.Webhooks {
		fp := k.obj.Webhooks[i].FailurePolicy
		if fp != nil && *fp == admissionregistrationv1.Ignore {
			return true, nil
		}
	}
	return false, nil
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sAdmissionValidatingwebhookconfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sAdmissionValidatingwebhookconfiguration](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] {
		return k.GetValidatingWebhookConfigurations()
	})
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sAdmissionValidatingwebhookconfiguration) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

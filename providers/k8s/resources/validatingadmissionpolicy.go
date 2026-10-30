// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sAdmissionValidatingadmissionpolicyInternal struct {
	obj *admissionregistrationv1.ValidatingAdmissionPolicy
}

func (k *mqlK8s) validatingAdmissionPolicies() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicy")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		vap, ok := resource.(*admissionregistrationv1.ValidatingAdmissionPolicy)
		if !ok {
			return nil, errors.New("not a k8s validatingadmissionpolicy")
		}

		failurePolicy := ""
		if vap.Spec.FailurePolicy != nil {
			failurePolicy = string(*vap.Spec.FailurePolicy)
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.admission.validatingadmissionpolicy", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"failurePolicy":   llx.StringData(failurePolicy),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sAdmissionValidatingadmissionpolicy).obj = vap
		return r, nil
	})
}

func initK8sAdmissionValidatingadmissionpolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sAdmissionValidatingadmissionpolicy](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] {
		return k.GetValidatingAdmissionPolicies()
	})
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) validations() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.Validations)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) matchConditions() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.MatchConditions)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) matchConstraints() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.MatchConstraints)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) variables() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.Variables)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) auditAnnotations() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.AuditAnnotations)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) paramKind() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.ParamKind)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) bindings() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	bindings := o.(*mqlK8s).GetValidatingAdmissionPolicyBindings()
	if bindings.Error != nil {
		return nil, bindings.Error
	}

	policyName := k.Name.Data
	out := []any{}
	for i := range bindings.Data {
		b, ok := bindings.Data[i].(*mqlK8sAdmissionValidatingadmissionpolicybinding)
		if !ok {
			continue
		}
		if b.obj.Spec.PolicyName == policyName {
			out = append(out, b)
		}
	}
	return out, nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicy) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

type mqlK8sAdmissionValidatingadmissionpolicybindingInternal struct {
	obj *admissionregistrationv1.ValidatingAdmissionPolicyBinding
}

func (k *mqlK8s) validatingAdmissionPolicyBindings() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicyBinding")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		vapb, ok := resource.(*admissionregistrationv1.ValidatingAdmissionPolicyBinding)
		if !ok {
			return nil, errors.New("not a k8s validatingadmissionpolicybinding")
		}

		validationActions := make([]any, 0, len(vapb.Spec.ValidationActions))
		for _, a := range vapb.Spec.ValidationActions {
			validationActions = append(validationActions, string(a))
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.admission.validatingadmissionpolicybinding", map[string]*llx.RawData{
			"id":                llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":               llx.StringData(string(obj.GetUID())),
			"resourceVersion":   llx.StringData(obj.GetResourceVersion()),
			"name":              llx.StringData(obj.GetName()),
			"kind":              llx.StringData(objT.GetKind()),
			"created":           llx.TimeData(ts.Time),
			"policyName":        llx.StringData(vapb.Spec.PolicyName),
			"validationActions": llx.ArrayData(validationActions, types.String),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sAdmissionValidatingadmissionpolicybinding).obj = vapb
		return r, nil
	})
}

func initK8sAdmissionValidatingadmissionpolicybinding(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sAdmissionValidatingadmissionpolicybinding](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] {
		return k.GetValidatingAdmissionPolicyBindings()
	})
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) paramRef() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.ParamRef)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) matchResources() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.MatchResources)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) policy() (*mqlK8sAdmissionValidatingadmissionpolicy, error) {
	if k.obj.Spec.PolicyName == "" {
		k.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.admission.validatingadmissionpolicy", map[string]*llx.RawData{
		"name": llx.StringData(k.obj.Spec.PolicyName),
	})
	if err != nil {
		// A referenced policy can have been deleted while the binding remains.
		// Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Policy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sAdmissionValidatingadmissionpolicy), nil
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sAdmissionValidatingadmissionpolicybinding) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

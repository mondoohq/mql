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
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sCertificatesigningrequestInternal struct {
	lock sync.Mutex
	obj  *certificatesv1.CertificateSigningRequest
}

func (k *mqlK8s) certificateSigningRequests() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(certificatesv1.SchemeGroupVersion.WithKind("CertificateSigningRequest")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		csr, ok := resource.(*certificatesv1.CertificateSigningRequest)
		if !ok {
			return nil, errors.New("not a k8s certificatesigningrequest")
		}

		usages := make([]any, len(csr.Spec.Usages))
		for i, u := range csr.Spec.Usages {
			usages[i] = string(u)
		}

		conditions, err := convert.JsonToDictSlice(csr.Status.Conditions)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.certificatesigningrequest", map[string]*llx.RawData{
			"id":                llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":               llx.StringData(string(obj.GetUID())),
			"resourceVersion":   llx.StringData(obj.GetResourceVersion()),
			"name":              llx.StringData(obj.GetName()),
			"kind":              llx.StringData(objT.GetKind()),
			"created":           llx.TimeData(ts.Time),
			"request":           llx.StringData(string(csr.Spec.Request)),
			"signerName":        llx.StringData(csr.Spec.SignerName),
			"expirationSeconds": llx.IntDataPtr(csr.Spec.ExpirationSeconds),
			"usages":            llx.ArrayData(usages, types.String),
			"username":          llx.StringData(csr.Spec.Username),
			"requesterUid":      llx.StringData(csr.Spec.UID),
			"groups":            llx.ArrayData(convert.SliceAnyToInterface(csr.Spec.Groups), types.String),
			"certificate":       llx.StringData(string(csr.Status.Certificate)),
			"conditions":        llx.ArrayData(conditions, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sCertificatesigningrequest).obj = csr
		return r, nil
	})
}

func (k *mqlK8sCertificatesigningrequest) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sCertificatesigningrequest) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sCertificatesigningrequest) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sCertificatesigningrequest) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sCertificatesigningrequest(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sCertificatesigningrequest](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetCertificateSigningRequests() })
}

func (k *mqlK8sCertificatesigningrequest) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sCertificatesigningrequest) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

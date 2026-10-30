// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/pem"
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sSecretInternal struct {
	lock    sync.Mutex
	obj     *corev1.Secret
	metaObj metav1.Object
}

func (k *mqlK8s) secrets() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("secrets")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		s, ok := resource.(*corev1.Secret)
		if !ok {
			return nil, errors.New("not a k8s secret")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.secret", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"type":            llx.StringData(string(s.Type)),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sSecret).obj = s
		r.(*mqlK8sSecret).metaObj = obj
		return r, nil
	})
}

func (k *mqlK8sSecret) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sSecret) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sSecret](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetSecrets() })
}

func (k *mqlK8sSecret) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sSecret) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sSecret) certificates() ([]any, error) {
	if k.obj.Type != corev1.SecretTypeTLS {
		// this is not an error, it just does not contain a certificate
		return nil, nil
	}

	// Re-encode only the blocks that actually parse. A tls.crt that is
	// truncated, garbage, or carries a stray non-certificate block must not
	// fail the whole field — report the certificates the secret does hold, the
	// way the sibling hygiene predicates already do. The API server accepts
	// such a Secret, so it is a real state, not a scan error.
	certs := k.tlsCertificates()
	if len(certs) == 0 {
		return nil, nil
	}

	var buf bytes.Buffer
	for _, cert := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}

	c, err := k.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(buf.String()),
	})
	if err != nil {
		return nil, err
	}

	list, err := k.MqlRuntime.GetSharedData("certificates", c.MqlID(), "list")
	if err != nil {
		return nil, err
	}

	return list.Value.([]any), nil
}

func (k *mqlK8sSecret) usedBy() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	pods := o.(*mqlK8s).GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	secretName := k.Name.Data
	namespace := k.Namespace.Data

	out := []any{}
	for i := range pods.Data {
		p, ok := pods.Data[i].(*mqlK8sPod)
		if !ok {
			continue
		}
		if p.Namespace.Data != namespace {
			continue
		}
		pod, err := p.getPod()
		if err != nil {
			continue
		}
		if podReferencesSecret(pod, secretName) {
			out = append(out, p)
		}
	}
	return out, nil
}

func podReferencesSecret(pod *corev1.Pod, secretName string) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil && v.Secret.SecretName == secretName {
			return true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil && src.Secret.Name == secretName {
					return true
				}
			}
		}
	}
	for _, ips := range pod.Spec.ImagePullSecrets {
		if ips.Name == secretName {
			return true
		}
	}
	for _, c := range pod.Spec.Containers {
		if containerReferencesSecret(c, secretName) {
			return true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if containerReferencesSecret(c, secretName) {
			return true
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if containerReferencesSecret(corev1.Container(c.EphemeralContainerCommon), secretName) {
			return true
		}
	}
	return false
}

func containerReferencesSecret(c corev1.Container, secretName string) bool {
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && e.ValueFrom.SecretKeyRef.Name == secretName {
			return true
		}
	}
	for _, ef := range c.EnvFrom {
		if ef.SecretRef != nil && ef.SecretRef.Name == secretName {
			return true
		}
	}
	return false
}

func (k *mqlK8sSecret) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sSecret) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

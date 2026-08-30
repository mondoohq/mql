// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sIngressInternal struct {
	lock  sync.Mutex
	obj   runtime.Object
	objId string
}

func (k *mqlK8sIngress) getIngress() (*networkingv1.Ingress, error) {
	ing, ok := k.obj.(*networkingv1.Ingress)
	if ok {
		return ing, nil
	}
	return nil, errors.New("invalid k8s ingress")
}

func (k *mqlK8s) ingresses() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(networkingv1.SchemeGroupVersion.WithKind("ingresses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		ingress, ok := resource.(*networkingv1.Ingress)
		if !ok {
			return nil, errors.New("not a k8s ingress")
		}

		objId := objIdFromK8sObj(obj, objT)

		rules, err := buildRules(ingress, objId, k.MqlRuntime)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.ingress", map[string]*llx.RawData{
			"id":              llx.StringData(objId),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"rules":           llx.ArrayData(rules, types.Resource("k8s.ingressrule")),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sIngress).obj = ingress
		r.(*mqlK8sIngress).objId = objId
		return r, nil
	})
}

func (k *mqlK8sIngress) tls() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	k8s := o.(*mqlK8s)

	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	tls, err := getTLS(ing, k.objId, k.MqlRuntime, k8s.GetSecrets)
	if err != nil {
		return nil, err
	}

	return tls, nil
}

func (k *mqlK8sIngress) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sIngress) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sIngress(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sIngress](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetIngresses() })
}

func (k *mqlK8sIngress) annotations() (map[string]any, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(ing.GetAnnotations()), nil
}

func (k *mqlK8sIngress) labels() (map[string]any, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(ing.GetLabels()), nil
}

func (k *mqlK8sIngress) ingressClassName() (string, error) {
	ing, err := k.getIngress()
	if err != nil {
		return "", err
	}
	if ing.Spec.IngressClassName == nil {
		return "", nil
	}
	return *ing.Spec.IngressClassName, nil
}

func (k *mqlK8sIngress) ingressClass() (*mqlK8sIngressclass, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	className := ""
	if ing.Spec.IngressClassName != nil {
		className = *ing.Spec.IngressClassName
	}
	if className == "" {
		className = ing.GetAnnotations()["kubernetes.io/ingress.class"]
	}
	if className == "" {
		return k.defaultIngressClass()
	}
	return k.ingressClassByName(className)
}

func (k *mqlK8sIngress) ingressClassByName(name string) (*mqlK8sIngressclass, error) {
	ic, err := NewResource(k.MqlRuntime, "k8s.ingressclass", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		// IngressClass is cluster-scoped, so it isn't loaded when queried
		// from a namespace-scoped asset, and a referenced IngressClass can
		// genuinely have been deleted. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.IngressClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return ic.(*mqlK8sIngressclass), nil
}

func (k *mqlK8sIngress) defaultIngressClass() (*mqlK8sIngressclass, error) {
	obj, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	classes := obj.(*mqlK8s).GetIngressClasses()
	if classes.Error != nil {
		return nil, classes.Error
	}
	var defaultClass *mqlK8sIngressclass
	for _, item := range classes.Data {
		ic, ok := item.(*mqlK8sIngressclass)
		if !ok {
			continue
		}
		if ic.GetAnnotations().Data["ingressclass.kubernetes.io/is-default-class"] != "true" {
			continue
		}
		if defaultClass != nil {
			k.IngressClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		defaultClass = ic
	}
	if defaultClass == nil {
		k.IngressClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return defaultClass, nil
}

func (k *mqlK8sIngress) loadBalancerIngress() ([]any, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(ing.Status.LoadBalancer.Ingress)
}

func buildRules(ingress *networkingv1.Ingress, objId string, runtime *plugin.Runtime) ([]any, error) {
	k8sIngressRules := []any{}

	for i, rule := range ingress.Spec.Rules {
		paths := []any{}
		ruleId := fmt.Sprintf("%s/rule%d", objId, i)

		if rule.HTTP != nil {
			for i, path := range rule.HTTP.Paths {
				pathId := fmt.Sprintf("%s/path%d", ruleId, i)
				ingresshttprulepath, err := buildIngressHttpRulePaths(path, pathId, runtime)
				if err != nil {
					return nil, err
				}
				paths = append(paths, ingresshttprulepath)
			}
		}

		ingressRule, err := CreateResource(runtime, "k8s.ingressrule", map[string]*llx.RawData{
			"id":        llx.StringData(ruleId),
			"host":      llx.StringData(rule.Host),
			"httpPaths": llx.ArrayData(paths, types.Resource("k8s.ingresshttprulepath")),
		})
		if err != nil {
			return nil, fmt.Errorf("error creating k8s.ingressrule: %s", err)
		}

		k8sIngressRules = append(k8sIngressRules, ingressRule)
	}

	return k8sIngressRules, nil
}

func buildIngressHttpRulePaths(path networkingv1.HTTPIngressPath, id string, runtime *plugin.Runtime) (plugin.Resource, error) {
	pathType := ""

	if path.PathType != nil {
		pathType = string(*path.PathType)
	}

	ingressbackend, err := buildIngressBackend(path.Backend, id, runtime)
	if err != nil {
		return nil, err
	}

	ingresshttprulepath, err := CreateResource(runtime, "k8s.ingresshttprulepath", map[string]*llx.RawData{
		"id":       llx.StringData(id),
		"path":     llx.StringData(path.Path),
		"pathType": llx.StringData(pathType),
		"backend":  llx.ResourceData(ingressbackend, "k8s.ingressbackend"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating k8s.ingresshttprulepath: %s", err)
	}

	return ingresshttprulepath, nil
}

func buildIngressBackend(networkingIngressBackend networkingv1.IngressBackend, id string, runtime *plugin.Runtime) (plugin.Resource, error) {
	ingressservicebackend, err := buildIngressServiceBackend(networkingIngressBackend.Service, id, runtime)
	if err != nil {
		return nil, err
	}

	ingressresourceref, err := buildIngressResourceRefBackend(networkingIngressBackend.Resource, id, runtime)
	if err != nil {
		return nil, err
	}

	backendId := id
	if networkingIngressBackend.Service != nil {
		backendId = backendId + "/service"
	}

	if networkingIngressBackend.Resource != nil {
		backendId = backendId + "/resourceRef"
	}
	ingressbackend, err := CreateResource(runtime, "k8s.ingressbackend", map[string]*llx.RawData{
		"id":          llx.StringData(backendId),
		"service":     llx.ResourceData(ingressservicebackend, "k8s.ingressservicebackend"),
		"resourceRef": llx.ResourceData(ingressresourceref, "k8s.ingressresourceref"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating k8s.ingressbackend: %s", err)
	}

	return ingressbackend, nil
}

func buildIngressServiceBackend(networkingIngressServiceBackend *networkingv1.IngressServiceBackend, id string, runtime *plugin.Runtime) (plugin.Resource, error) {
	ingressServiceBackendName := ""
	portName := ""
	var portNumber int64
	if networkingIngressServiceBackend != nil {
		ingressServiceBackendName = networkingIngressServiceBackend.Name
		portName = networkingIngressServiceBackend.Port.Name
		portNumber = int64(networkingIngressServiceBackend.Port.Number)
	}

	svcId := fmt.Sprintf("%s/%s-%s-%d", id, ingressServiceBackendName, portName, portNumber)
	ingressservicebackend, err := CreateResource(runtime, "k8s.ingressservicebackend", map[string]*llx.RawData{
		"id":         llx.StringData(svcId),
		"name":       llx.StringData(ingressServiceBackendName),
		"portName":   llx.StringData(portName),
		"portNumber": llx.IntData(portNumber),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating k8s.ingresservicebackend: %s", err)
	}
	return ingressservicebackend, nil
}

func buildIngressResourceRefBackend(corev1ResourceRef *corev1.TypedLocalObjectReference, id string, runtime *plugin.Runtime) (plugin.Resource, error) {
	apiGroup := ""
	kind := ""
	name := ""
	if corev1ResourceRef != nil {
		if corev1ResourceRef.APIGroup != nil {
			apiGroup = *corev1ResourceRef.APIGroup
		}
		kind = corev1ResourceRef.Kind
		name = corev1ResourceRef.Name
	}

	resRefId := fmt.Sprintf("%s/%s-%s-%s", id, apiGroup, kind, name)
	ingressresourceref, err := CreateResource(runtime, "k8s.ingressresourceref", map[string]*llx.RawData{
		"id":       llx.StringData(resRefId),
		"apiGroup": llx.StringData(apiGroup),
		"kind":     llx.StringData(kind),
		"name":     llx.StringData(name),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating k8s.ingressresourceref: %s", err)
	}
	return ingressresourceref, nil
}

func (k *mqlK8sIngressrule) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngresshttprulepath) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngressbackend) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngressservicebackend) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngressresourceref) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngresstls) id() (string, error) {
	return k.Id.Data, nil
}

func getTLS(ingress *networkingv1.Ingress, objId string, runtime *plugin.Runtime, getSecrets func() *plugin.TValue[[]any]) ([]any, error) {
	tlsData := []any{}
	if len(ingress.Spec.TLS) > 0 {
		// This returns ALL Secrets found in the cluster!
		secretsInterface := getSecrets()
		if secretsInterface.Error != nil {
			return nil, fmt.Errorf("failed to fetch Secrets referenced in Ingress: %s", secretsInterface.Error)
		}

		// Build up a map of Secrets found in the same Namespace as this Ingress resource
		secrets := map[string]*mqlK8sSecret{}
		for _, secInterface := range secretsInterface.Data {
			secret, ok := secInterface.(*mqlK8sSecret)
			if !ok {
				return nil, errors.New("returned list of Secrets failed type assertion")
			}

			if ingress.Namespace != secret.Namespace.Data {
				continue
			}

			secrets[secret.Name.Data] = secret
		}

		// There is the potential for no Secret to be found or that a Secret
		// is found (can happen when scanning static manifest files or simply an Ingress
		// which references a non-existent Secret) but either improperly-formatted
		// or simply not containing TLS data. In either event just keep trying to
		// process as much as we can.
		for i, tls := range ingress.Spec.TLS {
			secret, ok := secrets[tls.SecretName]
			if !ok {
				continue
			}

			certs := secret.GetCertificates()
			if certs.Error != nil {
				// A Secret whose tls.crt is absent or not parseable as PEM is a
				// property of this one entry, not of the Ingress. Skip it and keep
				// the remaining entries, the same way a missing Secret and a Secret
				// with no TLS data are handled.
				log.Debug().Err(certs.Error).
					Str("ingress", ingress.Name).
					Str("secret", tls.SecretName).
					Msg("skipping ingress TLS entry whose certificate could not be read")
				continue
			}
			if certs.Data == nil || len(certs.Data) == 0 {
				// no TLS data in Secret referenced
				// k8s will allow this, so we'll just follow along with this being
				// a non-critical issue and skip processing the Secret
				continue
			}

			ingressTls, err := CreateResource(runtime, "k8s.ingresstls", map[string]*llx.RawData{
				"id":           llx.StringData(fmt.Sprintf("%s-tls%d", objId, i)),
				"hosts":        llx.ArrayData(convert.SliceAnyToInterface(tls.Hosts), types.String),
				"certificates": llx.ArrayData(secret.Certificates.Data, types.Resource("network.certificate")),
			})
			if err != nil {
				return nil, fmt.Errorf("error creating k8s.ingresstls: %s", err)
			}

			tlsData = append(tlsData, ingressTls)
		}
	}

	return tlsData, nil
}

func (k *mqlK8sIngress) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sIngress) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

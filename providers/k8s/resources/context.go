// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"reflect"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// manifestSourceProvider is implemented by the manifest connection. Live-cluster
// and admission connections do not implement it, so resources scanned that way
// carry no source context.
type manifestSourceProvider interface {
	ManifestSource() (contents map[string]string, positions map[string]shared.SourcePosition)
}

func (r *mqlK8sContext) id() (string, error) {
	if r.Path.Data == "" {
		return "", errors.New("need path to exist for k8s.context ID")
	}
	return r.Path.Data + ":" + r.Range.Data.String(), nil
}

func (r *mqlK8sContext) content(path string, rnge llx.Range) (string, error) {
	if path == "" {
		return "", errors.New("no path information for k8s.context")
	}
	ms, ok := r.MqlRuntime.Connection.(manifestSourceProvider)
	if !ok {
		return "", errors.New("k8s.context content is not available for this connection")
	}
	contents, _ := ms.ManifestSource()
	content, ok := contents[path]
	if !ok {
		return "", errors.New("no manifest content for k8s.context path " + path)
	}
	return rnge.ExtractString(content, llx.DefaultExtractConfig), nil
}

// setK8sSourceContext populates a resource's `context` field with the manifest
// location it was declared at. It is a no-op for connections without a source
// manifest, for resources not found in the manifest (e.g. synthesized CRDs),
// and for manifest content passed in directly, which has no file to point at.
// The field is set directly via reflection because the ~40 annotated
// resource types share no common concrete type; every @context-annotated
// resource has an exported `Context` field of the same type.
func setK8sSourceContext(runtime *plugin.Runtime, kt shared.Connection, obj metav1.Object, objT metav1.Type, res any) error {
	ms, ok := kt.(manifestSourceProvider)
	if !ok {
		return nil
	}
	contents, positions := ms.ManifestSource()
	if len(positions) == 0 {
		return nil
	}
	pos, ok := positions[objIdFromFields(objT.GetKind(), obj.GetNamespace(), obj.GetName())]
	if !ok || pos.Path == "" {
		return nil
	}

	rnge := llx.NewRange().AddLineRange(uint32(pos.StartLine), uint32(pos.EndLine))
	ctxObj, err := CreateResource(runtime, "k8s.context", map[string]*llx.RawData{
		"path":    llx.StringData(pos.Path),
		"range":   llx.RangeData(rnge),
		"content": llx.StringData(rnge.ExtractString(contents[pos.Path], llx.DefaultExtractConfig)),
	})
	if err != nil {
		return err
	}

	rv := reflect.ValueOf(res)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return nil
	}
	field := rv.Elem().FieldByName("Context")
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(plugin.TValue[*mqlK8sContext]{
			Data:  ctxObj.(*mqlK8sContext),
			State: plugin.StateIsSet,
		}))
	}
	return nil
}

// The fallback context() resolvers below mark the field null rather than
// erroring. context is populated at creation for manifest-file scans; for
// live-cluster and admission connections it is legitimately absent, so a query
// touching .context there returns null instead of failing.

func (x *mqlK8sAdmissionMutatingwebhookconfiguration) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sAdmissionValidatingadmissionpolicy) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sAdmissionValidatingadmissionpolicybinding) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sAdmissionValidatingwebhookconfiguration) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sApiservice) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sCertificatesigningrequest) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sConfigmap) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sCronjob) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sCustomresource) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sDaemonset) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sDeployment) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sEndpointslice) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sGateway) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sGatewayclass) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sGrpcroute) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sHorizontalpodautoscaler) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sHttproute) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sIngress) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sIngressclass) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sJob) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sLease) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sLimitrange) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sNetworkpolicy) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sNode) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sPersistentvolume) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sPersistentvolumeclaim) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sPod) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sPoddisruptionbudget) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sPriorityclass) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sRbacClusterrole) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sRbacClusterrolebinding) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sRbacRole) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sRbacRolebinding) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sReferencegrant) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sReplicaset) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sResourcequota) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sRuntimeclass) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sSecret) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sService) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sServiceaccount) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sStatefulset) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlK8sStorageclass) context() (*mqlK8sContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

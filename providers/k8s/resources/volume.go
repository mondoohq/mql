// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
)

type mqlK8sVolumeInternal struct {
	vol       corev1.Volume
	namespace string
}

// volumeSourceType names the single populated member of a VolumeSource. A
// volume carries exactly one source, so the first match wins; an empty string
// means the volume declares no source at all, which the API server rejects but
// a hand-written manifest can still contain.
func volumeSourceType(vs corev1.VolumeSource) string {
	switch {
	case vs.HostPath != nil:
		return "hostPath"
	case vs.EmptyDir != nil:
		return "emptyDir"
	case vs.Secret != nil:
		return "secret"
	case vs.ConfigMap != nil:
		return "configMap"
	case vs.Projected != nil:
		return "projected"
	case vs.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case vs.CSI != nil:
		return "csi"
	case vs.DownwardAPI != nil:
		return "downwardAPI"
	case vs.Ephemeral != nil:
		return "ephemeral"
	case vs.NFS != nil:
		return "nfs"
	case vs.ISCSI != nil:
		return "iscsi"
	case vs.FC != nil:
		return "fc"
	case vs.RBD != nil:
		return "rbd"
	case vs.CephFS != nil:
		return "cephfs"
	case vs.Cinder != nil:
		return "cinder"
	case vs.Glusterfs != nil:
		return "glusterfs"
	case vs.AWSElasticBlockStore != nil:
		return "awsElasticBlockStore"
	case vs.AzureDisk != nil:
		return "azureDisk"
	case vs.AzureFile != nil:
		return "azureFile"
	case vs.GCEPersistentDisk != nil:
		return "gcePersistentDisk"
	case vs.VsphereVolume != nil:
		return "vsphereVolume"
	case vs.PortworxVolume != nil:
		return "portworxVolume"
	case vs.Quobyte != nil:
		return "quobyte"
	case vs.FlexVolume != nil:
		return "flexVolume"
	case vs.Flocker != nil:
		return "flocker"
	case vs.PhotonPersistentDisk != nil:
		return "photonPersistentDisk"
	case vs.ScaleIO != nil:
		return "scaleIO"
	case vs.StorageOS != nil:
		return "storageos"
	case vs.GitRepo != nil:
		return "gitRepo"
	case vs.Image != nil:
		return "image"
	default:
		return ""
	}
}

// volumeSecretNames lists every Secret the volume mounts, covering both a
// plain secret source and each secret source of a projected volume.
func volumeSecretNames(vs corev1.VolumeSource) []string {
	var out []string
	if vs.Secret != nil && vs.Secret.SecretName != "" {
		out = append(out, vs.Secret.SecretName)
	}
	if vs.Projected != nil {
		for i := range vs.Projected.Sources {
			src := vs.Projected.Sources[i]
			if src.Secret != nil && src.Secret.Name != "" {
				out = append(out, src.Secret.Name)
			}
		}
	}
	return out
}

// volumeConfigMapNames lists every ConfigMap the volume mounts, covering both
// a plain configMap source and each configMap source of a projected volume.
func volumeConfigMapNames(vs corev1.VolumeSource) []string {
	var out []string
	if vs.ConfigMap != nil && vs.ConfigMap.Name != "" {
		out = append(out, vs.ConfigMap.Name)
	}
	if vs.Projected != nil {
		for i := range vs.Projected.Sources {
			src := vs.Projected.Sources[i]
			if src.ConfigMap != nil && src.ConfigMap.Name != "" {
				out = append(out, src.ConfigMap.Name)
			}
		}
	}
	return out
}

// projectedServiceAccountTokens returns one entry per serviceAccountToken
// source of a projected volume. expirationSeconds stays null when the pod does
// not request a lifetime, because the kubelet then picks its own default and
// reporting a number here would claim the pod asked for one.
func projectedServiceAccountTokens(vs corev1.VolumeSource) []any {
	out := []any{}
	if vs.Projected == nil {
		return out
	}
	for i := range vs.Projected.Sources {
		sat := vs.Projected.Sources[i].ServiceAccountToken
		if sat == nil {
			continue
		}
		entry := map[string]any{
			"audience": sat.Audience,
			"path":     sat.Path,
		}
		if sat.ExpirationSeconds != nil {
			entry["expirationSeconds"] = *sat.ExpirationSeconds
		} else {
			entry["expirationSeconds"] = nil
		}
		out = append(out, entry)
	}
	return out
}

// newVolumes builds the k8s.volume resources for a pod spec. ownerID scopes
// the cache key: volume names are unique within one pod spec but repeat freely
// across pods and templates, so the key has to carry both dimensions.
func newVolumes(runtime *plugin.Runtime, ownerID, namespace string, spec *corev1.PodSpec) ([]any, error) {
	out := []any{}
	if spec == nil {
		return out, nil
	}

	for i := range spec.Volumes {
		v := spec.Volumes[i]

		source, err := convert.JsonToDict(v.VolumeSource)
		if err != nil {
			return nil, err
		}

		args := map[string]*llx.RawData{
			"__id":              llx.StringData(ownerID + "/volume/" + v.Name),
			"name":              llx.StringData(v.Name),
			"namespace":         llx.StringData(namespace),
			"type":              llx.StringData(volumeSourceType(v.VolumeSource)),
			"hostPath":          llx.NilData,
			"hostPathType":      llx.NilData,
			"emptyDirMedium":    llx.NilData,
			"emptyDirSizeLimit": llx.NilData,
			"csiDriver":         llx.NilData,
			"source":            llx.DictData(source),
		}

		if hp := v.HostPath; hp != nil {
			args["hostPath"] = llx.StringData(hp.Path)
			args["hostPathType"] = llx.StringDataPtr(stringPtrFromTypedPtr(hp.Type))
		}
		if ed := v.EmptyDir; ed != nil {
			args["emptyDirMedium"] = llx.StringData(string(ed.Medium))
			if ed.SizeLimit != nil {
				args["emptyDirSizeLimit"] = llx.StringData(ed.SizeLimit.String())
			}
		}
		if csi := v.CSI; csi != nil {
			args["csiDriver"] = llx.StringData(csi.Driver)
		}

		r, err := CreateResource(runtime, "k8s.volume", args)
		if err != nil {
			return nil, err
		}
		mqlVol := r.(*mqlK8sVolume)
		mqlVol.vol = v
		mqlVol.namespace = namespace
		out = append(out, mqlVol)
	}

	return out, nil
}

func (k *mqlK8sVolume) serviceAccountTokens() ([]any, error) {
	return projectedServiceAccountTokens(k.vol.VolumeSource), nil
}

func (k *mqlK8sVolume) secrets() ([]any, error) {
	return resolveNamespaced[*mqlK8sSecret](
		k.MqlRuntime, k.namespace, volumeSecretNames(k.vol.VolumeSource),
		func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetSecrets() })
}

func (k *mqlK8sVolume) configMaps() ([]any, error) {
	return resolveNamespaced[*mqlK8sConfigmap](
		k.MqlRuntime, k.namespace, volumeConfigMapNames(k.vol.VolumeSource),
		func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetConfigmaps() })
}

func (k *mqlK8sVolume) persistentVolumeClaim() (*mqlK8sPersistentvolumeclaim, error) {
	pvc := k.vol.VolumeSource.PersistentVolumeClaim
	if pvc == nil || pvc.ClaimName == "" {
		k.PersistentVolumeClaim.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	claims, err := resolveNamespaced[*mqlK8sPersistentvolumeclaim](
		k.MqlRuntime, k.namespace, []string{pvc.ClaimName},
		func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetPersistentVolumeClaims() })
	if err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		k.PersistentVolumeClaim.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	claim, ok := claims[0].(*mqlK8sPersistentvolumeclaim)
	if !ok {
		return nil, errors.New("not a k8s persistentvolumeclaim")
	}
	return claim, nil
}

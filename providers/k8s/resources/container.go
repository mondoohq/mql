// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ContainerType string

var (
	EphemeralContainerType ContainerType = "ephemeral"
	InitContainerType      ContainerType = "init"
	ContainerContainerType ContainerType = "container"
)

// containerSecurityContextArgs flattens the security-relevant fields of a
// container's SecurityContext into typed resource args. Pointer fields stay
// null when unset so policies can distinguish "not configured" from false.
//
// The string-valued confinement fields (seccomp, AppArmor, procMount, SELinux)
// stay empty when the container sets nothing, which is what lets a policy tell
// "this container asked for no confinement of its own, so the pod-level
// setting decides" apart from an explicit Unconfined.
func containerSecurityContextArgs(sc *corev1.SecurityContext) map[string]*llx.RawData {
	added := []any{}
	dropped := []any{}
	seccompType := ""
	appArmorType := ""
	procMount := ""
	seLinuxType := ""
	seLinuxLevel := ""

	var (
		privileged, allowPrivEsc, runAsNonRoot, readOnlyRoot *bool
		runAsUser, runAsGroup                                *int64
	)

	if sc != nil {
		privileged = sc.Privileged
		allowPrivEsc = sc.AllowPrivilegeEscalation
		runAsNonRoot = sc.RunAsNonRoot
		readOnlyRoot = sc.ReadOnlyRootFilesystem
		runAsUser = sc.RunAsUser
		runAsGroup = sc.RunAsGroup
		if sc.Capabilities != nil {
			for _, c := range sc.Capabilities.Add {
				added = append(added, string(c))
			}
			for _, c := range sc.Capabilities.Drop {
				dropped = append(dropped, string(c))
			}
		}
		if sc.SeccompProfile != nil {
			seccompType = string(sc.SeccompProfile.Type)
		}
		if sc.AppArmorProfile != nil {
			appArmorType = string(sc.AppArmorProfile.Type)
		}
		if sc.ProcMount != nil {
			procMount = string(*sc.ProcMount)
		}
		if sc.SELinuxOptions != nil {
			seLinuxType = sc.SELinuxOptions.Type
			seLinuxLevel = sc.SELinuxOptions.Level
		}
	}

	return map[string]*llx.RawData{
		"privileged":               llx.BoolDataPtr(privileged),
		"allowPrivilegeEscalation": llx.BoolDataPtr(allowPrivEsc),
		"runAsNonRoot":             llx.BoolDataPtr(runAsNonRoot),
		"runAsUser":                llx.IntDataPtr(runAsUser),
		"runAsGroup":               llx.IntDataPtr(runAsGroup),
		"readOnlyRootFilesystem":   llx.BoolDataPtr(readOnlyRoot),
		"addedCapabilities":        llx.ArrayData(added, types.String),
		"droppedCapabilities":      llx.ArrayData(dropped, types.String),
		"seccompProfileType":       llx.StringData(seccompType),
		"appArmorProfileType":      llx.StringData(appArmorType),
		"procMount":                llx.StringData(procMount),
		"seLinuxType":              llx.StringData(seLinuxType),
		"seLinuxLevel":             llx.StringData(seLinuxLevel),
	}
}

func getContainers(
	obj runtime.Object, meta metav1.Object, pluginRuntime *plugin.Runtime, containerType ContainerType,
) ([]any, error) {
	var containersFunc func(runtime.Object) ([]corev1.Container, error)
	resourceType := ""
	switch containerType {
	case EphemeralContainerType:
		containersFunc = resources.GetEphemeralContainers
		resourceType = "k8s.ephemeralContainer"
	case InitContainerType:
		containersFunc = resources.GetInitContainers
		resourceType = "k8s.initContainer"
	case ContainerContainerType:
		containersFunc = resources.GetContainers
		resourceType = "k8s.container"
	default:
		return nil, fmt.Errorf("unknown container type %s", containerType)
	}

	id, err := objId(obj, meta)
	if err != nil {
		return nil, err
	}

	resp := []any{}
	containers, err := containersFunc(obj)
	if err != nil {
		return nil, err
	}
	for i := range containers {

		c := containers[i]

		secContext, err := convert.JsonToDict(c.SecurityContext)
		if err != nil {
			return nil, err
		}

		volumeMounts, err := convert.JsonToDictSlice(c.VolumeMounts)
		if err != nil {
			return nil, err
		}

		volumeDevices, err := convert.JsonToDictSlice(c.VolumeDevices)
		if err != nil {
			return nil, err
		}

		env, err := convert.JsonToDictSlice(c.Env)
		if err != nil {
			return nil, err
		}

		envFrom, err := convert.JsonToDictSlice(c.EnvFrom)
		if err != nil {
			return nil, err
		}

		ports, err := convert.JsonToDictSlice(c.Ports)
		if err != nil {
			return nil, err
		}

		args := map[string]*llx.RawData{
			"uid":                      llx.StringData(id + "/" + c.Name), // container names are unique within a resource
			"name":                     llx.StringData(c.Name),
			"imageName":                llx.StringData(c.Image),
			"command":                  llx.ArrayData(convert.SliceAnyToInterface(c.Command), types.String),
			"args":                     llx.ArrayData(convert.SliceAnyToInterface(c.Args), types.String),
			"volumeMounts":             llx.ArrayData(volumeMounts, types.Dict),
			"volumeDevices":            llx.ArrayData(volumeDevices, types.Dict),
			"imagePullPolicy":          llx.StringData(string(c.ImagePullPolicy)),
			"securityContext":          llx.DictData(secContext),
			"workingDir":               llx.StringData(c.WorkingDir),
			"tty":                      llx.BoolData(c.TTY),
			"stdin":                    llx.BoolData(c.Stdin),
			"stdinOnce":                llx.BoolData(c.StdinOnce),
			"env":                      llx.ArrayData(env, types.Dict),
			"envFrom":                  llx.ArrayData(envFrom, types.Dict),
			"ports":                    llx.ArrayData(ports, types.Dict),
			"terminationMessagePath":   llx.StringData(c.TerminationMessagePath),
			"terminationMessagePolicy": llx.StringData(string(c.TerminationMessagePolicy)),
		}

		// flatten the common security-context fields so policies can read them
		// without digging through the raw securityContext dict
		for k, v := range containerSecurityContextArgs(c.SecurityContext) {
			args[k] = v
		}

		if containerType != EphemeralContainerType {
			resources, err := convert.JsonToDict(c.Resources)
			if err != nil {
				return nil, err
			}

			lifecycle, err := dictOrNil(c.Lifecycle)
			if err != nil {
				return nil, err
			}

			resizePolicy, err := convert.JsonToDictSlice(c.ResizePolicy)
			if err != nil {
				return nil, err
			}

			restartPolicy := ""
			if c.RestartPolicy != nil {
				restartPolicy = string(*c.RestartPolicy)
			}

			args["resources"] = llx.DictData(resources)
			args["lifecycle"] = dictDataOrNil(lifecycle)
			args["resizePolicy"] = llx.ArrayData(resizePolicy, types.Dict)
			args["restartPolicy"] = llx.StringData(restartPolicy)
		}

		if containerType == ContainerContainerType || containerType == InitContainerType {
			livenessProbe, err := dictOrNil(c.LivenessProbe)
			if err != nil {
				return nil, err
			}

			readinessProbe, err := dictOrNil(c.ReadinessProbe)
			if err != nil {
				return nil, err
			}

			startupProbe, err := dictOrNil(c.StartupProbe)
			if err != nil {
				return nil, err
			}

			args["livenessProbe"] = dictDataOrNil(livenessProbe)
			args["readinessProbe"] = dictDataOrNil(readinessProbe)
			args["startupProbe"] = dictDataOrNil(startupProbe)
		}

		mqlContainer, err := CreateResource(pluginRuntime, resourceType, args)
		if err != nil {
			return nil, err
		}
		resp = append(resp, mqlContainer)
	}
	return resp, nil
}

func (k *mqlK8sEphemeralContainer) id() (string, error) {
	return k.Uid.Data, nil
}

func (k *mqlK8sEphemeralContainer) containerImage() (plugin.Resource, error) {
	if k.ImageName.Error != nil {
		return nil, k.ImageName.Error
	}

	c, err := k.MqlRuntime.CreateSharedResource("container.image", map[string]*llx.RawData{
		"reference": llx.StringData(k.ImageName.Data),
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (k *mqlK8sInitContainer) id() (string, error) {
	return k.Uid.Data, nil
}

func (k *mqlK8sInitContainer) containerImage() (plugin.Resource, error) {
	if k.ImageName.Error != nil {
		return nil, k.ImageName.Error
	}

	c, err := k.MqlRuntime.CreateSharedResource("container.image", map[string]*llx.RawData{
		"reference": llx.StringData(k.ImageName.Data),
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (k *mqlK8sContainer) id() (string, error) {
	return k.Uid.Data, nil
}

func (k *mqlK8sContainer) containerImage() (plugin.Resource, error) {
	if k.ImageName.Error != nil {
		return nil, k.ImageName.Error
	}

	c, err := k.MqlRuntime.CreateSharedResource("container.image", map[string]*llx.RawData{
		"reference": llx.StringData(k.ImageName.Data),
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}

// dictOrNil converts p to a dict, or returns nil when p is a nil pointer, so an
// undeclared probe or lifecycle stays null rather than reading as {}.
// convert.JsonToDict starts from a non-nil map, so it turns nil into {}.
func dictOrNil[T any](p *T) (map[string]any, error) {
	if p == nil {
		return nil, nil
	}
	return convert.JsonToDict(p)
}

// dictDataOrNil wraps a dict for CreateResource, preserving a nil map as null.
func dictDataOrNil(d map[string]any) *llx.RawData {
	if d == nil {
		return llx.NilData
	}
	return llx.DictData(d)
}

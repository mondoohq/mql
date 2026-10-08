// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"slices"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// ociSpec is the part of an OCI runtime spec (config.json) that describes how
// a container is confined.
type ociSpec struct {
	Process *struct {
		User struct {
			UID uint32 `json:"uid"`
			GID uint32 `json:"gid"`
		} `json:"user"`
		Capabilities *struct {
			Bounding  []string `json:"bounding"`
			Effective []string `json:"effective"`
		} `json:"capabilities"`
		NoNewPrivileges bool   `json:"noNewPrivileges"`
		ApparmorProfile string `json:"apparmorProfile"`
		SelinuxLabel    string `json:"selinuxLabel"`
	} `json:"process"`
	Root *struct {
		Readonly bool `json:"readonly"`
	} `json:"root"`
	Mounts      []ociMount        `json:"mounts"`
	Annotations map[string]string `json:"annotations"`
	Linux       *struct {
		Namespaces []struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"namespaces"`
		Seccomp     json.RawMessage `json:"seccomp"`
		MaskedPaths []string        `json:"maskedPaths"`
		Resources   *struct {
			Memory *struct {
				Limit *int64 `json:"limit"`
			} `json:"memory"`
			CPU *struct {
				Shares *uint64 `json:"shares"`
				Quota  *int64  `json:"quota"`
				Period *uint64 `json:"period"`
			} `json:"cpu"`
			Pids *struct {
				Limit int64 `json:"limit"`
			} `json:"pids"`
		} `json:"resources"`
	} `json:"linux"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options"`
}

// The annotations and labels containerd's CRI plugin and the kubelet put on
// the containers of Kubernetes pods.
const (
	criContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	criContainerNameAnnotation = "io.kubernetes.cri.container-name"
	criSandboxIDAnnotation     = "io.kubernetes.cri.sandbox-id"
	criSandboxNameAnnotation   = "io.kubernetes.cri.sandbox-name"
	criSandboxNSAnnotation     = "io.kubernetes.cri.sandbox-namespace"
	kubeContainerNameLabel     = "io.kubernetes.container.name"
	kubePodNameLabel           = "io.kubernetes.pod.name"
	kubePodNamespaceLabel      = "io.kubernetes.pod.namespace"
)

// isPrivileged reports whether a spec has what privileged mode sets, in
// containerd's CRI plugin and ctr (oci.WithPrivileged) and in Docker: /sys
// mounted writable and no masked paths. Neither happens otherwise: the
// default spec mounts /sys read-only and masks paths of /proc.
func (s *ociSpec) isPrivileged() bool {
	if s.Linux != nil && len(s.Linux.MaskedPaths) > 0 {
		return false
	}
	for _, m := range s.Mounts {
		if m.Type == "sysfs" && m.Destination == "/sys" {
			return !slices.Contains(m.Options, "ro")
		}
	}
	return false
}

// seccompUnconfined reports whether a spec filters no system call: it has no
// seccomp profile, or one that lets every call run.
func (s *ociSpec) seccompUnconfined() bool {
	if s.Linux == nil || len(s.Linux.Seccomp) == 0 || string(s.Linux.Seccomp) == "null" {
		return true
	}
	return dockerSeccompAllowsAll(string(s.Linux.Seccomp))
}

func (s *ociSpec) seccompDefaultAction() string {
	if s.Linux == nil || len(s.Linux.Seccomp) == 0 {
		return ""
	}
	var profile struct {
		DefaultAction string `json:"defaultAction"`
	}
	if json.Unmarshal(s.Linux.Seccomp, &profile) != nil {
		return ""
	}
	return profile.DefaultAction
}

// hasNamespace reports whether a spec gives the container a namespace of a
// type, its own or one it joins.
func (s *ociSpec) hasNamespace(nsType string) bool {
	if s.Linux == nil {
		return false
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == nsType {
			return true
		}
	}
	return false
}

// isCRIContainer reports whether the spec is of a container of a Kubernetes
// pod, which joins the namespaces of its pod sandbox.
func (s *ociSpec) isCRIContainer() bool {
	return s.Annotations[criContainerTypeAnnotation] == "container"
}

// sharesHostNamespace reports whether a container shares a namespace of the
// host, and whether that is known. A container of a Kubernetes pod joins its
// sandbox's namespaces by path, so the sandbox's spec tells: CRI leaves a
// namespace out of the sandbox's spec when the pod shares the host's. Any
// other container shares the host's namespace when its spec has none of the
// type.
func sharesHostNamespace(spec, sandbox *ociSpec, nsType string) (bool, bool) {
	if spec == nil {
		return false, false
	}
	if spec.isCRIContainer() {
		if sandbox == nil {
			return false, false
		}
		return !sandbox.hasNamespace(nsType), true
	}
	return !spec.hasNamespace(nsType), true
}

// parseContainerdSpec decodes the Spec of `ctr containers info`. It is nil
// when there is none.
func parseContainerdSpec(raw json.RawMessage) (*ociSpec, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var spec ociSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// ociMountPropagation returns the propagation option of a mount.
func ociMountPropagation(options []string) string {
	for _, o := range options {
		switch o {
		case "private", "rprivate", "shared", "rshared", "slave", "rslave", "unbindable", "runbindable":
			return o
		}
	}
	return ""
}

// ociMountReadOnly reports whether a mount is read-only: the last of ro and
// rw wins, as in mount(8).
func ociMountReadOnly(options []string) bool {
	ro := false
	for _, o := range options {
		switch o {
		case "ro":
			ro = true
		case "rw":
			ro = false
		}
	}
	return ro
}

type mqlContainerdContainerInternal struct {
	// spec is the container's OCI runtime spec, nil when containerd reports none
	spec *ociSpec
	// sandbox is the spec of the pod sandbox of a Kubernetes container
	sandbox *ociSpec
	// infoSandboxID is the sandbox containerd reports for the container
	infoSandboxID string
}

// metadata returns a Kubernetes name of the container: from its label, which
// the kubelet sets, else from containerd's annotation.
func (c *mqlContainerdContainer) metadata(label, annotation string) string {
	if v, ok := c.Labels.Data[label].(string); ok && v != "" {
		return v
	}
	if c.spec != nil {
		return c.spec.Annotations[annotation]
	}
	return ""
}

func (c *mqlContainerdContainer) name() (string, error) {
	return c.metadata(kubeContainerNameLabel, criContainerNameAnnotation), nil
}

func (c *mqlContainerdContainer) podName() (string, error) {
	return c.metadata(kubePodNameLabel, criSandboxNameAnnotation), nil
}

func (c *mqlContainerdContainer) podNamespace() (string, error) {
	return c.metadata(kubePodNamespaceLabel, criSandboxNSAnnotation), nil
}

func (c *mqlContainerdContainer) sandboxId() (string, error) {
	if c.spec != nil {
		if id := c.spec.Annotations[criSandboxIDAnnotation]; id != "" {
			return id, nil
		}
	}
	return c.infoSandboxID, nil
}

// withSpec returns a value read from the spec, or sets the field null when
// containerd reports no spec.
func withSpec[T any](c *mqlContainerdContainer, field *plugin.TValue[T], read func(*ociSpec) T) (T, error) {
	if c.spec == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		var zero T
		return zero, nil
	}
	return read(c.spec), nil
}

func (c *mqlContainerdContainer) privileged() (bool, error) {
	return withSpec(c, &c.Privileged, (*ociSpec).isPrivileged)
}

func (c *mqlContainerdContainer) capabilities() ([]any, error) {
	return withSpec(c, &c.Capabilities, func(s *ociSpec) []any {
		if s.Process == nil || s.Process.Capabilities == nil {
			return []any{}
		}
		return stringsToAny(s.Process.Capabilities.Effective)
	})
}

func (c *mqlContainerdContainer) boundingCapabilities() ([]any, error) {
	return withSpec(c, &c.BoundingCapabilities, func(s *ociSpec) []any {
		if s.Process == nil || s.Process.Capabilities == nil {
			return []any{}
		}
		return stringsToAny(s.Process.Capabilities.Bounding)
	})
}

func (c *mqlContainerdContainer) seccompUnconfined() (bool, error) {
	return withSpec(c, &c.SeccompUnconfined, (*ociSpec).seccompUnconfined)
}

func (c *mqlContainerdContainer) seccompDefaultAction() (string, error) {
	return withSpec(c, &c.SeccompDefaultAction, (*ociSpec).seccompDefaultAction)
}

func (c *mqlContainerdContainer) apparmorProfile() (string, error) {
	return withSpec(c, &c.ApparmorProfile, func(s *ociSpec) string {
		if s.Process == nil {
			return ""
		}
		return s.Process.ApparmorProfile
	})
}

func (c *mqlContainerdContainer) selinuxLabel() (string, error) {
	return withSpec(c, &c.SelinuxLabel, func(s *ociSpec) string {
		if s.Process == nil {
			return ""
		}
		return s.Process.SelinuxLabel
	})
}

func (c *mqlContainerdContainer) noNewPrivileges() (bool, error) {
	return withSpec(c, &c.NoNewPrivileges, func(s *ociSpec) bool {
		return s.Process != nil && s.Process.NoNewPrivileges
	})
}

func (c *mqlContainerdContainer) readOnlyRootfs() (bool, error) {
	return withSpec(c, &c.ReadOnlyRootfs, func(s *ociSpec) bool {
		return s.Root != nil && s.Root.Readonly
	})
}

func (c *mqlContainerdContainer) uid() (int64, error) {
	return withSpec(c, &c.Uid, func(s *ociSpec) int64 {
		if s.Process == nil {
			return 0
		}
		return int64(s.Process.User.UID)
	})
}

func (c *mqlContainerdContainer) gid() (int64, error) {
	return withSpec(c, &c.Gid, func(s *ociSpec) int64 {
		if s.Process == nil {
			return 0
		}
		return int64(s.Process.User.GID)
	})
}

func (c *mqlContainerdContainer) hostNamespace(field *plugin.TValue[bool], nsType string) (bool, error) {
	shared, ok := sharesHostNamespace(c.spec, c.sandbox, nsType)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return shared, nil
}

func (c *mqlContainerdContainer) hostNetwork() (bool, error) {
	return c.hostNamespace(&c.HostNetwork, "network")
}

func (c *mqlContainerdContainer) hostPID() (bool, error) {
	return c.hostNamespace(&c.HostPID, "pid")
}

func (c *mqlContainerdContainer) hostIPC() (bool, error) {
	return c.hostNamespace(&c.HostIPC, "ipc")
}

func (c *mqlContainerdContainer) mounts() ([]any, error) {
	if c.spec == nil {
		c.Mounts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for i, m := range c.spec.Mounts {
		hostPath := ""
		if m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind") {
			hostPath = m.Source
		}
		r, err := CreateResource(c.MqlRuntime, "containerd.container.mount", map[string]*llx.RawData{
			"__id":          llx.StringData("containerd.container.mount/" + c.__id + "/" + strconv.Itoa(i)),
			"type":          llx.StringData(m.Type),
			"containerPath": llx.StringData(m.Destination),
			"hostPath":      llx.StringData(hostPath),
			"readOnly":      llx.BoolData(ociMountReadOnly(m.Options)),
			"propagation":   llx.StringData(ociMountPropagation(m.Options)),
			"options":       llx.ArrayData(stringsToAny(m.Options), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// ociLimits are the resource limits of a spec, nil where there is none.
type ociLimits struct {
	memory    *int64
	nanoCpus  *int64
	cpuShares *int64
	pids      *int64
}

func (s *ociSpec) limits() ociLimits {
	res := ociLimits{}
	if s.Linux == nil || s.Linux.Resources == nil {
		return res
	}
	r := s.Linux.Resources
	if r.Memory != nil && r.Memory.Limit != nil && *r.Memory.Limit > 0 {
		v := *r.Memory.Limit
		res.memory = &v
	}
	if r.CPU != nil {
		if r.CPU.Quota != nil && *r.CPU.Quota > 0 && r.CPU.Period != nil && *r.CPU.Period > 0 {
			v := *r.CPU.Quota * 1_000_000_000 / int64(*r.CPU.Period)
			res.nanoCpus = &v
		}
		if r.CPU.Shares != nil && *r.CPU.Shares > 0 {
			v := int64(*r.CPU.Shares)
			res.cpuShares = &v
		}
	}
	if r.Pids != nil && r.Pids.Limit > 0 {
		v := r.Pids.Limit
		res.pids = &v
	}
	return res
}

func (c *mqlContainerdContainer) limit(field *plugin.TValue[int64], pick func(ociLimits) *int64) (int64, error) {
	if c.spec == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	v := pick(c.spec.limits())
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (c *mqlContainerdContainer) memoryLimit() (int64, error) {
	return c.limit(&c.MemoryLimit, func(l ociLimits) *int64 { return l.memory })
}

func (c *mqlContainerdContainer) nanoCpus() (int64, error) {
	return c.limit(&c.NanoCpus, func(l ociLimits) *int64 { return l.nanoCpus })
}

func (c *mqlContainerdContainer) cpuShares() (int64, error) {
	return c.limit(&c.CpuShares, func(l ociLimits) *int64 { return l.cpuShares })
}

func (c *mqlContainerdContainer) pidsLimit() (int64, error) {
	return c.limit(&c.PidsLimit, func(l ociLimits) *int64 { return l.pids })
}

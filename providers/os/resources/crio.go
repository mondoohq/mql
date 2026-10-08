// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path"
	"regexp"
	"sync"

	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

const (
	// crioSocket is where CRI-O serves both the CRI and its own HTTP API
	// (/config, /info, /containers/<id>).
	crioSocket = "/var/run/crio/crio.sock"
	// crioConfigFile is CRI-O's main configuration file. The packages from
	// the CRI-O project ship none and configure everything in crio.conf.d.
	crioConfigFile = "/etc/crio/crio.conf"
	// crioConfigDir holds the drop-in files CRI-O applies after crioConfigFile.
	crioConfigDir = "/etc/crio/crio.conf.d"
	// crioVersionFile is where the running CRI-O records its version.
	crioVersionFile = "/var/run/crio/version"
)

var crioContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// crioEndpoint is the shape of a CRI-O API path: slash-separated words of
// letters, digits, dashes and underscores. Nothing else may reach the shell.
var crioEndpoint = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)+$`)

// crioAPI asks the running CRI-O over its socket's HTTP API. It needs root,
// and returns false when CRI-O is not running or cannot be reached, or when
// the endpoint is not a plain API path.
func crioAPI(runtime *plugin.Runtime, endpoint string) (string, bool) {
	if !crioEndpoint.MatchString(endpoint) {
		return "", false
	}
	return runCommandQuiet(runtime, "curl -s --fail --unix-socket "+crioSocket+" http://localhost"+endpoint)
}

func (c *mqlCrio) version() (string, error) {
	configured := ""
	if cfg := c.GetConfiguration(); cfg.Error == nil {
		data, _ := cfg.Data.(map[string]any)
		crio, _ := data["crio"].(map[string]any)
		configured, _ = crio["version_file"].(string)
	}
	for _, p := range crioVersionFilePaths(configured) {
		if v := parseCrioVersion(readKubeletFile(c.MqlRuntime, p)); v != "" {
			return v, nil
		}
		// a container scan reads files from the container's filesystem, which
		// holds none of its /run tmpfs; a command in the container does
		if out, ok := runCommandQuiet(c.MqlRuntime, "cat "+p); ok {
			if v := parseCrioVersion(out); v != "" {
				return v, nil
			}
		}
	}
	c.Version.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

// crioVersionFilePaths returns where to look for the version file: the one
// CRI-O is configured with (crio.version_file), or its default, and the same
// path under /run when it is under /var/run, a link to /run.
func crioVersionFilePaths(configured string) []string {
	p := configured
	if p == "" {
		p = crioVersionFile
	}
	paths := []string{p}
	if rest, ok := strings.CutPrefix(p, "/var/run/"); ok {
		paths = append(paths, "/run/"+rest)
	}
	return paths
}

// parseCrioVersion reads the version file CRI-O writes, a JSON string such as
// "1.37.2+585389f80055ab1a22b82802b6f9a2fb9487d9dd", and returns the release
// without the commit ("1.37.2").
func parseCrioVersion(content string) string {
	v := strings.Trim(strings.TrimSpace(content), `"`)
	v, _, _ = strings.Cut(v, "+")
	return v
}

// crioConfigFilePaths returns the configuration files in the order CRI-O
// applies them: crio.conf when present, then every file in crio.conf.d in
// name order. Both are read through the connection's filesystem, so image
// and filesystem scans find them too.
func (c *mqlCrio) crioConfigFilePaths() ([]string, error) {
	paths := []string{}
	f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(crioConfigFile)})
	if err != nil {
		return nil, err
	}
	exists := f.(*mqlFile).GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if exists.Data {
		paths = append(paths, crioConfigFile)
	}
	dropIns, err := listConfDFilesWith(c.MqlRuntime, []string{crioConfigDir}, isCrioDropInFile)
	if err != nil {
		return nil, err
	}
	return append(paths, dropIns...), nil
}

// isCrioDropInFile reports whether CRI-O reads a file of crio.conf.d: any
// file but a hidden one.
func isCrioDropInFile(name string) bool {
	return name != "" && !strings.HasPrefix(name, ".")
}

func (c *mqlCrio) configFiles() ([]any, error) {
	paths, err := c.crioConfigFilePaths()
	if err != nil {
		return nil, err
	}
	files := []any{}
	for _, p := range paths {
		f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func (c *mqlCrio) configuration() (map[string]any, error) {
	// the running CRI-O reports its effective configuration, defaults included
	if out, ok := crioAPI(c.MqlRuntime, "/config"); ok && strings.TrimSpace(out) != "" {
		return parseCrioConfig(out)
	}
	paths, err := c.crioConfigFilePaths()
	if err != nil {
		return nil, err
	}
	merged := map[string]any{}
	for _, p := range paths {
		cfg, err := parseCrioConfig(readKubeletFile(c.MqlRuntime, p))
		if err != nil {
			return nil, err
		}
		mergeCrioConfig(merged, cfg)
	}
	return merged, nil
}

// parseCrioConfig decodes a CRI-O TOML configuration into a dict.
func parseCrioConfig(content string) (map[string]any, error) {
	cfg := map[string]any{}
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, err
	}
	return convert.JsonToDict(cfg)
}

// mergeCrioConfig merges a drop-in into the configuration so far, the way
// CRI-O does: a key the drop-in sets replaces the earlier value, and tables
// merge key by key.
func mergeCrioConfig(dst, src map[string]any) {
	for k, v := range src {
		srcTable, srcIsTable := v.(map[string]any)
		dstTable, dstIsTable := dst[k].(map[string]any)
		if srcIsTable && dstIsTable {
			mergeCrioConfig(dstTable, srcTable)
			continue
		}
		dst[k] = v
	}
}

// crioValue reads a key of the configuration's [crio.<section>] table.
func (c *mqlCrio) crioValue(section, key string) (any, error) {
	cfg := c.GetConfiguration()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	data, _ := cfg.Data.(map[string]any)
	return crioConfigValue(data, section, key), nil
}

// crioConfigValue returns crio.<section>.<key> of a configuration, or nil.
func crioConfigValue(cfg map[string]any, section, key string) any {
	crio, _ := cfg["crio"].(map[string]any)
	table, _ := crio[section].(map[string]any)
	return table[key]
}

func (c *mqlCrio) runtimeString(field *plugin.TValue[string], key string) (string, error) {
	v, err := c.crioValue("runtime", key)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s, nil
}

func (c *mqlCrio) runtimeBool(field *plugin.TValue[bool], key string) (bool, error) {
	v, err := c.crioValue("runtime", key)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return b, nil
}

func (c *mqlCrio) runtimeList(key string) ([]any, error) {
	v, err := c.crioValue("runtime", key)
	if err != nil {
		return nil, err
	}
	return crioList(v), nil
}

// crioList returns a configuration list as a list of strings.
func crioList(v any) []any {
	res := []any{}
	list, _ := v.([]any)
	for _, item := range list {
		if s, ok := item.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

func (c *mqlCrio) defaultRuntime() (string, error) {
	return c.runtimeString(&c.DefaultRuntime, "default_runtime")
}

func (c *mqlCrio) seccompProfile() (string, error) {
	return c.runtimeString(&c.SeccompProfile, "seccomp_profile")
}

func (c *mqlCrio) apparmorProfile() (string, error) {
	return c.runtimeString(&c.ApparmorProfile, "apparmor_profile")
}

func (c *mqlCrio) selinux() (bool, error) {
	return c.runtimeBool(&c.Selinux, "selinux")
}

func (c *mqlCrio) readOnly() (bool, error) {
	return c.runtimeBool(&c.ReadOnly, "read_only")
}

func (c *mqlCrio) defaultCapabilities() ([]any, error) {
	return c.runtimeList("default_capabilities")
}

func (c *mqlCrio) defaultSysctls() ([]any, error) {
	return c.runtimeList("default_sysctls")
}

func (c *mqlCrio) allowedDevices() ([]any, error) {
	return c.runtimeList("allowed_devices")
}

// crioStorageContainer is an entry of containers/storage's container list,
// which CRI-O fills with the pod and container it created the entry for.
type crioStorageContainer struct {
	ID       string    `json:"id"`
	Names    []string  `json:"names"`
	Image    string    `json:"image"`
	Created  time.Time `json:"created"`
	Metadata string    `json:"metadata"`
}

// crioStorageMetadata is the JSON CRI-O stores in an entry's metadata.
type crioStorageMetadata struct {
	Pod          bool   `json:"pod"`
	PodName      string `json:"pod-name"`
	PodID        string `json:"pod-id"`
	ImageName    string `json:"image-name"`
	MetadataName string `json:"metadata-name"`
	Privileged   bool   `json:"privileged"`
}

// crioContainer is what the crio.container resource is built from.
type crioContainer struct {
	ID           string
	Name         string
	PodName      string
	PodNamespace string
	SandboxID    string
	Image        string
	// ImageID is the containers/storage ID of the container's image
	ImageID    string
	Privileged bool
	Created    time.Time
}

// parseCrioStorageContainers returns the containers of a containers/storage
// container list, leaving out the pod sandboxes (infra containers), which
// CRI-O marks as pods whose pod id is their own.
func parseCrioStorageContainers(content string) ([]crioContainer, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var entries []crioStorageContainer
	if err := json.Unmarshal([]byte(content), &entries); err != nil {
		return nil, err
	}
	res := []crioContainer{}
	for _, e := range entries {
		var md crioStorageMetadata
		if e.Metadata != "" {
			if err := json.Unmarshal([]byte(e.Metadata), &md); err != nil {
				log.Warn().Err(err).Str("container", e.ID).Msg("crio> skipping a container whose storage metadata cannot be read")
				continue
			}
		}
		if md.Pod || md.PodID == e.ID {
			continue
		}
		pod, namespace := crioPodFromSandboxName(md.PodName)
		res = append(res, crioContainer{
			ID:           e.ID,
			Name:         md.MetadataName,
			PodName:      pod,
			PodNamespace: namespace,
			SandboxID:    md.PodID,
			Image:        md.ImageName,
			ImageID:      e.Image,
			Privileged:   md.Privileged,
			Created:      e.Created,
		})
	}
	return res, nil
}

// crioPodFromSandboxName reads the pod and namespace from a CRI-O sandbox
// name, k8s_<pod>_<namespace>_<uid>_<attempt>. Kubernetes names cannot
// contain an underscore, so the fields split cleanly.
func crioPodFromSandboxName(name string) (string, string) {
	parts := strings.Split(strings.TrimPrefix(name, "k8s_"), "_")
	if !strings.HasPrefix(name, "k8s_") || len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// crioInspect is what CRI-O's /containers/<id> reports of a container.
type crioInspect struct {
	Pid         int64             `json:"pid"`
	Image       string            `json:"image"`
	ImageRef    string            `json:"image_ref"`
	Labels      map[string]string `json:"labels"`
	HostNetwork bool              `json:"host_network"`
	Annotations map[string]string `json:"crio_annotations"`
}

// crioSeccompAnnotation is where CRI-O records the seccomp profile a
// container runs with.
const crioSeccompAnnotation = "io.kubernetes.cri-o.SeccompProfilePath"

func parseCrioInspect(content string) (crioInspect, error) {
	var inspect crioInspect
	err := json.Unmarshal([]byte(content), &inspect)
	return inspect, err
}

func (c *mqlCrio) containers() ([]any, error) {
	root, driver, err := c.crioStorage()
	if err != nil {
		return nil, err
	}

	dir := path.Join(root, driver+"-containers")
	sandboxes := &crioSpecCache{runtime: c.MqlRuntime, specs: map[string]*ociSpec{}}
	res := []any{}
	for _, list := range []string{"volatile-containers.json", "containers.json"} {
		containers, err := parseCrioStorageContainers(readKubeletFile(c.MqlRuntime, path.Join(dir, list)))
		if err != nil {
			return nil, err
		}
		for _, ctr := range containers {
			r, err := c.newCrioContainer(ctr, dir, sandboxes)
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

func (c *mqlCrio) newCrioContainer(ctr crioContainer, dir string, sandboxes *crioSpecCache) (plugin.Resource, error) {
	var inspect crioInspect
	inspected := false
	validID := crioContainerID.MatchString(ctr.ID)
	if validID {
		if out, ok := crioAPI(c.MqlRuntime, "/containers/"+ctr.ID); ok {
			if parsed, err := parseCrioInspect(out); err == nil {
				inspect = parsed
				inspected = true
			}
		}
	}

	internal := mqlCrioContainerInternal{sandboxes: sandboxes, imageID: ctr.ImageID}
	if validID {
		internal.configPath = path.Join(dir, ctr.ID, "userdata", "config.json")
	}
	if crioContainerID.MatchString(ctr.SandboxID) {
		internal.sandboxConfigPath = path.Join(dir, ctr.SandboxID, "userdata", "config.json")
	}
	if inspected {
		hostNetwork := inspect.HostNetwork
		internal.inspectHostNetwork = &hostNetwork
	} else if spec := internal.loadSpec(c.MqlRuntime); spec != nil {
		// without a running CRI-O, what it recorded in the spec
		inspect.Annotations = spec.Annotations
		inspect.Labels = crioSpecLabels(spec)
	}

	image := ctr.Image
	if inspect.Image != "" {
		image = inspect.Image
	}
	podName, podNamespace := ctr.PodName, ctr.PodNamespace
	if v := inspect.Labels["io.kubernetes.pod.name"]; v != "" {
		podName = v
	}
	if v := inspect.Labels["io.kubernetes.pod.namespace"]; v != "" {
		podNamespace = v
	}
	labels := map[string]any{}
	for k, v := range inspect.Labels {
		labels[k] = v
	}
	created := ctr.Created

	r, err := CreateResource(c.MqlRuntime, "crio.container", map[string]*llx.RawData{
		"__id":           llx.StringData("crio.container/" + ctr.ID),
		"id":             llx.StringData(ctr.ID),
		"name":           llx.StringData(ctr.Name),
		"podName":        llx.StringData(podName),
		"podNamespace":   llx.StringData(podNamespace),
		"sandboxId":      llx.StringData(ctr.SandboxID),
		"image":          llx.StringData(image),
		"imageRef":       llx.StringData(inspect.ImageRef),
		"pid":            llx.IntData(inspect.Pid),
		"privileged":     llx.BoolData(ctr.Privileged),
		"seccompProfile": llx.StringData(inspect.Annotations[crioSeccompAnnotation]),
		"labels":         llx.MapData(labels, types.String),
		"created":        llx.TimeData(created),
	})
	if err != nil {
		return nil, err
	}
	ctrRes := r.(*mqlCrioContainer)
	ctrRes.volumes, ctrRes.hasVolumes = inspect.Annotations[crioVolumesAnnotation]
	ctrRes.configPath = internal.configPath
	ctrRes.sandboxConfigPath = internal.sandboxConfigPath
	ctrRes.sandboxes = sandboxes
	ctrRes.imageID = internal.imageID
	ctrRes.inspectHostNetwork = internal.inspectHostNetwork
	if internal.specLoaded {
		ctrRes.spec, ctrRes.specLoaded = internal.spec, true
	}
	return ctrRes, nil
}

// crioVolumesAnnotation is where CRI-O records the volumes it mounted into a
// container, in its inspect output and the container's OCI config.json.
const crioVolumesAnnotation = "io.kubernetes.cri-o.Volumes"

type mqlCrioContainerInternal struct {
	// imageID is the containers/storage ID of the container's image
	imageID string
	// volumes is the Volumes annotation CRI-O reported for the container
	volumes    string
	hasVolumes bool
	// configPath is the container's OCI config.json in containers/storage
	configPath string
	// sandboxConfigPath is the OCI config.json of the container's pod sandbox
	sandboxConfigPath string
	// sandboxes reads each pod sandbox's spec once for all its containers
	sandboxes *crioSpecCache
	// inspectHostNetwork is what the running CRI-O reported, nil without it
	inspectHostNetwork *bool

	specMu     sync.Mutex
	specLoaded bool
	// spec is the container's OCI runtime spec, nil when it cannot be read
	spec *ociSpec
}

// crioMount is one entry of the Volumes annotation.
type crioMount struct {
	ContainerPath     string `json:"container_path"`
	HostPath          string `json:"host_path"`
	Readonly          bool   `json:"readonly"`
	RecursiveReadOnly bool   `json:"recursive_read_only"`
	Propagation       int    `json:"propagation"`
	SelinuxRelabel    bool   `json:"selinux_relabel"`
}

func parseCrioMounts(content string) ([]crioMount, error) {
	var mounts []crioMount
	if err := json.Unmarshal([]byte(content), &mounts); err != nil {
		return nil, err
	}
	return mounts, nil
}

// crioSpecVolumes returns the Volumes annotation of a container's OCI spec,
// and whether it holds one.
func crioSpecVolumes(spec *ociSpec) (string, bool) {
	if spec == nil {
		return "", false
	}
	v, ok := spec.Annotations[crioVolumesAnnotation]
	return v, ok
}

// crioPropagation names a CRI mount propagation the way a pod spec does.
func crioPropagation(p int) string {
	switch p {
	case 0:
		return "None"
	case 1:
		return "HostToContainer"
	case 2:
		return "Bidirectional"
	default:
		return strconv.Itoa(p)
	}
}

// loadSpec reads the container's OCI runtime spec once. It is nil when the
// spec cannot be read or parsed.
func (c *mqlCrioContainerInternal) loadSpec(runtime *plugin.Runtime) *ociSpec {
	c.specMu.Lock()
	defer c.specMu.Unlock()
	if c.specLoaded {
		return c.spec
	}
	c.specLoaded = true
	c.spec = readCrioSpec(runtime, c.configPath)
	return c.spec
}

// readCrioSpec reads and parses an OCI config.json in containers/storage,
// nil when it is missing or does not parse.
func readCrioSpec(runtime *plugin.Runtime, p string) *ociSpec {
	if p == "" {
		return nil
	}
	spec, err := parseOCISpec([]byte(readKubeletFile(runtime, p)))
	if err != nil {
		log.Debug().Err(err).Str("path", p).Msg("crio> cannot parse a container's config.json")
		return nil
	}
	return spec
}

// crioSpecCache holds the specs of pod sandboxes, which every container of
// a pod reads.
type crioSpecCache struct {
	runtime *plugin.Runtime
	mu      sync.Mutex
	specs   map[string]*ociSpec
}

func (c *crioSpecCache) get(p string) *ociSpec {
	if c == nil || p == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if spec, ok := c.specs[p]; ok {
		return spec
	}
	spec := readCrioSpec(c.runtime, p)
	c.specs[p] = spec
	return spec
}

// crioSpecLabels returns the container labels CRI-O records in a spec.
func crioSpecLabels(spec *ociSpec) map[string]string {
	labels := map[string]string{}
	if v := spec.Annotations[crioLabelsAnnotation]; v != "" {
		if err := json.Unmarshal([]byte(v), &labels); err != nil {
			return map[string]string{}
		}
	}
	return labels
}

// The annotations CRI-O records in the specs it creates.
const (
	crioLabelsAnnotation = "io.kubernetes.cri-o.Labels"
	// crioNamespaceOptionsAnnotation holds a pod's CRI namespace options, on
	// the spec of its sandbox
	crioNamespaceOptionsAnnotation = "io.kubernetes.cri-o.NamespaceOptions"
	// crioHostNetworkAnnotation is "true" on the sandbox of a hostNetwork pod
	crioHostNetworkAnnotation = "io.kubernetes.cri-o.HostNetwork"
)

// criNamespaceModeNode is the CRI NamespaceMode of a namespace shared with
// the node. POD (0) is left out of the JSON, CONTAINER is 1, TARGET 3.
const criNamespaceModeNode = 2

// crioNamespaceOptions is the CRI NamespaceOption CRI-O records on a pod
// sandbox.
type crioNamespaceOptions struct {
	Network int `json:"network"`
	Pid     int `json:"pid"`
	Ipc     int `json:"ipc"`
}

// crioSandboxNamespaces returns the namespace options of a pod sandbox's
// spec, and whether it records them. A pod's containers join namespaces
// CRI-O pinned for the sandbox by path, also those of the node (hostIPC), so
// their own specs cannot tell.
func crioSandboxNamespaces(sandbox *ociSpec) (crioNamespaceOptions, bool) {
	var opts crioNamespaceOptions
	if sandbox == nil {
		return opts, false
	}
	v, ok := sandbox.Annotations[crioNamespaceOptionsAnnotation]
	if !ok || json.Unmarshal([]byte(v), &opts) != nil {
		return opts, false
	}
	return opts, true
}

func (c *mqlCrioContainer) containerSpec() *ociSpec {
	return c.loadSpec(c.MqlRuntime)
}

func (c *mqlCrioContainer) capabilities() ([]any, error) {
	return withSpec(c.containerSpec(), &c.Capabilities, (*ociSpec).effectiveCapabilities)
}

func (c *mqlCrioContainer) boundingCapabilities() ([]any, error) {
	return withSpec(c.containerSpec(), &c.BoundingCapabilities, (*ociSpec).boundingCapabilities)
}

func (c *mqlCrioContainer) seccompUnconfined() (bool, error) {
	return withSpec(c.containerSpec(), &c.SeccompUnconfined, (*ociSpec).seccompUnconfined)
}

func (c *mqlCrioContainer) seccompDefaultAction() (string, error) {
	return withSpec(c.containerSpec(), &c.SeccompDefaultAction, (*ociSpec).seccompDefaultAction)
}

func (c *mqlCrioContainer) apparmorProfile() (string, error) {
	return withSpec(c.containerSpec(), &c.ApparmorProfile, (*ociSpec).apparmorProfile)
}

func (c *mqlCrioContainer) selinuxLabel() (string, error) {
	return withSpec(c.containerSpec(), &c.SelinuxLabel, (*ociSpec).selinuxLabel)
}

func (c *mqlCrioContainer) noNewPrivileges() (bool, error) {
	return withSpec(c.containerSpec(), &c.NoNewPrivileges, (*ociSpec).noNewPrivileges)
}

func (c *mqlCrioContainer) readOnlyRootfs() (bool, error) {
	return withSpec(c.containerSpec(), &c.ReadOnlyRootfs, (*ociSpec).readOnlyRootfs)
}

func (c *mqlCrioContainer) uid() (int64, error) {
	return withSpec(c.containerSpec(), &c.Uid, (*ociSpec).uid)
}

func (c *mqlCrioContainer) gid() (int64, error) {
	return withSpec(c.containerSpec(), &c.Gid, (*ociSpec).gid)
}

func (c *mqlCrioContainer) memoryLimit() (int64, error) {
	return specLimit(c.containerSpec(), &c.MemoryLimit, func(l ociLimits) *int64 { return l.memory })
}

func (c *mqlCrioContainer) nanoCpus() (int64, error) {
	return specLimit(c.containerSpec(), &c.NanoCpus, func(l ociLimits) *int64 { return l.nanoCpus })
}

func (c *mqlCrioContainer) cpuShares() (int64, error) {
	return specLimit(c.containerSpec(), &c.CpuShares, func(l ociLimits) *int64 { return l.cpuShares })
}

func (c *mqlCrioContainer) pidsLimit() (int64, error) {
	return specLimit(c.containerSpec(), &c.PidsLimit, func(l ociLimits) *int64 { return l.pids })
}

// hostNamespace reports whether the container's pod shares a namespace of
// the node, from the namespace options on its sandbox's spec.
func (c *mqlCrioContainer) hostNamespace(field *plugin.TValue[bool], mode func(crioNamespaceOptions) int) (bool, error) {
	opts, ok := crioSandboxNamespaces(c.sandboxes.get(c.sandboxConfigPath))
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return mode(opts) == criNamespaceModeNode, nil
}

func (c *mqlCrioContainer) hostNetwork() (bool, error) {
	sandbox := c.sandboxes.get(c.sandboxConfigPath)
	if opts, ok := crioSandboxNamespaces(sandbox); ok {
		return opts.Network == criNamespaceModeNode, nil
	}
	if sandbox != nil {
		if v, ok := sandbox.Annotations[crioHostNetworkAnnotation]; ok {
			return v == "true", nil
		}
	}
	if c.inspectHostNetwork != nil {
		return *c.inspectHostNetwork, nil
	}
	c.HostNetwork.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (c *mqlCrioContainer) hostPID() (bool, error) {
	return c.hostNamespace(&c.HostPID, func(o crioNamespaceOptions) int { return o.Pid })
}

func (c *mqlCrioContainer) hostIPC() (bool, error) {
	return c.hostNamespace(&c.HostIPC, func(o crioNamespaceOptions) int { return o.Ipc })
}

func (c *mqlCrioContainer) mounts() ([]any, error) {
	volumes, ok := c.volumes, c.hasVolumes
	if !ok {
		volumes, ok = crioSpecVolumes(c.containerSpec())
	}
	if !ok {
		c.Mounts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mounts, err := parseCrioMounts(volumes)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i, m := range mounts {
		r, err := CreateResource(c.MqlRuntime, "crio.container.mount", map[string]*llx.RawData{
			"__id":              llx.StringData("crio.container.mount/" + c.Id.Data + "/" + strconv.Itoa(i)),
			"containerPath":     llx.StringData(m.ContainerPath),
			"hostPath":          llx.StringData(m.HostPath),
			"readOnly":          llx.BoolData(m.Readonly),
			"recursiveReadOnly": llx.BoolData(m.RecursiveReadOnly),
			"propagation":       llx.StringData(crioPropagation(m.Propagation)),
			"selinuxRelabel":    llx.BoolData(m.SelinuxRelabel),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (c *mqlCrio) streamAddress() (string, error) {
	v, err := c.crioValue("api", "stream_address")
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		c.StreamAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s, nil
}

func (c *mqlCrio) streamPort() (int64, error) {
	v, err := c.crioValue("api", "stream_port")
	if err != nil {
		return 0, err
	}
	port, ok := crioPort(v)
	if !ok {
		c.StreamPort.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return port, nil
}

// crioPort reads a port CRI-O's configuration holds as a string ("10010"),
// or as a number when a drop-in writes it unquoted (int64 from TOML, float64
// once the configuration has passed through JSON).
func crioPort(v any) (int64, bool) {
	switch p := v.(type) {
	case string:
		n, err := strconv.ParseInt(p, 10, 64)
		return n, err == nil
	case int64:
		return p, true
	case float64:
		return int64(p), p == float64(int64(p))
	default:
		return 0, false
	}
}

func (c *mqlCrio) streamTlsEnabled() (bool, error) {
	v, err := c.crioValue("api", "stream_enable_tls")
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		c.StreamTlsEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return b, nil
}

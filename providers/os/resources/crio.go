// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
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
	// crioDefaultStorageRoot is containers/storage's root unless crio.root
	// says otherwise.
	crioDefaultStorageRoot = "/var/lib/containers/storage"
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
// name order.
func (c *mqlCrio) crioConfigFilePaths() []string {
	paths := []string{}
	if _, ok := runCommandQuiet(c.MqlRuntime, "test -f "+crioConfigFile); ok {
		paths = append(paths, crioConfigFile)
	}
	out, ok := runCommandQuiet(c.MqlRuntime, "ls -1A -- "+crioConfigDir)
	if !ok {
		return paths
	}
	for _, name := range crioDropInFiles(strings.Split(strings.TrimSpace(out), "\n")) {
		paths = append(paths, path.Join(crioConfigDir, name))
	}
	return paths
}

// crioDropInFiles orders the files of crio.conf.d as CRI-O reads them: by
// name, hidden files left out.
func crioDropInFiles(names []string) []string {
	res := []string{}
	for _, name := range names {
		if name != "" && !strings.HasPrefix(name, ".") {
			res = append(res, name)
		}
	}
	sort.Strings(res)
	return res
}

func (c *mqlCrio) configFiles() ([]any, error) {
	files := []any{}
	for _, p := range c.crioConfigFilePaths() {
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
	merged := map[string]any{}
	for _, p := range c.crioConfigFilePaths() {
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
	Privileged   bool
	Created      time.Time
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
	cfg := c.GetConfiguration()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	data, _ := cfg.Data.(map[string]any)
	crioTable, _ := data["crio"].(map[string]any)
	root, _ := crioTable["root"].(string)
	if root == "" {
		root = crioDefaultStorageRoot
	}
	driver, _ := crioTable["storage_driver"].(string)
	if driver == "" {
		driver = "overlay"
	}

	dir := path.Join(root, driver+"-containers")
	res := []any{}
	for _, list := range []string{"volatile-containers.json", "containers.json"} {
		containers, err := parseCrioStorageContainers(readKubeletFile(c.MqlRuntime, path.Join(dir, list)))
		if err != nil {
			return nil, err
		}
		for _, ctr := range containers {
			r, err := c.newCrioContainer(ctr, dir)
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

func (c *mqlCrio) newCrioContainer(ctr crioContainer, dir string) (plugin.Resource, error) {
	var inspect crioInspect
	if crioContainerID.MatchString(ctr.ID) {
		if out, ok := crioAPI(c.MqlRuntime, "/containers/"+ctr.ID); ok {
			if parsed, err := parseCrioInspect(out); err == nil {
				inspect = parsed
			}
		}
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
		"hostNetwork":    llx.BoolData(inspect.HostNetwork),
		"seccompProfile": llx.StringData(inspect.Annotations[crioSeccompAnnotation]),
		"labels":         llx.MapData(labels, "string"),
		"created":        llx.TimeData(created),
	})
	if err != nil {
		return nil, err
	}
	ctrRes := r.(*mqlCrioContainer)
	ctrRes.volumes, ctrRes.hasVolumes = inspect.Annotations[crioVolumesAnnotation]
	if crioContainerID.MatchString(ctr.ID) {
		ctrRes.configPath = path.Join(dir, ctr.ID, "userdata", "config.json")
	}
	return ctrRes, nil
}

// crioVolumesAnnotation is where CRI-O records the volumes it mounted into a
// container, in its inspect output and the container's OCI config.json.
const crioVolumesAnnotation = "io.kubernetes.cri-o.Volumes"

type mqlCrioContainerInternal struct {
	// volumes is the Volumes annotation CRI-O reported for the container
	volumes    string
	hasVolumes bool
	// configPath is the container's OCI config.json in containers/storage
	configPath string
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

// crioVolumesFromOCIConfig returns the Volumes annotation of an OCI
// config.json, and whether it holds one.
func crioVolumesFromOCIConfig(content string) (string, bool) {
	var cfg struct {
		Annotations map[string]string `json:"annotations"`
	}
	if json.Unmarshal([]byte(content), &cfg) != nil {
		return "", false
	}
	v, ok := cfg.Annotations[crioVolumesAnnotation]
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

func (c *mqlCrioContainer) mounts() ([]any, error) {
	volumes, ok := c.volumes, c.hasVolumes
	if !ok && c.configPath != "" {
		volumes, ok = crioVolumesFromOCIConfig(readKubeletFile(c.MqlRuntime, c.configPath))
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

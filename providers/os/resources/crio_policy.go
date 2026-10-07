// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// crioDefaultSignaturePolicyDir holds the per-namespace policies unless
// crio.image.signature_policy_dir names another directory.
const crioDefaultSignaturePolicyDir = "/etc/crio/policies"

func (c *mqlCrio) imageConfig(key, fallback string) string {
	if v, ok := crioConfigValueOf(c, "image", key).(string); ok && v != "" {
		return v
	}
	return fallback
}

// crioConfigValueOf reads crio.<section>.<key> of the crio resource's
// configuration, or nil.
func crioConfigValueOf(c *mqlCrio, section, key string) any {
	cfg := c.GetConfiguration()
	if cfg.Error != nil {
		return nil
	}
	data, _ := cfg.Data.(map[string]any)
	return crioConfigValue(data, section, key)
}

func (c *mqlCrio) signaturePolicy() (*mqlContainersPolicy, error) {
	p := c.imageConfig("signature_policy", containersDefaultPolicy)
	if readKubeletFile(c.MqlRuntime, p) == "" {
		c.SignaturePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newContainersPolicy(c.MqlRuntime, p)
}

func (c *mqlCrio) namespaceSignaturePolicies() ([]any, error) {
	dir := c.imageConfig("signature_policy_dir", crioDefaultSignaturePolicyDir)
	files, err := listConfDFilesWith(c.MqlRuntime, []string{dir}, isCrioNamespacePolicyFile)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, p := range files {
		policy, err := newContainersPolicy(c.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(c.MqlRuntime, "crio.namespaceSignaturePolicy", map[string]*llx.RawData{
			"__id":      llx.StringData("crio.namespaceSignaturePolicy/" + p),
			"namespace": llx.StringData(strings.TrimSuffix(path.Base(p), ".json")),
			"policy":    llx.ResourceData(policy, "containers.policy"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// isCrioNamespacePolicyFile reports whether a file of signature_policy_dir is
// the policy of a namespace, <namespace>.json.
func isCrioNamespacePolicyFile(name string) bool {
	return strings.HasSuffix(name, ".json") && !strings.HasPrefix(name, ".")
}

// crioRuntimeHandler is a [crio.runtime.runtimes.<name>] table.
type crioRuntimeHandler struct {
	Name                         string
	Path                         string
	Type                         string
	Root                         string
	MonitorPath                  string
	AllowedAnnotations           []any
	PrivilegedWithoutHostDevices bool
}

// crioRuntimeHandlers returns the runtime handlers of a configuration, by
// name. An empty runtime_type is CRI-O's default, oci. An entry that is not a
// table is not a handler and is left out.
func crioRuntimeHandlers(cfg map[string]any) []crioRuntimeHandler {
	runtimes, _ := crioConfigValue(cfg, "runtime", "runtimes").(map[string]any)
	names := make([]string, 0, len(runtimes))
	for name := range runtimes {
		names = append(names, name)
	}
	sort.Strings(names)
	res := []crioRuntimeHandler{}
	for _, name := range names {
		t, ok := runtimes[name].(map[string]any)
		if !ok {
			continue
		}
		h := crioRuntimeHandler{Name: name}
		h.Path, _ = t["runtime_path"].(string)
		h.Type, _ = t["runtime_type"].(string)
		if h.Type == "" {
			h.Type = "oci"
		}
		h.Root, _ = t["runtime_root"].(string)
		h.MonitorPath, _ = t["monitor_path"].(string)
		h.AllowedAnnotations = crioList(t["allowed_annotations"])
		h.PrivilegedWithoutHostDevices, _ = t["privileged_without_host_devices"].(bool)
		res = append(res, h)
	}
	return res
}

func (c *mqlCrio) runtimes() ([]any, error) {
	cfg := c.GetConfiguration()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	data, _ := cfg.Data.(map[string]any)
	defaultRuntime, _ := crioConfigValue(data, "runtime", "default_runtime").(string)
	res := []any{}
	for _, h := range crioRuntimeHandlers(data) {
		r, err := CreateResource(c.MqlRuntime, "crio.runtime", map[string]*llx.RawData{
			"__id":                         llx.StringData("crio.runtime/" + h.Name),
			"name":                         llx.StringData(h.Name),
			"path":                         llx.StringData(h.Path),
			"type":                         llx.StringData(h.Type),
			"root":                         llx.StringData(h.Root),
			"monitorPath":                  llx.StringData(h.MonitorPath),
			"allowedAnnotations":           llx.ArrayData(h.AllowedAnnotations, "string"),
			"privilegedWithoutHostDevices": llx.BoolData(h.PrivilegedWithoutHostDevices),
			"isDefault":                    llx.BoolData(h.Name == defaultRuntime),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

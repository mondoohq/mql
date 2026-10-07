// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	// crioDefaultSignaturePolicy is the policy CRI-O verifies images against
	// unless crio.image.signature_policy names another.
	crioDefaultSignaturePolicy = "/etc/containers/policy.json"
	// crioDefaultSignaturePolicyDir holds the per-namespace policies unless
	// crio.image.signature_policy_dir names another directory.
	crioDefaultSignaturePolicyDir = "/etc/crio/policies"
)

// crioPolicy is a containers-policy.json(5) file.
type crioPolicy struct {
	Default    []crioPolicyRequirement                       `json:"default"`
	Transports map[string]map[string][]crioPolicyRequirement `json:"transports"`
}

// crioPolicyRequirement is one requirement of a containers-policy.json(5)
// file. Key data, when given inline, is only reported as present.
type crioPolicyRequirement struct {
	Type                string         `json:"type"`
	KeyType             string         `json:"keyType"`
	KeyPath             string         `json:"keyPath"`
	KeyPaths            []string       `json:"keyPaths"`
	KeyData             string         `json:"keyData"`
	KeyDatas            []string       `json:"keyDatas"`
	Fulcio              *crioFulcio    `json:"fulcio"`
	RekorPublicKeyPath  string         `json:"rekorPublicKeyPath"`
	RekorPublicKeyPaths []string       `json:"rekorPublicKeyPaths"`
	SignedIdentity      map[string]any `json:"signedIdentity"`
}

type crioFulcio struct {
	CAPath       string `json:"caPath"`
	OIDCIssuer   string `json:"oidcIssuer"`
	SubjectEmail string `json:"subjectEmail"`
}

// parseCrioPolicy decodes a containers-policy.json(5) file. A file that is
// not valid JSON is an error rather than an empty policy, so that a broken
// policy never reads as one without requirements.
func parseCrioPolicy(content string) (crioPolicy, error) {
	var p crioPolicy
	if err := json.Unmarshal([]byte(content), &p); err != nil {
		return crioPolicy{}, fmt.Errorf("cannot parse image signature policy: %w", err)
	}
	return p, nil
}

// crioPolicyScope is a scope of a policy with its requirements.
type crioPolicyScope struct {
	Transport    string
	Scope        string
	Requirements []crioPolicyRequirement
}

// scopes returns the policy's scopes, by transport and then scope.
func (p crioPolicy) scopes() []crioPolicyScope {
	res := []crioPolicyScope{}
	for transport, scopes := range p.Transports {
		for scope, reqs := range scopes {
			res = append(res, crioPolicyScope{Transport: transport, Scope: scope, Requirements: reqs})
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Transport != res[j].Transport {
			return res[i].Transport < res[j].Transport
		}
		return res[i].Scope < res[j].Scope
	})
	return res
}

// keyPaths returns every public key file a requirement names.
func (r crioPolicyRequirement) keyPaths() []string {
	res := []string{}
	if r.KeyPath != "" {
		res = append(res, r.KeyPath)
	}
	return append(res, r.KeyPaths...)
}

// rekorKeyPaths returns every Rekor public key file a requirement names.
func (r crioPolicyRequirement) rekorKeyPaths() []string {
	res := []string{}
	if r.RekorPublicKeyPath != "" {
		res = append(res, r.RekorPublicKeyPath)
	}
	return append(res, r.RekorPublicKeyPaths...)
}

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

func (c *mqlCrio) signaturePolicy() (*mqlCrioImagePolicy, error) {
	p := c.imageConfig("signature_policy", crioDefaultSignaturePolicy)
	if readKubeletFile(c.MqlRuntime, p) == "" {
		c.SignaturePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newCrioImagePolicy(c.MqlRuntime, p, "")
}

func (c *mqlCrio) namespaceSignaturePolicies() ([]any, error) {
	dir := c.imageConfig("signature_policy_dir", crioDefaultSignaturePolicyDir)
	out, ok := runCommandQuiet(c.MqlRuntime, "ls -1A -- "+shellQuote(dir))
	if !ok {
		return []any{}, nil
	}
	res := []any{}
	for _, name := range crioNamespacePolicyFiles(strings.Split(strings.TrimSpace(out), "\n")) {
		policy, err := newCrioImagePolicy(c.MqlRuntime, path.Join(dir, name), strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}
	return res, nil
}

// crioNamespacePolicyFiles returns the per-namespace policy files of
// signature_policy_dir, <namespace>.json, by name.
func crioNamespacePolicyFiles(names []string) []string {
	res := []string{}
	for _, name := range names {
		if strings.HasSuffix(name, ".json") && !strings.HasPrefix(name, ".") && name != ".json" {
			res = append(res, name)
		}
	}
	sort.Strings(res)
	return res
}

func newCrioImagePolicy(runtime *plugin.Runtime, p, namespace string) (*mqlCrioImagePolicy, error) {
	r, err := CreateResource(runtime, "crio.imagePolicy", map[string]*llx.RawData{
		"__id":      llx.StringData("crio.imagePolicy/" + p),
		"path":      llx.StringData(p),
		"namespace": llx.StringData(namespace),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlCrioImagePolicy), nil
}

func (p *mqlCrioImagePolicy) file() (*mqlFile, error) {
	f, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p.Path.Data)})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

type mqlCrioImagePolicyInternal struct {
	lock      sync.Mutex
	fetched   bool
	parsed    crioPolicy
	policyErr error
}

// policy reads and parses the policy file once for all of its fields.
func (p *mqlCrioImagePolicy) policy() (crioPolicy, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.fetched {
		p.parsed, p.policyErr = parseCrioPolicy(readKubeletFile(p.MqlRuntime, p.Path.Data))
		p.fetched = true
	}
	return p.parsed, p.policyErr
}

func (p *mqlCrioImagePolicy) defaultRequirements() ([]any, error) {
	policy, err := p.policy()
	if err != nil {
		return nil, err
	}
	return newCrioRequirements(p.MqlRuntime, p.Path.Data+"/default", policy.Default)
}

func (p *mqlCrioImagePolicy) scopes() ([]any, error) {
	policy, err := p.policy()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, scope := range policy.scopes() {
		id := p.Path.Data + "/" + scope.Transport + "/" + scope.Scope
		reqs, err := newCrioRequirements(p.MqlRuntime, id, scope.Requirements)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(p.MqlRuntime, "crio.imagePolicy.scope", map[string]*llx.RawData{
			"__id":         llx.StringData("crio.imagePolicy.scope/" + id),
			"transport":    llx.StringData(scope.Transport),
			"scope":        llx.StringData(scope.Scope),
			"requirements": llx.ArrayData(reqs, "crio.imagePolicy.requirement"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// requirements is set when the scope is created.
func (s *mqlCrioImagePolicyScope) requirements() ([]any, error) {
	return []any{}, nil
}

func newCrioRequirements(runtime *plugin.Runtime, parentID string, reqs []crioPolicyRequirement) ([]any, error) {
	res := []any{}
	for i, req := range reqs {
		fulcio := crioFulcio{}
		if req.Fulcio != nil {
			fulcio = *req.Fulcio
		}
		identity := map[string]any{}
		for k, v := range req.SignedIdentity {
			identity[k] = v
		}
		r, err := CreateResource(runtime, "crio.imagePolicy.requirement", map[string]*llx.RawData{
			"__id":                llx.StringData("crio.imagePolicy.requirement/" + parentID + "/" + strconv.Itoa(i)),
			"type":                llx.StringData(req.Type),
			"keyType":             llx.StringData(req.KeyType),
			"keyPaths":            llx.ArrayData(stringsToAny(req.keyPaths()), "string"),
			"inlineKey":           llx.BoolData(req.KeyData != "" || len(req.KeyDatas) > 0),
			"fulcioCAPath":        llx.StringData(fulcio.CAPath),
			"fulcioOIDCIssuer":    llx.StringData(fulcio.OIDCIssuer),
			"fulcioSubjectEmail":  llx.StringData(fulcio.SubjectEmail),
			"rekorPublicKeyPaths": llx.ArrayData(stringsToAny(req.rekorKeyPaths()), "string"),
			"signedIdentity":      llx.DictData(identity),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
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

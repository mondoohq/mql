// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// containersDefaultPolicy is the policy Podman, Buildah, Skopeo and CRI-O
// verify images against unless they are told to use another.
const containersDefaultPolicy = "/etc/containers/policy.json"

// containersPolicyFile is a containers-policy.json(5) file.
type containersPolicyFile struct {
	Default    []containersPolicyRequirement                       `json:"default"`
	Transports map[string]map[string][]containersPolicyRequirement `json:"transports"`
}

// containersPolicyRequirement is one requirement of a
// containers-policy.json(5) file. Key data, when given inline, is only
// reported as present.
type containersPolicyRequirement struct {
	Type                string                  `json:"type"`
	KeyType             string                  `json:"keyType"`
	KeyPath             string                  `json:"keyPath"`
	KeyPaths            []string                `json:"keyPaths"`
	KeyData             string                  `json:"keyData"`
	KeyDatas            []string                `json:"keyDatas"`
	Fulcio              *containersPolicyFulcio `json:"fulcio"`
	RekorPublicKeyPath  string                  `json:"rekorPublicKeyPath"`
	RekorPublicKeyPaths []string                `json:"rekorPublicKeyPaths"`
	SignedIdentity      map[string]any          `json:"signedIdentity"`
}

type containersPolicyFulcio struct {
	CAPath       string `json:"caPath"`
	OIDCIssuer   string `json:"oidcIssuer"`
	SubjectEmail string `json:"subjectEmail"`
}

// parseContainersPolicy decodes a containers-policy.json(5) file. A file that
// is not valid JSON is an error rather than an empty policy, so that a broken
// policy never reads as one without requirements.
func parseContainersPolicy(content string) (containersPolicyFile, error) {
	var p containersPolicyFile
	if err := json.Unmarshal([]byte(content), &p); err != nil {
		return containersPolicyFile{}, fmt.Errorf("cannot parse image signature policy: %w", err)
	}
	return p, nil
}

// containersPolicyScope is a scope of a policy with its requirements.
type containersPolicyScope struct {
	Transport    string
	Scope        string
	Requirements []containersPolicyRequirement
}

// scopes returns the policy's scopes, by transport and then scope.
func (p containersPolicyFile) scopes() []containersPolicyScope {
	res := []containersPolicyScope{}
	for transport, scopes := range p.Transports {
		for scope, reqs := range scopes {
			res = append(res, containersPolicyScope{Transport: transport, Scope: scope, Requirements: reqs})
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
func (r containersPolicyRequirement) keyPaths() []string {
	res := []string{}
	if r.KeyPath != "" {
		res = append(res, r.KeyPath)
	}
	return append(res, r.KeyPaths...)
}

// rekorKeyPaths returns every Rekor public key file a requirement names.
func (r containersPolicyRequirement) rekorKeyPaths() []string {
	res := []string{}
	if r.RekorPublicKeyPath != "" {
		res = append(res, r.RekorPublicKeyPath)
	}
	return append(res, r.RekorPublicKeyPaths...)
}

func initContainersPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if _, ok := x.Value.(string); !ok {
			return nil, nil, errors.New("wrong type for 'path' in containers.policy initialization, it must be a string")
		}
		return args, nil, nil
	}
	args["path"] = llx.StringData(containersDefaultPolicy)
	return args, nil, nil
}

func newContainersPolicy(runtime *plugin.Runtime, p string) (*mqlContainersPolicy, error) {
	r, err := NewResource(runtime, "containers.policy", map[string]*llx.RawData{
		"path": llx.StringData(p),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlContainersPolicy), nil
}

func (p *mqlContainersPolicy) id() (string, error) {
	return p.Path.Data, nil
}

func (p *mqlContainersPolicy) file() (*mqlFile, error) {
	f, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p.Path.Data)})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

type mqlContainersPolicyInternal struct {
	lock      sync.Mutex
	fetched   bool
	parsed    containersPolicyFile
	policyErr error
}

// policy reads and parses the policy file once for all of its fields. A
// missing file is not an empty policy: the tools refuse to pull without one.
func (p *mqlContainersPolicy) policy() (containersPolicyFile, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.fetched {
		p.parsed, p.policyErr = p.read()
		p.fetched = true
	}
	return p.parsed, p.policyErr
}

func (p *mqlContainersPolicy) read() (containersPolicyFile, error) {
	f, err := p.file()
	if err != nil {
		return containersPolicyFile{}, err
	}
	exists := f.GetExists()
	if exists.Error != nil {
		return containersPolicyFile{}, exists.Error
	}
	if !exists.Data {
		return containersPolicyFile{}, llx.NotFound(fmt.Errorf("image signature policy %s does not exist", p.Path.Data))
	}
	content := f.GetContent()
	if content.Error != nil {
		return containersPolicyFile{}, content.Error
	}
	return parseContainersPolicy(content.Data)
}

func (p *mqlContainersPolicy) defaultRequirements() ([]any, error) {
	policy, err := p.policy()
	if err != nil {
		return nil, err
	}
	return newContainersPolicyRequirements(p.MqlRuntime, p.Path.Data+"/default", policy.Default)
}

func (p *mqlContainersPolicy) scopes() ([]any, error) {
	policy, err := p.policy()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, scope := range policy.scopes() {
		id := p.Path.Data + "/" + scope.Transport + "/" + scope.Scope
		reqs, err := newContainersPolicyRequirements(p.MqlRuntime, id, scope.Requirements)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(p.MqlRuntime, "containers.policy.scope", map[string]*llx.RawData{
			"__id":         llx.StringData("containers.policy.scope/" + id),
			"transport":    llx.StringData(scope.Transport),
			"scope":        llx.StringData(scope.Scope),
			"requirements": llx.ArrayData(reqs, types.Resource("containers.policy.requirement")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// requirements is set when the scope is created.
func (s *mqlContainersPolicyScope) requirements() ([]any, error) {
	return []any{}, nil
}

func newContainersPolicyRequirements(runtime *plugin.Runtime, parentID string, reqs []containersPolicyRequirement) ([]any, error) {
	res := []any{}
	for i, req := range reqs {
		fulcio := containersPolicyFulcio{}
		if req.Fulcio != nil {
			fulcio = *req.Fulcio
		}
		identity := map[string]any{}
		for k, v := range req.SignedIdentity {
			identity[k] = v
		}
		r, err := CreateResource(runtime, "containers.policy.requirement", map[string]*llx.RawData{
			"__id":                llx.StringData("containers.policy.requirement/" + parentID + "/" + strconv.Itoa(i)),
			"type":                llx.StringData(req.Type),
			"keyType":             llx.StringData(req.KeyType),
			"keyPaths":            llx.ArrayData(stringsToAny(req.keyPaths()), types.String),
			"inlineKey":           llx.BoolData(req.KeyData != "" || len(req.KeyDatas) > 0),
			"fulcioCAPath":        llx.StringData(fulcio.CAPath),
			"fulcioOIDCIssuer":    llx.StringData(fulcio.OIDCIssuer),
			"fulcioSubjectEmail":  llx.StringData(fulcio.SubjectEmail),
			"rekorPublicKeyPaths": llx.ArrayData(stringsToAny(req.rekorKeyPaths()), types.String),
			"signedIdentity":      llx.DictData(identity),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

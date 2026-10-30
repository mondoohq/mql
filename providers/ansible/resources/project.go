// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ansible/connection"
	"go.mondoo.com/mql/providers/ansible/play"
	"go.mondoo.com/mql/providers/ansible/project"
	"go.mondoo.com/mql/types"
)

// ansibleProject returns the parsed project model, or nil when the provider is
// connected to a single playbook file rather than a directory.
func ansibleProject(runtime *plugin.Runtime) *project.Project {
	conn, ok := runtime.Connection.(*connection.AnsibleConnection)
	if !ok {
		return nil
	}
	return conn.Project()
}

func initAnsibleProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["path"]; ok {
		return args, nil, nil
	}
	path := ""
	if proj := ansibleProject(runtime); proj != nil {
		path = proj.Root
	}
	args["path"] = llx.StringData(path)
	return args, nil, nil
}

func (r *mqlAnsibleProject) playbooks() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Playbooks))
	for _, pf := range proj.Playbooks {
		mqlPb, err := newMqlAnsiblePlaybook(r.MqlRuntime, pf.Path, pf.Plays)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlPb)
	}
	return out, nil
}

func (r *mqlAnsibleProject) roles() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Roles))
	for _, role := range proj.Roles {
		mqlRole, err := newMqlAnsibleRole(r.MqlRuntime, role)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlRole)
	}
	return out, nil
}

func (r *mqlAnsibleProject) inventory() (*mqlAnsibleInventory, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Inventory == nil {
		r.Inventory.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "ansible.inventory", map[string]*llx.RawData{
		"__id": llx.StringData(proj.Root + "/inventory"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleInventory), nil
}

func (r *mqlAnsibleProject) requirements() (*mqlAnsibleGalaxyRequirements, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Requirements == nil {
		r.Requirements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "ansible.galaxy.requirements", map[string]*llx.RawData{
		"__id": llx.StringData(proj.Requirements.Path),
		"path": llx.StringData(proj.Requirements.Path),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleGalaxyRequirements), nil
}

func (r *mqlAnsibleProject) collections() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Collections))
	for _, c := range proj.Collections {
		res, err := CreateResource(r.MqlRuntime, "ansible.collection", map[string]*llx.RawData{
			"__id":      llx.StringData(c.Path),
			"name":      llx.StringData(c.Name),
			"namespace": llx.StringData(c.Namespace),
			"version":   llx.StringData(c.Version),
			"path":      llx.StringData(c.Path),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAnsibleProject) plugins() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Plugins))
	for _, p := range proj.Plugins {
		res, err := CreateResource(r.MqlRuntime, "ansible.plugin", map[string]*llx.RawData{
			"__id": llx.StringData(p.Path),
			"name": llx.StringData(p.Name),
			"type": llx.StringData(p.Type),
			"path": llx.StringData(p.Path),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAnsibleProject) manifest() (*mqlAnsibleGalaxyManifest, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Manifest == nil {
		r.Manifest.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	m := proj.Manifest
	res, err := CreateResource(r.MqlRuntime, "ansible.galaxy.manifest", map[string]*llx.RawData{
		"__id":      llx.StringData(m.Path),
		"path":      llx.StringData(m.Path),
		"namespace": llx.StringData(m.Namespace),
		"name":      llx.StringData(m.Name),
		"version":   llx.StringData(m.Version),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleGalaxyManifest), nil
}

func (r *mqlAnsibleProject) lintConfig() (string, error) {
	if proj := ansibleProject(r.MqlRuntime); proj != nil {
		return proj.LintConfig, nil
	}
	return "", nil
}

func (r *mqlAnsibleProject) moleculeScenarios() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	return convert.SliceAnyToInterface(proj.MoleculeScenarios), nil
}

func (r *mqlAnsibleProject) config() (*mqlAnsibleConfig, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Config == nil {
		r.Config.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cfg := proj.Config
	sections := make(map[string]any, len(cfg.Sections))
	for name, kv := range cfg.Sections {
		sections[name] = kv
	}
	res, err := CreateResource(r.MqlRuntime, "ansible.config", map[string]*llx.RawData{
		"__id":            llx.StringData(cfg.Path),
		"path":            llx.StringData(cfg.Path),
		"sections":        dictMapData(sections),
		"hostKeyChecking": llx.BoolData(cfg.HostKeyChecking),
		"become":          llx.BoolData(cfg.Become),
		"becomeUser":      llx.StringData(cfg.BecomeUser),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleConfig), nil
}

func (r *mqlAnsibleProject) vault() (*mqlAnsibleVault, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		r.Vault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "ansible.vault", map[string]*llx.RawData{
		"__id": llx.StringData(proj.Root + "/vault"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleVault), nil
}

// --- ansible.playbook ---

type mqlAnsiblePlaybookInternal struct {
	playbook play.Playbook
	baseDir  string
}

func newMqlAnsiblePlaybook(runtime *plugin.Runtime, path string, playbook play.Playbook) (*mqlAnsiblePlaybook, error) {
	res, err := CreateResource(runtime, "ansible.playbook", map[string]*llx.RawData{
		"__id": llx.StringData(path),
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	mqlPb := res.(*mqlAnsiblePlaybook)
	mqlPb.playbook = playbook
	mqlPb.baseDir = filepath.Dir(path)
	return mqlPb, nil
}

func (r *mqlAnsiblePlaybook) plays() ([]any, error) {
	return newMqlAnsiblePlays(r.MqlRuntime, r.MqlID()+"/", r.baseDir, r.playbook)
}

// --- ansible.role ---

type mqlAnsibleRoleInternal struct {
	role *project.Role
}

func newMqlAnsibleRole(runtime *plugin.Runtime, role *project.Role) (*mqlAnsibleRole, error) {
	res, err := CreateResource(runtime, "ansible.role", map[string]*llx.RawData{
		"__id":          llx.StringData(role.Path),
		"name":          llx.StringData(role.Name),
		"path":          llx.StringData(role.Path),
		"defaults":      dictMapData(role.Defaults),
		"vars":          dictMapData(role.Vars),
		"argumentSpecs": dictData(role.ArgumentSpecs),
		"templates":     llx.ArrayData(convert.SliceAnyToInterface(role.Templates), types.String),
		"files":         llx.ArrayData(convert.SliceAnyToInterface(role.Files), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlRole := res.(*mqlAnsibleRole)
	mqlRole.role = role
	return mqlRole, nil
}

func (r *mqlAnsibleRole) tasks() ([]any, error) {
	// role is nil when the resource was instantiated bare (e.g. a top-level
	// `ansible.role` query, or recording replay) rather than through
	// newMqlAnsibleRole. Guard before dereferencing, matching the sibling
	// ansible.play / ansible.task accessors.
	if r.role == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "tasks", filepath.Join(r.role.Path, "tasks"), r.role.Tasks)
}

func (r *mqlAnsibleRole) handlers() ([]any, error) {
	if r.role == nil {
		return []any{}, nil
	}
	return newMqlAnsibleHandlers(r.MqlRuntime, r.MqlID(), r.role.Handlers)
}

func (r *mqlAnsibleRole) meta() (*mqlAnsibleRoleMeta, error) {
	if r.role == nil || r.role.Meta == nil {
		r.Meta.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	meta := r.role.Meta
	res, err := CreateResource(r.MqlRuntime, "ansible.role.meta", map[string]*llx.RawData{
		"__id":              llx.StringData(r.MqlID() + "/meta"),
		"minAnsibleVersion": llx.StringData(meta.MinAnsibleVersion),
		"galaxyInfo":        dictData(meta.GalaxyInfo),
		"dependencies":      llx.ArrayData(convert.SliceAnyToInterface(meta.Dependencies), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleRoleMeta), nil
}

func (r *mqlAnsibleRole) dependencies() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || r.role == nil {
		return []any{}, nil
	}
	return newMqlAnsibleRoleRefs(r.MqlRuntime, proj, r.role.DependencyNames)
}

// newMqlAnsibleRoleRefs resolves role names to their role resources, dropping
// names that do not match a role in the project. Roles are keyed by path, so a
// referenced role shares the same resource instance as its definition.
func newMqlAnsibleRoleRefs(runtime *plugin.Runtime, proj *project.Project, names []string) ([]any, error) {
	out := []any{}
	for _, name := range names {
		role := proj.RoleByName(name)
		if role == nil {
			continue
		}
		mqlRole, err := newMqlAnsibleRole(runtime, role)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlRole)
	}
	return out, nil
}

// --- ansible.inventory ---

func (r *mqlAnsibleInventory) groups() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Inventory == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Inventory.Groups))
	for _, g := range proj.Inventory.Groups {
		res, err := CreateResource(r.MqlRuntime, "ansible.inventory.group", map[string]*llx.RawData{
			"__id":     llx.StringData(proj.Root + "/group/" + g.Name),
			"name":     llx.StringData(g.Name),
			"hosts":    llx.ArrayData(convert.SliceAnyToInterface(g.Hosts), types.String),
			"children": llx.ArrayData(convert.SliceAnyToInterface(g.Children), types.String),
			"vars":     dictMapData(g.Vars),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAnsibleInventory) hosts() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Inventory == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Inventory.Hosts))
	for _, h := range proj.Inventory.Hosts {
		res, err := CreateResource(r.MqlRuntime, "ansible.inventory.host", map[string]*llx.RawData{
			"__id":   llx.StringData(proj.Root + "/host/" + h.Name),
			"name":   llx.StringData(h.Name),
			"groups": llx.ArrayData(convert.SliceAnyToInterface(h.Groups), types.String),
			"vars":   dictMapData(h.Vars),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- ansible.galaxy.requirements ---

func (r *mqlAnsibleGalaxyRequirements) roles() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Requirements == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Requirements.Roles))
	for i, role := range proj.Requirements.Roles {
		res, err := CreateResource(r.MqlRuntime, "ansible.galaxy.role", map[string]*llx.RawData{
			"__id":    llx.StringData(r.MqlID() + "/role[" + strconv.Itoa(i) + "]"),
			"name":    llx.StringData(role.Name),
			"src":     llx.StringData(role.Src),
			"version": llx.StringData(role.Version),
			"scm":     llx.StringData(role.SCM),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAnsibleGalaxyRequirements) collections() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil || proj.Requirements == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.Requirements.Collections))
	for i, col := range proj.Requirements.Collections {
		res, err := CreateResource(r.MqlRuntime, "ansible.galaxy.collection", map[string]*llx.RawData{
			"__id":    llx.StringData(r.MqlID() + "/collection[" + strconv.Itoa(i) + "]"),
			"name":    llx.StringData(col.Name),
			"version": llx.StringData(col.Version),
			"source":  llx.StringData(col.Source),
			"type":    llx.StringData(col.Type),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- ansible.vault ---

func (r *mqlAnsibleVault) files() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.VaultFiles))
	for _, vf := range proj.VaultFiles {
		res, err := CreateResource(r.MqlRuntime, "ansible.vault.file", map[string]*llx.RawData{
			"__id":    llx.StringData(vf.Path),
			"path":    llx.StringData(vf.Path),
			"format":  llx.StringData(vf.Format),
			"cipher":  llx.StringData(vf.Cipher),
			"vaultId": llx.StringData(vf.VaultID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAnsibleVault) variables() ([]any, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(proj.VaultVars))
	for _, vv := range proj.VaultVars {
		res, err := CreateResource(r.MqlRuntime, "ansible.vault.variable", map[string]*llx.RawData{
			"__id": llx.StringData(vv.Path + "#" + vv.Key),
			"key":  llx.StringData(vv.Key),
			"file": llx.StringData(vv.Path),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ansible/connection"
)

func newProjectRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": "./testdata/project"},
	}}}
	conn, err := connection.NewAnsibleConnection(1, asset, &inventory.Config{})
	require.NoError(t, err)
	require.True(t, conn.IsProject(), "testdata/project must connect as a project")
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func findRole(t *testing.T, roles []any, name string) *mqlAnsibleRole {
	t.Helper()
	for _, r := range roles {
		role := r.(*mqlAnsibleRole)
		if role.Name.Data == name {
			return role
		}
	}
	t.Fatalf("role %q not found", name)
	return nil
}

func TestProjectPlaybooks(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	playbooks, err := proj.playbooks()
	require.NoError(t, err)
	require.Len(t, playbooks, 1)

	pb := playbooks[0].(*mqlAnsiblePlaybook)
	plays, err := pb.plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)
	assert.Equal(t, "Configure web servers", plays[0].(*mqlAnsiblePlay).Name.Data)
}

func TestProjectRolesAndDependencies(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	roles, err := proj.roles()
	require.NoError(t, err)
	require.Len(t, roles, 2)

	nginx := findRole(t, roles, "nginx")

	tasks, err := nginx.tasks()
	require.NoError(t, err)
	assert.Len(t, tasks, 2)

	handlers, err := nginx.handlers()
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	assert.Equal(t, "restart nginx", handlers[0].(*mqlAnsibleHandler).Name.Data)

	assert.Equal(t, int64(80), nginx.Defaults.Data["nginx_port"])
	assert.Equal(t, "nginx", nginx.Vars.Data["nginx_package_name"])
	assert.Contains(t, nginx.Templates.Data, "nginx.conf.j2")
	assert.Contains(t, nginx.Files.Data, "index.html")

	// meta resolves through the ansible.role.meta resource despite sharing the
	// field path with the resource name.
	meta, err := nginx.meta()
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, "2.10", meta.MinAnsibleVersion.Data)

	// dependencies resolve by name to the typed common role.
	deps, err := nginx.dependencies()
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "common", deps[0].(*mqlAnsibleRole).Name.Data)
}

// A bare ansible.role (Internal .role unset) is what a top-level `ansible.role`
// query or a recording replay produces. Its accessors must degrade to
// empty/null rather than panic on the nil dereference, matching the sibling
// ansible.play / ansible.task accessors.
func TestRoleAccessorsNilRole(t *testing.T) {
	rt := newProjectRuntime(t)
	role := &mqlAnsibleRole{MqlRuntime: rt}

	tasks, err := role.tasks()
	require.NoError(t, err)
	assert.Empty(t, tasks)

	handlers, err := role.handlers()
	require.NoError(t, err)
	assert.Empty(t, handlers)

	meta, err := role.meta()
	require.NoError(t, err)
	assert.Nil(t, meta)

	deps, err := role.dependencies()
	require.NoError(t, err)
	assert.Empty(t, deps)
}

func TestProjectPlayRoleApplications(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	playbooks, err := proj.playbooks()
	require.NoError(t, err)
	plays, err := playbooks[0].(*mqlAnsiblePlaybook).plays()
	require.NoError(t, err)

	apps, err := plays[0].(*mqlAnsiblePlay).roleApplications()
	require.NoError(t, err)
	require.Len(t, apps, 1)

	app := apps[0].(*mqlAnsiblePlayRoleApplication)
	assert.Equal(t, "nginx", app.Name.Data)
	assert.Equal(t, `ansible_os_family == "Debian"`, app.When.Data)
	assert.Equal(t, []any{"web"}, app.Tags.Data)
	assert.Equal(t, int64(8080), app.Vars.Data["http_port"])

	role, err := app.role()
	require.NoError(t, err)
	require.NotNil(t, role)
	assert.Equal(t, "nginx", role.Name.Data)
}

func TestProjectPlayLevelVars(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	playbooks, err := proj.playbooks()
	require.NoError(t, err)
	plays, err := playbooks[0].(*mqlAnsiblePlaybook).plays()
	require.NoError(t, err)
	p := plays[0].(*mqlAnsiblePlay)

	assert.Equal(t, []any{"vars/secrets.yml"}, p.VarsFiles.Data)
	assert.Equal(t, []any{"community.general"}, p.Collections.Data)
	assert.Equal(t, "http://proxy.example.com:8080", p.Environment.Data["HTTP_PROXY"])
	require.Len(t, p.VarsPrompt.Data, 1)
	prompt := p.VarsPrompt.Data[0].(map[string]any)
	assert.Equal(t, "admin_password", prompt["name"])
}

func TestProjectTaskModule(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	playbooks, err := proj.playbooks()
	require.NoError(t, err)
	plays, err := playbooks[0].(*mqlAnsiblePlaybook).plays()
	require.NoError(t, err)

	tasks, err := plays[0].(*mqlAnsiblePlay).tasks()
	require.NoError(t, err)
	require.Len(t, tasks, 1)

	task := tasks[0].(*mqlAnsibleTask)
	module, err := task.module()
	require.NoError(t, err)
	assert.Equal(t, "ansible.builtin.service", module)

	args, err := task.moduleArgs()
	require.NoError(t, err)
	argMap, ok := args.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "nginx", argMap["name"])
	assert.Equal(t, "started", argMap["state"])
}

func TestProjectRoleArgumentSpecs(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	roles, err := proj.roles()
	require.NoError(t, err)
	nginx := findRole(t, roles, "nginx")

	specs, ok := nginx.ArgumentSpecs.Data.(map[string]any)
	require.True(t, ok)
	main, ok := specs["main"].(map[string]any)
	require.True(t, ok, "argument_specs should have a main entrypoint")
	assert.Equal(t, "Configure nginx", main["short_description"])
}

func TestProjectPlugins(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	plugins, err := proj.plugins()
	require.NoError(t, err)
	require.Len(t, plugins, 2)

	byType := map[string]string{}
	for _, p := range plugins {
		pl := p.(*mqlAnsiblePlugin)
		byType[pl.Type.Data] = pl.Name.Data
	}
	assert.Equal(t, "acme_widget", byType["module"])
	assert.Equal(t, "acme_filters", byType["filter"])
}

func TestProjectVendoredCollections(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	collections, err := proj.collections()
	require.NoError(t, err)
	require.Len(t, collections, 1)

	c := collections[0].(*mqlAnsibleCollection)
	assert.Equal(t, "acme.util", c.Name.Data)
	assert.Equal(t, "acme", c.Namespace.Data)
	assert.Equal(t, "2.3.1", c.Version.Data)
}

func TestProjectManifest(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	manifest, err := proj.manifest()
	require.NoError(t, err)
	require.NotNil(t, manifest)
	assert.Equal(t, "example", manifest.Namespace.Data)
	assert.Equal(t, "webstack", manifest.Name.Data)
	assert.Equal(t, "1.0.0", manifest.Version.Data)
}

func TestProjectInlineVaultVars(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	vault, err := proj.vault()
	require.NoError(t, err)

	vars, err := vault.variables()
	require.NoError(t, err)
	require.Len(t, vars, 1)

	vv := vars[0].(*mqlAnsibleVaultVariable)
	assert.Equal(t, "db_password", vv.Key.Data)
	assert.Contains(t, vv.File.Data, "webservers.yml")
}

func TestProjectVaultId(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	vault, err := proj.vault()
	require.NoError(t, err)
	files, err := vault.files()
	require.NoError(t, err)
	require.Len(t, files, 1)
	// The fully-encrypted fixture has no vault-id label.
	assert.Equal(t, "", files[0].(*mqlAnsibleVaultFile).VaultId.Data)
}

func TestProjectTooling(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	lint, err := proj.lintConfig()
	require.NoError(t, err)
	assert.Contains(t, lint, ".ansible-lint")

	scenarios, err := proj.moleculeScenarios()
	require.NoError(t, err)
	assert.Equal(t, []any{"default"}, scenarios)
}

func TestProjectImportedTasks(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	playbooks, err := proj.playbooks()
	require.NoError(t, err)
	plays, err := playbooks[0].(*mqlAnsiblePlaybook).plays()
	require.NoError(t, err)

	pre, err := plays[0].(*mqlAnsiblePlay).preTasks()
	require.NoError(t, err)
	require.Len(t, pre, 1)

	imported, err := pre[0].(*mqlAnsibleTask).importedTasks()
	require.NoError(t, err)
	require.Len(t, imported, 2, "tasks/setup.yml has two tasks")
	assert.Equal(t, "Install base packages", imported[0].(*mqlAnsibleTask).Name.Data)
}

// A crafted import/include reference must not escape the analysis root, so the
// provider cannot be tricked into reading arbitrary host files.
func TestResolveRefPathContainment(t *testing.T) {
	root := "/project"
	cases := []struct {
		baseDir, ref string
		want         string
	}{
		{"/project", "tasks/setup.yml", "/project/tasks/setup.yml"},
		{"/project/roles/web/tasks", "../handlers/main.yml", "/project/roles/web/handlers/main.yml"},
		{"/project", "/etc/shadow", ""},
		{"/project", "../../etc/passwd", ""},
		{"/project", "../outside.yml", ""},
		{"/project", "{{ role_path }}/tasks.yml", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, resolveRefPath(c.baseDir, root, c.ref), "baseDir=%q ref=%q", c.baseDir, c.ref)
	}
}

func TestProjectInventory(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	inv, err := proj.inventory()
	require.NoError(t, err)
	require.NotNil(t, inv)

	groups, err := inv.groups()
	require.NoError(t, err)

	webservers := findGroup(t, groups, "webservers")
	assert.ElementsMatch(t, []any{"web1.example.com", "web2.example.com"}, webservers.Hosts.Data)
	assert.Equal(t, "80", webservers.Vars.Data["http_port"])

	production := findGroup(t, groups, "production")
	assert.Contains(t, production.Children.Data, "webservers")

	all := findGroup(t, groups, "all")
	assert.Equal(t, "pool.ntp.org", all.Vars.Data["ntp_server"])

	hosts, err := inv.hosts()
	require.NoError(t, err)
	web1 := findHost(t, hosts, "web1.example.com")
	assert.Equal(t, "10.0.0.1", web1.Vars.Data["ansible_host"])
	assert.Equal(t, int64(1), web1.Vars.Data["server_id"])
	assert.Contains(t, web1.Groups.Data, "webservers")
}

func findGroup(t *testing.T, groups []any, name string) *mqlAnsibleInventoryGroup {
	t.Helper()
	for _, g := range groups {
		group := g.(*mqlAnsibleInventoryGroup)
		if group.Name.Data == name {
			return group
		}
	}
	t.Fatalf("group %q not found", name)
	return nil
}

func findHost(t *testing.T, hosts []any, name string) *mqlAnsibleInventoryHost {
	t.Helper()
	for _, h := range hosts {
		host := h.(*mqlAnsibleInventoryHost)
		if host.Name.Data == name {
			return host
		}
	}
	t.Fatalf("host %q not found", name)
	return nil
}

func TestProjectRequirements(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	req, err := proj.requirements()
	require.NoError(t, err)
	require.NotNil(t, req)

	roles, err := req.roles()
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, "geerlingguy.nginx", roles[0].(*mqlAnsibleGalaxyRole).Name.Data)
	assert.Equal(t, "3.1.4", roles[0].(*mqlAnsibleGalaxyRole).Version.Data)

	collections, err := req.collections()
	require.NoError(t, err)
	require.Len(t, collections, 2)
	assert.Equal(t, "community.general", collections[0].(*mqlAnsibleGalaxyCollection).Name.Data)
}

func TestProjectConfig(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	cfg, err := proj.config()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.False(t, cfg.HostKeyChecking.Data, "host_key_checking = False")
	assert.True(t, cfg.Become.Data)
	assert.Equal(t, "root", cfg.BecomeUser.Data)

	defaults, ok := cfg.Sections.Data["defaults"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "./roles", defaults["roles_path"])
}

func TestProjectVault(t *testing.T) {
	rt := newProjectRuntime(t)
	proj := &mqlAnsibleProject{MqlRuntime: rt}

	vault, err := proj.vault()
	require.NoError(t, err)
	require.NotNil(t, vault)

	files, err := vault.files()
	require.NoError(t, err)
	require.Len(t, files, 1)

	vf := files[0].(*mqlAnsibleVaultFile)
	assert.Equal(t, "1.1", vf.Format.Data)
	assert.Equal(t, "AES256", vf.Cipher.Data)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package play

import (
	"maps"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Playbook is a collection of plays
type Playbook []*Play

// Play is a collection of tasks to be executed
// see https://docs.ansible.com/projects/ansible/latest/reference_appendices/playbooks_keywords.html
type Play struct {
	// Name is the name of the play
	Name string `yaml:"name,omitempty"`

	// Hosts is a pattern that matches hosts
	// see https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_patterns.html
	Hosts any `yaml:"hosts"`

	// RemoteUser sets the user to use for the connection
	// see https://docs.ansible.com/projects/ansible/latest/inventory_guide/connection_details.html
	RemoteUser string `yaml:"remote_user,omitempty"`

	// Become sets to true to activate privilege escalation.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	Become bool `yaml:"become,omitempty"`

	// BecomeUser sets to user with desired privileges
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeUser string `yaml:"become_user,omitempty"`

	// BecomeMethod overrides the default method of privilege escalation
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeMethod string `yaml:"become_method,omitempty"`

	// BecomeFlags permits the use of specific flags
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeFlags string `yaml:"become_flags,omitempty"`

	// Serial sets the batch size
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_strategies.html#setting-the-batch-size-with-serial
	Serial any `yaml:"serial,omitempty"` // Can be an integer or a string

	// Playbook execution strategy
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_strategies.html
	Strategy string `yaml:"strategy,omitempty"`

	// MaxFailPercentage sets a maximum failure percentage. Ansible types this
	// field as a percent, so beyond a plain integer it also accepts a float
	// (33.3) or a percent-suffixed string ("30%"). Decode it as any and
	// normalize with MaxFailPercentageValue so one of those forms can't fail
	// the whole playbook decode.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#maximum-failure-percentage
	MaxFailPercentage any `yaml:"max_fail_percentage,omitempty"`

	// IgnoreUnreachable sets to true to ignore unreachable hosts
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#ignore-unreachable
	IgnoreUnreachable bool `yaml:"ignore_unreachable,omitempty"`

	// AnyErrorsFatal finishes the fatal task on all hosts in the current batch
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#aborting-on-the-first-error-any-errors-fatal
	AnyErrorsFatal bool `yaml:"any_errors_fatal,omitempty"`

	// Vars are variables to be used in the play
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html
	Vars map[string]any `yaml:"vars,omitempty"`

	// Tags scope which plays run with --tags / --skip-tags
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_tags.html
	Tags []string `yaml:"tags,omitempty"`

	// Roles are a list of roles to be applied to the play. An entry is either a
	// bare role name or a mapping with a `role` key plus application directives
	// (when, tags, vars), so it is decoded as any and normalized by
	// RoleApplications.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_reuse_roles.html
	Roles []any `yaml:"roles,omitempty"`

	// VarsFiles lists files of variables loaded into the play
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html#defining-variables-in-files
	VarsFiles []string `yaml:"vars_files,omitempty"`

	// VarsPrompt defines variables prompted for interactively at runtime
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_prompts.html
	VarsPrompt []map[string]any `yaml:"vars_prompt,omitempty"`

	// Environment sets environment variables for all tasks in the play
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_environment.html
	Environment map[string]any `yaml:"environment,omitempty"`

	// Collections lists the collection search order for unqualified module names
	// see https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_using_playbooks.html
	Collections []string `yaml:"collections,omitempty"`

	// PreTasks run before roles
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_reuse_roles.html#using-roles
	PreTasks []*Task `yaml:"pre_tasks,omitempty"`

	// Tasks are a list of tasks to be executed
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_intro.html#id4
	Tasks []*Task `yaml:"tasks"`

	// PostTasks run after roles and tasks
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_reuse_roles.html#using-roles
	PostTasks []*Task `yaml:"post_tasks,omitempty"`

	// Handlers are tasks that only run when notified
	Handlers []*Handler `yaml:"handlers,omitempty"`

	GatherFacts string `yaml:"gather_facts,omitempty"`
}

// MaxFailPercentageValue normalizes the play's max_fail_percentage into an
// integer percentage. Ansible types the field as a percent, so it may arrive
// from YAML as an int, a float (33.3), or a string with an optional trailing
// "%" ("30%"). Unrecognized or absent values yield 0, Ansible's default.
func (p *Play) MaxFailPercentageValue() int64 {
	switch v := p.MaxFailPercentage.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "%"))
		if s == "" {
			return 0
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f)
		}
		return 0
	default:
		return 0
	}
}

// Tasks is a list of tasks to be executed
type Tasks struct {
	// Tasks are a list of tasks to be executed
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_intro.html#id4
	Tasks []*Task `yaml:"tasks"`
}

// Task is a single task to be executed
// see https://docs.ansible.com/projects/ansible/latest/reference_appendices/playbooks_keywords.html#task
type Task struct {
	// Name is the name of the task
	Name string `yaml:"name,omitempty"`

	// Action is the module to be executed
	Action map[string]any `yaml:",inline"` // Use inline to handle dynamic task modules

	// Vars are variables to be used in the play
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html
	Vars map[string]any `yaml:"vars,omitempty"`

	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_tags.html
	Tags []string `yaml:"tags,omitempty"`

	// Register is a variable to store the result of the task
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html#registering-variables
	Register string `yaml:"register,omitempty"`

	// Become sets to true to activate privilege escalation.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	Become bool `yaml:"become,omitempty"`

	// BecomeUser sets to user with desired privileges
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeUser string `yaml:"become_user,omitempty"`

	// BecomeMethod overrides the default method of privilege escalation
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeMethod string `yaml:"become_method,omitempty"`

	// BecomeFlags permits the use of specific flags
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html#become
	BecomeFlags string `yaml:"become_flags,omitempty"`

	// DelegateTo delegates the task to a specific host
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_delegation.html#delegating-tasks
	DelegateTo string `yaml:"delegate_to,omitempty"`

	// Environment sets environment variables for the task
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_environment.html
	Environment map[string]any `yaml:"environment,omitempty"`

	// NoLog hides sensitive task output from logs. Usually a boolean but
	// Ansible also accepts a Jinja2 templated string, so it is decoded as any.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_advanced_syntax.html#keep-secret-data
	NoLog any `yaml:"no_log,omitempty"`

	// IgnoreErrors continues the play even if the task fails. Usually a boolean
	// but Ansible also accepts a Jinja2 templated string, so it is decoded as any.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#ignoring-failed-commands
	IgnoreErrors any `yaml:"ignore_errors,omitempty"`

	// RunOnce runs the task on only one host. Usually a boolean but Ansible
	// also accepts a Jinja2 templated string, so it is decoded as any.
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_delegation.html#run-once
	RunOnce any `yaml:"run_once,omitempty"`

	// Conditional statement to execute the task
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_conditionals.html#basic-conditionals-with-when
	When string `yaml:"when,omitempty"`

	// Failed condition
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#defining-failure
	FailedWhen string `yaml:"failed_when,omitempty"`

	// Changed condition
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html#defining-changed
	ChangedWhen string `yaml:"changed_when,omitempty"`

	// Notify is a list of handlers to notify
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_handlers.html
	Notify []string `yaml:"notify,omitempty"`

	// Loop is the items the task iterates over
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_loops.html
	Loop any `yaml:"loop,omitempty"`

	// LoopControl tunes loop behavior (loop_var, label, index_var, pause, etc.)
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_loops.html#limiting-loop-output-with-label
	LoopControl map[string]any `yaml:"loop_control,omitempty"`

	// Importing Playbooks
	// see https://docs.ansible.com/projects/ansible/2.9/user_guide/playbooks_reuse_includes.html
	ImportPlaybook string `yaml:"import_playbook,omitempty"`

	// Include Playbooks
	// see https://docs.ansible.com/projects/ansible/2.9/user_guide/playbooks_reuse_includes.html
	IncludePlaybook string `yaml:"include_playbook,omitempty"`

	// Import statements are pre-processed at the time playbooks are parsed
	// see https://docs.ansible.com/projects/ansible/2.9/user_guide/playbooks_reuse_includes.html
	ImportTasks string `yaml:"import_tasks,omitempty"`

	// Include statements are processed at the time the play is executed
	// see https://docs.ansible.com/projects/ansible/2.9/user_guide/playbooks_reuse_includes.html
	IncludeTasks string `yaml:"include_tasks,omitempty"`

	// Task grouping with blocks
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_blocks.html
	Block []*Task `yaml:"block,omitempty"`

	// Handle error in block
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_blocks.html
	Rescue []*Task `yaml:"rescue,omitempty"`

	// Always runs regardless of the results of the block
	// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_blocks.html
	Always []*Task `yaml:"always,omitempty"`
}

// Handler is a task that only runs when notified
// see https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_handlers.html
type Handler struct {
	// Name is the name of the handler
	Name string `yaml:"name,omitempty"`
	// Action is the module to be executed
	Action map[string]any `yaml:",inline"` // Use inline to handle dynamic handler modules
}

func DecodeTasks(data []byte) (Tasks, error) {
	var tasks Tasks
	err := yaml.Unmarshal(data, &tasks)
	if err != nil {
		return tasks, err
	}
	return tasks, nil
}

// compact returns xs without its nil elements, reusing the backing array when
// there is nothing to drop.
//
// A YAML sequence entry that is null — a bare `-`, `- ~`, or `- null` — decodes
// to a nil pointer. That happens for real whenever a play or task is commented
// out and its leading dash is left behind. Nothing downstream nil-checks these
// elements, so a single stray dash would otherwise panic the resource layer and
// take the whole scan with it (blocks run in executor goroutines, so the panic
// is not recoverable per-query).
func compact[T any](xs []*T) []*T {
	keep := xs[:0]
	for _, x := range xs {
		if x != nil {
			keep = append(keep, x)
		}
	}
	return keep
}

// compactTasks drops nil entries from a task list and from every nested
// block/rescue/always list, which are reached through the same accessors.
func compactTasks(tasks []*Task) []*Task {
	tasks = compact(tasks)
	for _, t := range tasks {
		t.Block = compactTasks(t.Block)
		t.Rescue = compactTasks(t.Rescue)
		t.Always = compactTasks(t.Always)
	}
	return tasks
}

func DecodePlaybook(data []byte) (Playbook, error) {
	var playbook Playbook
	err := yaml.Unmarshal(data, &playbook)
	if err != nil {
		return nil, err
	}

	playbook = compact(playbook)
	for _, p := range playbook {
		p.PreTasks = compactTasks(p.PreTasks)
		p.Tasks = compactTasks(p.Tasks)
		p.PostTasks = compactTasks(p.PostTasks)
		p.Handlers = compact(p.Handlers)
	}
	return playbook, nil
}

// DecodeTaskList decodes a bare YAML list of tasks, the shape used by a role's
// tasks/main.yml and by files referenced through import_tasks / include_tasks.
func DecodeTaskList(data []byte) ([]*Task, error) {
	var tasks []*Task
	if err := yaml.Unmarshal(data, &tasks); err != nil {
		return nil, err
	}
	return compactTasks(tasks), nil
}

// DecodeHandlerList decodes a bare YAML list of handlers, the shape used by a
// role's handlers/main.yml.
func DecodeHandlerList(data []byte) ([]*Handler, error) {
	var handlers []*Handler
	if err := yaml.Unmarshal(data, &handlers); err != nil {
		return nil, err
	}
	return compact(handlers), nil
}

// RoleApplication is a single role applied by a play, including the directives
// (when, tags, vars) supplied at the application site.
type RoleApplication struct {
	Name string
	When string
	Tags []string
	Vars map[string]any
}

// roleApplicationDirectives are the keys of a role mapping that are application
// directives rather than role parameters. Everything else becomes a role var.
var roleApplicationDirectives = map[string]bool{
	"role": true, "name": true, "when": true, "tags": true, "vars": true,
	"become": true, "become_user": true, "become_method": true, "become_flags": true,
	"delegate_to": true,
}

// RoleApplications normalizes the play's roles into role applications. A bare
// string is the role name; a mapping carries the name (under `role` or `name`)
// plus its directives and parameters.
func (p *Play) RoleApplications() []RoleApplication {
	apps := make([]RoleApplication, 0, len(p.Roles))
	for _, entry := range p.Roles {
		switch v := entry.(type) {
		case string:
			apps = append(apps, RoleApplication{Name: v})
		case map[string]any:
			app := RoleApplication{
				Name: roleEntryName(v),
				When: stringifyCondition(v["when"]),
				Tags: anyToStringSlice(v["tags"]),
				Vars: roleEntryVars(v),
			}
			apps = append(apps, app)
		}
	}
	return apps
}

// RoleNames returns just the role names a play applies, preserving order.
func (p *Play) RoleNames() []string {
	apps := p.RoleApplications()
	names := make([]string, 0, len(apps))
	for _, a := range apps {
		names = append(names, a.Name)
	}
	return names
}

func roleEntryName(m map[string]any) string {
	if r, ok := m["role"].(string); ok {
		return r
	}
	if n, ok := m["name"].(string); ok {
		return n
	}
	return ""
}

func roleEntryVars(m map[string]any) map[string]any {
	vars := map[string]any{}
	if explicit, ok := m["vars"].(map[string]any); ok {
		maps.Copy(vars, explicit)
	}
	for k, v := range m {
		if !roleApplicationDirectives[k] {
			vars[k] = v
		}
	}
	if len(vars) == 0 {
		return nil
	}
	return vars
}

// Module returns the module a task invokes — the action key as written in the
// source (for example `ansible.builtin.copy` or `command`), or "" when the task
// is a pure control-flow construct (block, include, etc.).
func (t *Task) Module() string {
	if act, ok := t.Action["action"].(string); ok {
		if fields := strings.Fields(act); len(fields) > 0 {
			return fields[0]
		}
	}
	keys := make([]string, 0, len(t.Action))
	for k := range t.Action {
		if !taskInlineDirectives[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys) // deterministic when more than one non-directive key
	return keys[0]
}

// ModuleArgs returns the arguments passed to the task's module: the mapping
// under the module key, or the free-form argument string for the `action:`
// shorthand. Returns nil when there is no module.
func (t *Task) ModuleArgs() any {
	if act, ok := t.Action["action"].(string); ok {
		if fields := strings.Fields(act); len(fields) > 1 {
			return strings.Join(fields[1:], " ")
		}
		return nil
	}
	name := t.Module()
	if name == "" {
		return nil
	}
	return t.Action[name]
}

// taskInlineDirectives are inline action-map keys that are task directives
// rather than the module itself. Most directives are explicit struct fields;
// these are the ones Ansible accepts inline that are not.
var taskInlineDirectives = map[string]bool{
	"action": true, "args": true, "local_action": true,
	"with_items": true, "until": true, "retries": true, "delay": true,
	"check_mode": true, "diff": true, "throttle": true, "timeout": true,
	"poll": true, "async": true,
}

func stringifyCondition(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, item := range c {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " and ")
	}
	return ""
}

func anyToStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

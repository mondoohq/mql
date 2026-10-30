// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ansible/connection"
)

func newTestRuntime(t *testing.T, yaml string) *plugin.Runtime {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "playbook.yml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
	conn, err := connection.NewAnsibleConnection(1, asset, &inventory.Config{})
	require.NoError(t, err)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

// Two plays with identical names used to collide on `__id = name`, causing the
// second play's MQL resource to silently reuse the first's state.
func TestPlayIDsUnique_SameName(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: same
  hosts: a
  tasks:
    - name: do-thing
      ping:
- name: same
  hosts: b
  tasks:
    - name: do-thing
      ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 2)

	p0 := plays[0].(*mqlAnsiblePlay)
	p1 := plays[1].(*mqlAnsiblePlay)
	assert.NotEqual(t, p0.MqlID(), p1.MqlID(), "two plays with same name must have distinct __ids")
	assert.Equal(t, "play[0]", p0.MqlID())
	assert.Equal(t, "play[1]", p1.MqlID())

	// hosts must come from the correct play
	assert.Equal(t, "a", p0.Hosts.Data)
	assert.Equal(t, "b", p1.Hosts.Data)
}

// Two unnamed plays used to both get `__id = ""` and collide.
func TestPlayIDsUnique_Unnamed(t *testing.T) {
	rt := newTestRuntime(t, `---
- hosts: a
  tasks:
    - ping:
- hosts: b
  tasks:
    - ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 2)
	p0 := plays[0].(*mqlAnsiblePlay)
	p1 := plays[1].(*mqlAnsiblePlay)
	assert.NotEqual(t, p0.MqlID(), p1.MqlID())
	assert.Equal(t, "a", p0.Hosts.Data)
	assert.Equal(t, "b", p1.Hosts.Data)
}

// Same-named tasks across plays used to collide because the id prefix was
// global ("tasks") and a non-empty name replaced the prefix entirely.
func TestTaskIDsUnique_SameNameAcrossPlays(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: play-a
  hosts: a
  tasks:
    - name: do-thing
      ping:
- name: play-b
  hosts: b
  tasks:
    - name: do-thing
      ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 2)

	tasks0, err := plays[0].(*mqlAnsiblePlay).tasks()
	require.NoError(t, err)
	tasks1, err := plays[1].(*mqlAnsiblePlay).tasks()
	require.NoError(t, err)
	require.Len(t, tasks0, 1)
	require.Len(t, tasks1, 1)

	t0 := tasks0[0].(*mqlAnsibleTask)
	t1 := tasks1[0].(*mqlAnsibleTask)
	assert.NotEqual(t, t0.MqlID(), t1.MqlID(), "same-named tasks in different plays must have distinct __ids")
	// task ids must be nested under the parent play id
	assert.Contains(t, t0.MqlID(), "play[0]")
	assert.Contains(t, t1.MqlID(), "play[1]")
	// and the internal task pointers must match their respective parents
	assert.NotSame(t, t0.task, t1.task)
}

// Task group prefixes (preTasks, tasks, postTasks) used to share id space across
// plays — also recursive groups (block/rescue/always) used to be flat.
func TestTaskIDsUnique_NestedGroups(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: only
  hosts: a
  pre_tasks:
    - name: setup
      ping:
  tasks:
    - name: setup
      block:
        - name: setup
          ping:
        - name: setup
          ping:
      rescue:
        - name: setup
          ping:
      always:
        - name: setup
          ping:
  post_tasks:
    - name: setup
      ping:
  handlers:
    - name: setup
      ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)

	p := plays[0].(*mqlAnsiblePlay)
	pre, err := p.preTasks()
	require.NoError(t, err)
	tasks, err := p.tasks()
	require.NoError(t, err)
	post, err := p.postTasks()
	require.NoError(t, err)
	handlers, err := p.handlers()
	require.NoError(t, err)

	require.Len(t, pre, 1)
	require.Len(t, tasks, 1)
	require.Len(t, post, 1)
	require.Len(t, handlers, 1)

	tasksParent := tasks[0].(*mqlAnsibleTask)
	block, err := tasksParent.block()
	require.NoError(t, err)
	rescue, err := tasksParent.rescue()
	require.NoError(t, err)
	always, err := tasksParent.always()
	require.NoError(t, err)
	require.Len(t, block, 2)
	require.Len(t, rescue, 1)
	require.Len(t, always, 1)

	// Every id observed in this play must be globally unique even though every
	// task is named "setup".
	ids := map[string]string{}
	collect := func(label, id string) {
		t.Helper()
		if prev, ok := ids[id]; ok {
			t.Fatalf("id collision: %q used by %s and %s", id, prev, label)
		}
		ids[id] = label
	}
	collect("play", p.MqlID())
	collect("preTasks[0]", pre[0].(*mqlAnsibleTask).MqlID())
	collect("tasks[0]", tasksParent.MqlID())
	collect("postTasks[0]", post[0].(*mqlAnsibleTask).MqlID())
	collect("handlers[0]", handlers[0].(*mqlAnsibleHandler).MqlID())
	collect("block[0]", block[0].(*mqlAnsibleTask).MqlID())
	collect("block[1]", block[1].(*mqlAnsibleTask).MqlID())
	collect("rescue[0]", rescue[0].(*mqlAnsibleTask).MqlID())
	collect("always[0]", always[0].(*mqlAnsibleTask).MqlID())
}

// Calling a child accessor twice on the same play must return resources whose
// MqlIDs match — proving the cache works correctly with the new id scheme.
func TestTaskIDsStable_AcrossCalls(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: p
  hosts: a
  tasks:
    - name: t
      ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)
	p := plays[0].(*mqlAnsiblePlay)

	first, err := p.tasks()
	require.NoError(t, err)
	second, err := p.tasks()
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Same(t, first[0], second[0], "repeated tasks() calls must return the cached resource")
}

// Serial was parsed by the YAML decoder but never exposed. Make sure the field
// is now populated on the MQL resource.
func TestSerialIsExposed(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: p
  hosts: a
  serial: 3
  tasks:
    - ping:
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)
	assert.Equal(t, int64(3), plays[0].(*mqlAnsiblePlay).Serial.Data)
}

// Task-level security attributes (become family, no_log, ignore_errors,
// delegate_to, run_once, environment) must decode and be exposed on the MQL
// resource. The polymorphic dict fields must accept a Jinja2 templated string
// without breaking playbook parsing.
func TestTaskSecurityAttributesExposed(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: p
  hosts: a
  tasks:
    - name: privileged
      command: /usr/bin/rotate-secrets
      become: true
      become_user: root
      become_method: sudo
      become_flags: "-H -S -n"
      delegate_to: localhost
      no_log: true
      run_once: true
      environment:
        HTTP_PROXY: http://proxy.example.com:8080
    - name: templated
      command: /usr/bin/maybe-fails
      ignore_errors: "{{ ansible_check_mode }}"
`)
	a := &mqlAnsible{MqlRuntime: rt}
	plays, err := a.plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)

	tasks, err := plays[0].(*mqlAnsiblePlay).tasks()
	require.NoError(t, err)
	require.Len(t, tasks, 2)

	priv := tasks[0].(*mqlAnsibleTask)
	assert.Equal(t, true, priv.Become.Data)
	assert.Equal(t, "root", priv.BecomeUser.Data)
	assert.Equal(t, "sudo", priv.BecomeMethod.Data)
	assert.Equal(t, "-H -S -n", priv.BecomeFlags.Data)
	assert.Equal(t, "localhost", priv.DelegateTo.Data)
	assert.Equal(t, true, priv.NoLog.Data)
	assert.Equal(t, true, priv.RunOnce.Data)
	assert.Equal(t, "http://proxy.example.com:8080", priv.Environment.Data["HTTP_PROXY"])

	// A Jinja2 templated ignore_errors must be exposed as the raw string, not
	// fail to parse.
	templated := tasks[1].(*mqlAnsibleTask)
	assert.Equal(t, "{{ ansible_check_mode }}", templated.IgnoreErrors.Data)
}

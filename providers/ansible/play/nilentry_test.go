// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package play

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A YAML sequence entry that is null decodes to a nil element. It happens for
// real whenever a play or task is commented out and the leading `-` is left
// behind. The decoders are the single choke point every consumer goes through,
// so they must never hand back a nil the resource layer would dereference.
func TestDecodePlaybookDropsNilPlays(t *testing.T) {
	pb, err := DecodePlaybook([]byte(`
- hosts: web
  tasks:
    - ping:

# temporarily disabled
-
- ~
- null
`))
	require.NoError(t, err)
	require.Len(t, pb, 1, "the three null entries must be dropped")
	for i, p := range pb {
		require.NotNil(t, p, "play[%d] must not be nil", i)
	}
	assert.Equal(t, "web", pb[0].Hosts)
}

func TestDecodeTaskListDropsNilTasks(t *testing.T) {
	tasks, err := DecodeTaskList([]byte(`
- name: real
  ping:
-
- ~
`))
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	require.NotNil(t, tasks[0])
	assert.Equal(t, "real", tasks[0].Name)
}

func TestDecodeHandlerListDropsNilHandlers(t *testing.T) {
	handlers, err := DecodeHandlerList([]byte(`
- name: restart nginx
  service:
    name: nginx
    state: restarted
-
`))
	require.NoError(t, err)
	require.Len(t, handlers, 1)
	require.NotNil(t, handlers[0])
	assert.Equal(t, "restart nginx", handlers[0].Name)
}

// A null entry can also sit inside a play's task lists or inside a block, and
// those are reached through the same accessors, so they need the same guard.
func TestDecodePlaybookDropsNilNestedEntries(t *testing.T) {
	pb, err := DecodePlaybook([]byte(`
- hosts: web
  pre_tasks:
    - name: pre
      ping:
    -
  tasks:
    - name: outer
      block:
        - name: inner
          ping:
        -
      rescue:
        -
        - name: recover
          ping:
      always:
        -
    -
  post_tasks:
    -
    - name: post
      ping:
  handlers:
    -
    - name: h
      ping:
`))
	require.NoError(t, err)
	require.Len(t, pb, 1)
	p := pb[0]

	require.Len(t, p.PreTasks, 1)
	require.NotNil(t, p.PreTasks[0])
	assert.Equal(t, "pre", p.PreTasks[0].Name)

	require.Len(t, p.Tasks, 1)
	outer := p.Tasks[0]
	require.NotNil(t, outer)

	require.Len(t, outer.Block, 1)
	require.NotNil(t, outer.Block[0])
	assert.Equal(t, "inner", outer.Block[0].Name)

	require.Len(t, outer.Rescue, 1)
	require.NotNil(t, outer.Rescue[0])
	assert.Equal(t, "recover", outer.Rescue[0].Name)

	assert.Empty(t, outer.Always, "a block of only null entries collapses to empty")

	require.Len(t, p.PostTasks, 1)
	require.NotNil(t, p.PostTasks[0])
	assert.Equal(t, "post", p.PostTasks[0].Name)

	require.Len(t, p.Handlers, 1)
	require.NotNil(t, p.Handlers[0])
	assert.Equal(t, "h", p.Handlers[0].Name)
}

// A file that is entirely null entries is a valid (if useless) playbook and
// must decode to an empty list rather than a list of nils.
func TestDecodePlaybookAllNullEntries(t *testing.T) {
	pb, err := DecodePlaybook([]byte("-\n-\n"))
	require.NoError(t, err)
	assert.Empty(t, pb)
}

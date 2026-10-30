// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// A playbook whose leading `-` is left behind after a play is commented out
// decodes to a nil *Play. Nothing downstream nil-checked it, so reading any
// field panicked — and because the executor runs blocks in goroutines, that
// killed the entire scan rather than failing one query.
func TestPlaysSkipNullPlaybookEntries(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: real
  hosts: web
  tasks:
    - name: do-thing
      ping:

# temporarily disabled
-
`)
	a, err := CreateResource(rt, "ansible", map[string]*llx.RawData{})
	require.NoError(t, err)

	plays, err := a.(*mqlAnsible).plays()
	require.NoError(t, err)
	require.Len(t, plays, 1, "the null entry must not become a play")

	assert.Equal(t, "real", plays[0].(*mqlAnsiblePlay).Name.Data)
}

// The same hazard inside a play's task list, reached through the tasks
// accessor rather than the plays accessor.
func TestTasksSkipNullEntries(t *testing.T) {
	rt := newTestRuntime(t, `---
- name: real
  hosts: web
  tasks:
    - name: do-thing
      ping:
    -
    - name: other-thing
      ping:
`)
	a, err := CreateResource(rt, "ansible", map[string]*llx.RawData{})
	require.NoError(t, err)

	plays, err := a.(*mqlAnsible).plays()
	require.NoError(t, err)
	require.Len(t, plays, 1)

	tasks, err := plays[0].(*mqlAnsiblePlay).tasks()
	require.NoError(t, err)
	require.Len(t, tasks, 2, "the null entry must not become a task")

	assert.Equal(t, "do-thing", tasks[0].(*mqlAnsibleTask).Name.Data)
	assert.Equal(t, "other-thing", tasks[1].(*mqlAnsibleTask).Name.Data)
}

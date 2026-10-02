// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTaskList(t *testing.T) {
	taskOutput := `TASK                                                                PID        STATUS
a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919    3440258    RUNNING
98deb1bb7adca2cce91ae97270238814436c4de3b8b15da64922bea1948f8671    3440318    RUNNING`

	taskInfo := parseTaskList(taskOutput)

	require.Len(t, taskInfo, 2)

	// Check first task
	task1, exists := taskInfo["a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919"]
	require.True(t, exists)
	assert.Equal(t, int64(3440258), task1.pid)
	assert.Equal(t, "RUNNING", task1.status)

	// Check second task
	task2, exists := taskInfo["98deb1bb7adca2cce91ae97270238814436c4de3b8b15da64922bea1948f8671"]
	require.True(t, exists)
	assert.Equal(t, int64(3440318), task2.pid)
	assert.Equal(t, "RUNNING", task2.status)
}

func TestParseTaskListEmpty(t *testing.T) {
	// Only header, no tasks
	taskOutput := `TASK    PID    STATUS`
	taskInfo := parseTaskList(taskOutput)
	assert.Empty(t, taskInfo)
}

func TestParseTaskListMalformed(t *testing.T) {
	// Lines with insufficient fields should be skipped
	taskOutput := `TASK                                                                PID        STATUS
container1    12345    RUNNING
container2    incomplete`

	taskInfo := parseTaskList(taskOutput)

	require.Len(t, taskInfo, 1)

	// Only first task should be parsed
	task1, exists := taskInfo["container1"]
	require.True(t, exists)
	assert.Equal(t, int64(12345), task1.pid)
	assert.Equal(t, "RUNNING", task1.status)

	// Second task should not exist
	_, exists = taskInfo["container2"]
	assert.False(t, exists)
}

func TestParseTaskListWithPausedStatus(t *testing.T) {
	taskOutput := `TASK          PID     STATUS
container1    12345   RUNNING
container2    67890   PAUSED
container3    11111   STOPPED`

	taskInfo := parseTaskList(taskOutput)

	require.Len(t, taskInfo, 3)

	assert.Equal(t, "RUNNING", taskInfo["container1"].status)
	assert.Equal(t, "PAUSED", taskInfo["container2"].status)
	assert.Equal(t, "STOPPED", taskInfo["container3"].status)
}

func TestParseContainerInfo(t *testing.T) {
	// Actual output from ctr -n moby containers info
	jsonOutput := `{
    "ID": "a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919",
    "Labels": {
        "com.docker/engine.bundle.path": "/var/run/docker/containerd/a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919"
    },
    "Image": "",
    "Runtime": {
        "Name": "io.containerd.runc.v2",
        "Options": {
            "type_url": "containerd.runc.v1.Options",
            "value": "MgRydW5jOhwvdmFyL3J1bi9kb2NrZXIvcnVudGltZS1ydW5jSAE="
        }
    },
    "SnapshotKey": "",
    "Snapshotter": "",
    "CreatedAt": "2026-01-16T18:04:53.753134751Z",
    "UpdatedAt": "2026-01-16T18:04:53.753134751Z"
}`

	info, err := parseContainerInfo([]byte(jsonOutput))
	require.NoError(t, err)

	assert.Equal(t, "a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919", info.ID)
	assert.Equal(t, "", info.Image)
	assert.Equal(t, "io.containerd.runc.v2", info.Runtime.Name)
	assert.Equal(t, "", info.Snapshotter)

	require.NotNil(t, info.Labels)
	assert.Equal(t, "/var/run/docker/containerd/a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919",
		info.Labels["com.docker/engine.bundle.path"])
}

func TestParseContainerInfoWithSnapshotter(t *testing.T) {
	// Container with image and snapshotter info
	jsonOutput := `{
    "ID": "test-container",
    "Labels": {
        "app": "web",
        "env": "prod"
    },
    "Image": "docker.io/library/nginx:latest",
    "Runtime": {
        "Name": "io.containerd.runc.v2"
    },
    "Snapshotter": "overlayfs"
}`

	info, err := parseContainerInfo([]byte(jsonOutput))
	require.NoError(t, err)

	assert.Equal(t, "test-container", info.ID)
	assert.Equal(t, "docker.io/library/nginx:latest", info.Image)
	assert.Equal(t, "io.containerd.runc.v2", info.Runtime.Name)
	assert.Equal(t, "overlayfs", info.Snapshotter)
	assert.Len(t, info.Labels, 2)
	assert.Equal(t, "web", info.Labels["app"])
	assert.Equal(t, "prod", info.Labels["env"])
}

func TestParseContainerInfoInvalidJSON(t *testing.T) {
	jsonOutput := `{invalid json}`

	_, err := parseContainerInfo([]byte(jsonOutput))
	assert.Error(t, err)
}

func TestParseNamespaceList(t *testing.T) {
	output := "moby\nk8s.io\ndefault"
	namespaces := parseNamespaceList(output)

	assert.Equal(t, []string{"moby", "k8s.io", "default"}, namespaces)
}

func TestParseNamespaceListSingle(t *testing.T) {
	output := "moby"
	namespaces := parseNamespaceList(output)

	assert.Equal(t, []string{"moby"}, namespaces)
}

func TestParseNamespaceListWithEmptyLines(t *testing.T) {
	output := "moby\n\nk8s.io\n"
	namespaces := parseNamespaceList(output)

	// Empty lines should be filtered out
	assert.Equal(t, []string{"moby", "k8s.io"}, namespaces)
}

func TestParseContainerIDList(t *testing.T) {
	output := `98deb1bb7adca2cce91ae97270238814436c4de3b8b15da64922bea1948f8671
a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919`

	containerIDs := parseContainerIDList(output)

	assert.Equal(t, []string{
		"98deb1bb7adca2cce91ae97270238814436c4de3b8b15da64922bea1948f8671",
		"a5e26880c8937d5d0ee37ffc9c3e3605448ff11a6eab018162beac0be6e66919",
	}, containerIDs)
}

func TestParseContainerIDListSingle(t *testing.T) {
	output := "container1"
	containerIDs := parseContainerIDList(output)

	assert.Equal(t, []string{"container1"}, containerIDs)
}

func TestParseContainerIDListWithEmptyLines(t *testing.T) {
	output := "container1\n\ncontainer2\n"
	containerIDs := parseContainerIDList(output)

	// Empty lines should be filtered out
	assert.Equal(t, []string{"container1", "container2"}, containerIDs)
}

func TestCtrCommand(t *testing.T) {
	clis := ctrCLIs(nil)
	assert.Equal(t, "ctr -n g08ns tasks list", ctrCommand(clis[0], "-n", "g08ns", "tasks", "list"))
	// SUSE's containerd-ctr package, on root's PATH and off a non-root one
	assert.Equal(t, []string{"containerd-ctr"}, clis[1])
	assert.Equal(t, []string{"/usr/sbin/containerd-ctr"}, clis[2])

	// Debian 10's docker.io 18.09 bundles containerd as docker-containerd, which
	// does not listen on the containerd default socket
	clis = ctrCLIs([]string{"--address", dockerContainerdSocket})
	assert.Equal(t,
		"docker-containerd-ctr --address /run/docker/containerd/containerd.sock -n g08ns containers info c-run",
		ctrCommand(clis[3], "-n", "g08ns", "containers", "info", "c-run"))
	// building a command line leaves the CLI untouched for the next call
	assert.Equal(t, []string{"docker-containerd-ctr", "--address", "/run/docker/containerd/containerd.sock"}, clis[3])
}

func TestContainerdAddressArgs(t *testing.T) {
	statFrom := func(results map[string]error) func(string) error {
		return func(path string) error {
			if err, ok := results[path]; ok {
				return err
			}
			return fs.ErrNotExist
		}
	}
	dockerAddress := []string{"--address", "/run/docker/containerd/containerd.sock"}

	// Ubuntu/Debian/RHEL: a standalone containerd serves the default socket,
	// whether or not dockerd also runs (it then uses that containerd)
	assert.Nil(t, containerdAddressArgs(statFrom(map[string]error{
		containerdSocket: nil,
	})))
	assert.Nil(t, containerdAddressArgs(statFrom(map[string]error{
		containerdSocket:       nil,
		dockerContainerdSocket: nil,
	})))
	// the default socket exists but its directory refuses this user: ctr
	// reports that refusal
	assert.Nil(t, containerdAddressArgs(statFrom(map[string]error{
		containerdSocket: fs.ErrPermission,
	})))

	// SLES and Leap with docker: containerd.service conflicts with
	// docker.service, so dockerd runs its own containerd
	assert.Equal(t, dockerAddress, containerdAddressArgs(statFrom(map[string]error{
		dockerContainerdSocket: nil,
	})))
	// the same host as ec2-user: /run/containerd is 0711 so the missing default
	// socket shows, while /run/docker is 0700 and refuses the stat
	assert.Equal(t, dockerAddress, containerdAddressArgs(statFrom(map[string]error{
		dockerContainerdSocket: fs.ErrPermission,
	})))

	// no containerd runs at all: ctr reports the default socket
	assert.Nil(t, containerdAddressArgs(statFrom(nil)))
}

func TestContainerdTaskState(t *testing.T) {
	// captured from "docker-containerd-ctr -n g08ns tasks list" on Debian 10
	// (docker.io 18.09), before and after "ctr tasks pause c-run"
	running := parseTaskList("TASK         PID      STATUS    \n" +
		"c-run        12308    RUNNING\n" +
		"c-stopped    12374    STOPPED\n")
	paused := parseTaskList("TASK         PID      STATUS    \n" +
		"c-run        12308    PAUSED\n" +
		"c-stopped    12374    STOPPED\n")

	task, ok := running["c-run"]
	status, pid := containerdTaskState(task, ok)
	assert.Equal(t, "running", status)
	assert.Equal(t, int64(12308), pid)

	task, ok = running["c-stopped"]
	status, pid = containerdTaskState(task, ok)
	assert.Equal(t, "stopped", status)
	assert.Equal(t, int64(0), pid, "a stopped task's process has exited")

	task, ok = paused["c-run"]
	status, pid = containerdTaskState(task, ok)
	assert.Equal(t, "paused", status)
	assert.Equal(t, int64(12308), pid, "a paused task's process still exists")

	// c-created has a container but no task
	task, ok = running["c-created"]
	status, pid = containerdTaskState(task, ok)
	assert.Equal(t, "created", status)
	assert.Equal(t, int64(0), pid)
}

func TestIsCtrNotInstalled(t *testing.T) {
	// "ctr namespaces list -q" on Debian 10 (docker.io 18.09 only), locally and
	// over SSH with sudo
	assert.True(t, isCtrNotInstalled("ctr", 127, "sh: 1: ctr: not found\n"))
	assert.True(t, isCtrNotInstalled("ctr", 1, "sudo: ctr: command not found\n"))
	// SLES 16 and Leap 16 without ctr, and the absolute containerd-ctr path on a
	// SLES 15 host without the containerd-ctr package, locally and with sudo
	assert.True(t, isCtrNotInstalled("ctr", 127, "sh: line 1: ctr: command not found\n"))
	assert.True(t, isCtrNotInstalled("/usr/sbin/containerd-ctr", 127, "sh: /usr/sbin/containerd-ctr: No such file or directory\n"))
	assert.True(t, isCtrNotInstalled("/usr/sbin/containerd-ctr", 1, "sudo: /usr/sbin/containerd-ctr: command not found\n"))

	// containerd is installed but refuses a non-root user (Debian 12)
	assert.False(t, isCtrNotInstalled("ctr", 1, `ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"`+"\n"))
	// the bundled containerd refuses a non-root user (Debian 10)
	assert.False(t, isCtrNotInstalled("docker-containerd-ctr", 1, `ctr: failed to dial "/run/docker/containerd/containerd.sock": context deadline exceeded`+"\n"))
}

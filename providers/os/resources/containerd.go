// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// containerInfo represents the parsed JSON output from ctr containers info
type containerInfo struct {
	ID      string `json:"ID"`
	Image   string `json:"Image"`
	Runtime struct {
		Name string `json:"Name"`
	} `json:"Runtime"`
	Snapshotter string            `json:"Snapshotter"`
	Labels      map[string]string `json:"Labels"`
}

// taskData holds information about a containerd task
type taskData struct {
	pid    int64
	status string
}

// parseNamespaceList parses the output of "ctr namespaces list -q"
func parseNamespaceList(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var namespaces []string
	for _, line := range lines {
		if line != "" {
			namespaces = append(namespaces, line)
		}
	}
	return namespaces
}

// parseContainerIDList parses the output of "ctr -n <ns> containers list -q"
func parseContainerIDList(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var containerIDs []string
	for _, line := range lines {
		if line != "" {
			containerIDs = append(containerIDs, line)
		}
	}
	return containerIDs
}

// parseTaskList parses the output of "ctr -n <ns> tasks list"
// Format: TASK    PID    STATUS
func parseTaskList(output string) map[string]taskData {
	taskInfo := make(map[string]taskData)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			taskID := fields[0]
			pid, _ := strconv.ParseInt(fields[1], 10, 64)
			status := fields[2]
			taskInfo[taskID] = taskData{pid, status}
		}
	}
	return taskInfo
}

// parseContainerInfo parses the JSON output from "ctr -n <ns> containers info <id>"
func parseContainerInfo(jsonData []byte) (*containerInfo, error) {
	var info containerInfo
	if err := json.Unmarshal(jsonData, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// ctrCLIs are the containerd command lines to try, in order. Docker 18.09 and
// older bundle their own containerd under docker-prefixed names, serving its
// socket from docker's run directory instead of the containerd default.
var ctrCLIs = [][]string{
	{"ctr"},
	{"docker-containerd-ctr", "--address", "/run/docker/containerd/containerd.sock"},
}

// ctrCommand builds the command line that runs ctr with the given arguments.
func ctrCommand(cli []string, args ...string) string {
	return shellquote.Join(append(append([]string{}, cli...), args...)...)
}

// containerdTaskState returns the status and pid of a container from its task.
// A container without a task was created but never started. A stopped task
// keeps the pid of its exited process, which is no process anymore.
func containerdTaskState(task taskData, ok bool) (string, int64) {
	if !ok {
		return "created", 0
	}
	status := strings.ToLower(task.status)
	switch status {
	case "running", "paused", "pausing":
		return status, task.pid
	default:
		return status, 0
	}
}

// listContainerdNamespaces lists the containerd namespaces with the first ctr
// CLI that is installed, and returns that CLI for every later call.
func (p *mqlContainerd) listContainerdNamespaces() ([]string, []string, error) {
	var firstErr error
	for _, cli := range ctrCLIs {
		o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(ctrCommand(cli, "namespaces", "list", "-q")),
		})
		if err != nil {
			return nil, nil, err
		}
		cmd := o.(*mqlCommand)
		exit := cmd.GetExitcode()
		if exit.Error != nil {
			return nil, nil, exit.Error
		}
		if exit.Data == 0 {
			return cli, parseNamespaceList(cmd.Stdout.Data), nil
		}
		listErr := errors.New("failed to list namespaces: " + cmd.Stderr.Data)
		if !isCtrNotInstalled(cli[0], exit.Data, cmd.Stderr.Data) {
			return nil, nil, listErr
		}
		if firstErr == nil {
			firstErr = listErr
		}
	}
	return nil, nil, firstErr
}

// isCtrNotInstalled reports whether a ctr call failed because the binary is
// missing, rather than because containerd refused or is down. Shells exit with
// 127 for a command they cannot find, but sudo exits with 1 and says so on
// stderr.
func isCtrNotInstalled(bin string, exitCode int64, stderr string) bool {
	if exitCode == 127 {
		return true
	}
	return strings.Contains(stderr, bin+": command not found") ||
		strings.Contains(stderr, bin+": not found")
}

func (p *mqlContainerd) containers() ([]any, error) {
	ctr, namespaces, err := p.listContainerdNamespaces()
	if err != nil {
		return nil, err
	}
	var containers []any

	for _, ns := range namespaces {
		if ns == "" {
			continue
		}

		// List containers in namespace
		o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(ctrCommand(ctr, "-n", ns, "containers", "list", "-q")),
		})
		if err != nil {
			log.Debug().Str("namespace", ns).Err(err).Msg("skipping namespace, failed to create command")
			continue
		}
		cmd := o.(*mqlCommand)
		if exit := cmd.GetExitcode(); exit.Data != 0 {
			log.Debug().Str("namespace", ns).Str("stderr", cmd.Stderr.Data).Msg("skipping namespace, failed to list containers")
			continue
		}

		containerIDs := parseContainerIDList(cmd.Stdout.Data)

		// Get tasks info for this namespace to map PIDs and status
		var taskInfo map[string]taskData

		o, err = CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(ctrCommand(ctr, "-n", ns, "tasks", "list")),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			if exit := cmd.GetExitcode(); exit.Data == 0 {
				taskInfo = parseTaskList(cmd.Stdout.Data)
			}
		}

		for _, containerID := range containerIDs {
			if containerID == "" {
				continue
			}

			// Get container info as JSON
			o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
				"command": llx.StringData(ctrCommand(ctr, "-n", ns, "containers", "info", containerID)),
			})
			if err != nil {
				log.Debug().Str("namespace", ns).Str("container", containerID).Err(err).Msg("skipping container, failed to create command")
				continue
			}
			cmd := o.(*mqlCommand)
			if exit := cmd.GetExitcode(); exit.Data != 0 {
				log.Debug().Str("namespace", ns).Str("container", containerID).Str("stderr", cmd.Stderr.Data).Msg("skipping container, failed to get info")
				continue
			}

			// Parse JSON output from ctr
			info, err := parseContainerInfo([]byte(cmd.Stdout.Data))
			if err != nil {
				log.Debug().Str("namespace", ns).Str("container", containerID).Err(err).Msg("skipping container, failed to parse info")
				continue
			}

			// Convert labels to map[string]any
			labels := make(map[string]any)
			for k, v := range info.Labels {
				labels[k] = v
			}

			task, ok := taskInfo[containerID]
			status, pid := containerdTaskState(task, ok)

			// Create resource with unique ID combining namespace and container ID
			resourceID := fmt.Sprintf("%s/%s", ns, containerID)

			containerRes, err := CreateResource(p.MqlRuntime, "containerd.container", map[string]*llx.RawData{
				"__id":        llx.StringData(resourceID),
				"id":          llx.StringData(containerID),
				"image":       llx.StringData(info.Image),
				"status":      llx.StringData(status),
				"labels":      llx.MapData(labels, types.String),
				"pid":         llx.IntData(pid),
				"namespace":   llx.StringData(ns),
				"runtime":     llx.StringData(info.Runtime.Name),
				"snapshotter": llx.StringData(info.Snapshotter),
			})
			if err != nil {
				return nil, err
			}

			containers = append(containers, containerRes.(*mqlContainerdContainer))
		}
	}

	return containers, nil
}

func (p *mqlContainerdContainer) id() (string, error) {
	return p.Id.Data, nil
}

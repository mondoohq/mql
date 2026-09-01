// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

func (p *mqlContainerd) containers() ([]any, error) {
	// Get all namespaces using ctr CLI
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(shellquote.Join("ctr", "namespaces", "list", "-q")),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	stdout, err := commandOutput(cmd, "ctr namespaces list")
	if err != nil {
		return nil, err
	}

	namespaces := parseNamespaceList(stdout)
	containers := []any{}
	// incomplete records that at least one namespace or container could not be
	// read. Combined with an empty result it means "unknown", not "none".
	incomplete := false

	for _, ns := range namespaces {
		if ns == "" {
			continue
		}

		// List containers in namespace
		o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(shellquote.Join("ctr", "-n", ns, "containers", "list", "-q")),
		})
		if err != nil {
			log.Debug().Str("namespace", ns).Err(err).Msg("skipping namespace, failed to create command")
			incomplete = true
			continue
		}
		cmd := o.(*mqlCommand)
		nsRun, err := commandResult(cmd)
		if err != nil {
			return nil, err
		}
		if nsRun.exitcode != 0 {
			log.Debug().Str("namespace", ns).Str("stderr", nsRun.stderr).Msg("skipping namespace, failed to list containers")
			incomplete = true
			continue
		}

		containerIDs := parseContainerIDList(nsRun.stdout)

		// Get tasks info for this namespace to map PIDs and status
		var taskInfo map[string]taskData

		o, err = CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(shellquote.Join("ctr", "-n", ns, "tasks", "list")),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			// exitcode reads as 0 on a command that never ran; parsing that
			// would report every container as taskless.
			if taskRun, taskErr := commandResult(cmd); taskErr == nil && taskRun.exitcode == 0 {
				taskInfo = parseTaskList(taskRun.stdout)
			}
		}

		for _, containerID := range containerIDs {
			if containerID == "" {
				continue
			}

			// Get container info as JSON
			o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
				"command": llx.StringData(shellquote.Join("ctr", "-n", ns, "containers", "info", containerID)),
			})
			if err != nil {
				log.Debug().Str("namespace", ns).Str("container", containerID).Err(err).Msg("skipping container, failed to create command")
				incomplete = true
				continue
			}
			cmd := o.(*mqlCommand)
			infoRun, err := commandResult(cmd)
			if err != nil {
				return nil, err
			}
			if infoRun.exitcode != 0 {
				log.Debug().Str("namespace", ns).Str("container", containerID).Str("stderr", infoRun.stderr).Msg("skipping container, failed to get info")
				incomplete = true
				continue
			}

			// Parse JSON output from ctr
			info, err := parseContainerInfo([]byte(infoRun.stdout))
			if err != nil {
				log.Debug().Str("namespace", ns).Str("container", containerID).Err(err).Msg("skipping container, failed to parse info")
				incomplete = true
				continue
			}

			// Convert labels to map[string]any
			labels := make(map[string]any)
			for k, v := range info.Labels {
				labels[k] = v
			}

			// Get task info - default to "created" if no task exists
			status := "created"
			var pid int64
			if task, ok := taskInfo[containerID]; ok {
				status = strings.ToLower(task.status)
				pid = task.pid
			}

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

	if len(containers) == 0 && incomplete {
		// Every namespace or container we tried to read was skipped, so we
		// measured nothing. An empty list would pass
		// `containerd.containers.none(...)` on a host we never managed to
		// inspect.
		p.Containers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return containers, nil
}

func (p *mqlContainerdContainer) id() (string, error) {
	return p.Id.Data, nil
}

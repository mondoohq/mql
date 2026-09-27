// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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

func (p *mqlContainerd) containers() ([]any, error) {
	// Get all namespaces using ctr CLI
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(shellquote.Join("ctr", "namespaces", "list", "-q")),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return nil, errors.New("failed to list namespaces: " + cmd.Stderr.Data)
	}

	namespaces := parseNamespaceList(cmd.Stdout.Data)
	var containers []any

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
			"command": llx.StringData(shellquote.Join("ctr", "-n", ns, "tasks", "list")),
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
				"command": llx.StringData(shellquote.Join("ctr", "-n", ns, "containers", "info", containerID)),
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

	return containers, nil
}

func (p *mqlContainerdContainer) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlContainerd) delegate() (*mqlContainerRuntimeDelegate, error) {
	delegate, err := CreateResource(p.MqlRuntime, "container.runtimeDelegate", map[string]*llx.RawData{
		"id":            llx.StringData("containerd"),
		"kind":          llx.StringData("containerd"),
		"endpoint":      llx.StringData(""),
		"priority":      llx.IntData(0),
		"namespaces":    llx.ArrayData([]any{}, types.String),
		"snapshotters":  llx.ArrayData([]any{}, types.String),
		"readonly":      llx.BoolData(true),
		"allowPull":     llx.BoolData(false),
		"status":        llx.StringData("ready"),
		"statusMessage": llx.StringData(""),
		"lastChecked":   llx.TimeData(time.Time{}),
	})
	if err != nil {
		return nil, err
	}
	return delegate.(*mqlContainerRuntimeDelegate), nil
}

func (p *mqlContainerd) images() ([]any, error) {
	containers := p.GetContainers()
	if containers.Error != nil {
		return nil, containers.Error
	}

	type imageRef struct {
		ref        string
		namespaces map[string]struct{}
		containers []string
	}

	byRef := map[string]*imageRef{}
	for _, item := range containers.Data {
		c, ok := item.(*mqlContainerdContainer)
		if !ok {
			continue
		}
		ref := strings.TrimSpace(c.Image.Data)
		if ref == "" {
			continue
		}
		entry := byRef[ref]
		if entry == nil {
			entry = &imageRef{ref: ref, namespaces: map[string]struct{}{}}
			byRef[ref] = entry
		}
		if c.Namespace.Data != "" {
			entry.namespaces[c.Namespace.Data] = struct{}{}
		}
		if c.Id.Data != "" {
			entry.containers = append(entry.containers, c.Id.Data)
		}
	}

	out := make([]any, 0, len(byRef))
	for _, entry := range byRef {
		args := runtimeImageArgsFromReference(entry.ref)
		args["delegateId"] = llx.StringData("containerd")
		args["runtimeKind"] = llx.StringData("containerd")
		args["namespaces"] = llx.ArrayData(stringsSetToAny(entry.namespaces), types.String)
		args["containers"] = llx.ArrayData(stringsSliceToAny(entry.containers), types.String)
		args["inUse"] = llx.BoolData(len(entry.containers) > 0)
		args["scanStatus"] = llx.StringData("pending")

		img, err := CreateResource(p.MqlRuntime, "container.runtimeImage", args)
		if err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, nil
}

func (p *mqlContainerRuntimeDelegate) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlContainerRuntimeImage) id() (string, error) {
	if p.Id.Data != "" {
		return p.Id.Data, nil
	}
	if p.ResolvedDigest.Data != "" {
		return p.ResolvedDigest.Data, nil
	}
	if p.ImageId.Data != "" {
		return p.ImageId.Data, nil
	}
	if len(p.RepoDigests.Data) > 0 {
		return p.RepoDigests.Data[0].(string), nil
	}
	if len(p.RepoTags.Data) > 0 {
		return p.RepoTags.Data[0].(string), nil
	}
	return "", nil
}

func (p *mqlContainerRuntimeImageLayer) id() (string, error) {
	return p.Digest.Data, nil
}

func runtimeImageArgsFromReference(ref string) map[string]*llx.RawData {
	tags, digests := splitImageReferenceNames([]string{ref})
	resolvedDigest := ""
	if len(digests) > 0 {
		resolvedDigest = digests[0]
	}
	imageID := normalizeRuntimeImageID(ref)
	if resolvedDigest != "" {
		imageID = resolvedDigest
	}
	id := imageID
	if id == "" && len(tags) > 0 {
		id = tags[0]
	}

	return map[string]*llx.RawData{
		"id":                llx.StringData(id),
		"imageId":           llx.StringData(imageID),
		"repoTags":          llx.ArrayData(stringsSliceToAny(tags), types.String),
		"repoDigests":       llx.ArrayData(stringsSliceToAny(digests), types.String),
		"resolvedDigest":    llx.StringData(resolvedDigest),
		"targetDigest":      llx.StringData(resolvedDigest),
		"labels":            llx.MapData(map[string]any{}, types.String),
		"namespaces":        llx.ArrayData([]any{}, types.String),
		"containers":        llx.ArrayData([]any{}, types.String),
		"scanStatusMessage": llx.StringData(""),
		"layers":            llx.ArrayData([]any{}, types.Resource("container.runtimeImageLayer")),
		"created":           llx.TimeData(time.Time{}),
	}
}

func splitImageReferenceNames(names []string) ([]string, []string) {
	tags := []string{}
	digests := []string{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if strings.Contains(name, "@sha256:") || strings.HasPrefix(name, "sha256:") {
			digests = append(digests, normalizeRuntimeImageID(name))
			continue
		}
		tags = append(tags, name)
	}
	return tags, digests
}

func normalizeRuntimeImageID(imageID string) string {
	imageID = strings.TrimSpace(imageID)
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	imageID = strings.TrimPrefix(imageID, "docker://")
	imageID = strings.TrimPrefix(imageID, "containerd://")
	imageID = strings.TrimPrefix(imageID, "cri-o://")
	if idx := strings.LastIndex(imageID, "@sha256:"); idx >= 0 {
		return imageID[idx+1:]
	}
	return imageID
}

func stringsSliceToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

func stringsSetToAny(in map[string]struct{}) []any {
	keys := make([]string, 0, len(in))
	for v := range in {
		keys = append(keys, v)
	}
	sort.Strings(keys)

	out := make([]any, 0, len(keys))
	for _, v := range keys {
		out = append(out, v)
	}
	return out
}

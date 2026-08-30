// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func runtimeImageArgsFromK8sNames(nodeName, runtimeKind string, names []string, sizeBytes int64, containers []string, scanStatus string) map[string]*llx.RawData {
	tags, digests := splitK8sImageNames(names)
	imageID := ""
	if len(digests) > 0 {
		imageID = digests[0]
	}
	if imageID == "" {
		for _, name := range names {
			normalized := normalizeRuntimeImageID(name)
			if strings.HasPrefix(normalized, "sha256:") {
				imageID = normalized
				break
			}
		}
	}
	resolvedDigest := ""
	if len(digests) > 0 {
		resolvedDigest = digests[0]
	}
	id := nodeScopedRuntimeID(nodeName, resolvedDigest)
	if id == "" {
		id = nodeScopedRuntimeID(nodeName, imageID)
	}
	if id == "" && len(tags) > 0 {
		id = nodeScopedRuntimeID(nodeName, tags[0])
	}

	return map[string]*llx.RawData{
		"id":                llx.StringData(id),
		"nodeName":          llx.StringData(nodeName),
		"delegateId":        llx.StringData(runtimeKind),
		"runtimeKind":       llx.StringData(runtimeKind),
		"imageId":           llx.StringData(imageID),
		"repoTags":          llx.ArrayData(runtimeStringsToAny(tags), types.String),
		"repoDigests":       llx.ArrayData(runtimeStringsToAny(digests), types.String),
		"resolvedDigest":    llx.StringData(resolvedDigest),
		"targetDigest":      llx.StringData(resolvedDigest),
		"sizeBytes":         llx.IntData(sizeBytes),
		"labels":            llx.MapData(map[string]any{}, types.String),
		"namespaces":        llx.ArrayData([]any{}, types.String),
		"inUse":             llx.BoolData(len(containers) > 0),
		"containers":        llx.ArrayData(runtimeStringsToAny(containers), types.String),
		"scanStatus":        llx.StringData(scanStatus),
		"scanStatusMessage": llx.StringData(""),
		"layers":            llx.ArrayData([]any{}, types.Resource("container.runtimeImageLayer")),
		"created":           llx.TimeData(time.Time{}),
	}
}

func runtimeDelegateArgsFromK8sNode(nodeName, runtimeKind string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":            llx.StringData(nodeScopedRuntimeID(nodeName, runtimeKind)),
		"kind":          llx.StringData(runtimeKind),
		"endpoint":      llx.StringData(""),
		"priority":      llx.IntData(0),
		"nodeName":      llx.StringData(nodeName),
		"namespaces":    llx.ArrayData([]any{}, types.String),
		"snapshotters":  llx.ArrayData([]any{}, types.String),
		"readonly":      llx.BoolData(true),
		"allowPull":     llx.BoolData(false),
		"status":        llx.StringData("unavailable"),
		"statusMessage": llx.StringData("runtime-cache delegate is not configured"),
		"lastChecked":   llx.TimeData(time.Time{}),
	}
}

func runtimeDelegateArgsFromRuntimeCacheDelegate(nodeName string, settings *runtimeCacheSettings, delegate runtimeCacheDelegate) map[string]*llx.RawData {
	allowPull := false
	if settings != nil {
		allowPull = settings.AllowPull
	}
	return map[string]*llx.RawData{
		"id":            llx.StringData(nodeScopedRuntimeID(nodeName, delegate.ID)),
		"kind":          llx.StringData(delegate.Kind),
		"endpoint":      llx.StringData(delegate.Endpoint),
		"priority":      llx.IntData(int64(delegate.Priority)),
		"nodeName":      llx.StringData(nodeName),
		"namespaces":    llx.ArrayData(runtimeStringsToAny(delegate.Namespaces), types.String),
		"snapshotters":  llx.ArrayData([]any{}, types.String),
		"readonly":      llx.BoolData(delegate.ReadOnly),
		"allowPull":     llx.BoolData(allowPull),
		"status":        llx.StringData("ready"),
		"statusMessage": llx.StringData(""),
		"lastChecked":   llx.TimeData(time.Time{}),
	}
}

func nodeScopedRuntimeID(nodeName, id string) string {
	nodeName = strings.TrimSpace(nodeName)
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if nodeName == "" {
		return id
	}
	return nodeName + "/" + id
}

func splitK8sImageNames(names []string) ([]string, []string) {
	tags := []string{}
	digests := []string{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		normalized := normalizeRuntimeImageID(name)
		if strings.Contains(name, "@sha256:") || strings.HasPrefix(normalized, "sha256:") {
			digests = append(digests, normalized)
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

func runtimeKindFromVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	if idx := strings.Index(version, "://"); idx > 0 {
		return version[:idx]
	}
	return version
}

func runtimeKindFromContainerID(containerID string) string {
	containerID = strings.TrimSpace(containerID)
	if idx := strings.Index(containerID, "://"); idx > 0 {
		return containerID[:idx]
	}
	return ""
}

func runtimeStringsToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

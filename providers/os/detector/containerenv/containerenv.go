// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package containerenv tells whether a live connection runs inside a
// container, from the marker files container engines leave behind.
package containerenv

import (
	"bytes"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// markerFiles are created by the container engine when it starts the
// container: /.dockerenv by Docker (and by Podman for Docker compatibility),
// /run/.containerenv by Podman and CRI-O. Neither is part of an image.
var markerFiles = []string{
	"/.dockerenv",
	"/run/.containerenv",
}

// systemdContainerFile is where systemd records the container manager it was
// started under (systemd-nspawn writes it too). It holds a name such as
// "docker", "podman" or "lxc".
const systemdContainerFile = "/run/systemd/container"

// kubernetesServiceAccountDir is mounted into every pod that keeps the default
// service account token automount.
const kubernetesServiceAccountDir = "/var/run/secrets/kubernetes.io"

// cgroupContainerMarkers are path segments of PID 1's cgroup under cgroup v1
// when it runs in a container. Under cgroup v2 a container with its own cgroup
// namespace reads "0::/", which a host whose init is not systemd reads too, so
// v2 paths are not a signal on their own.
var cgroupContainerMarkers = []string{
	"/docker/", "/docker-", "/libpod-", "/libpod_parent/", "/lxc/", "/lxc.payload",
	"/kubepods", "/containerd/", "/cri-containerd-", "/crio-", "/ecs/", "/actions_job/",
}

// InContainer reports whether the connection runs commands inside a
// container: a local scan started in one, or an SSH session into one.
//
// Only connections that run commands are checked. A filesystem, tar or
// snapshot connection reads an image or a mounted disk, never a running
// container, and the docker connections already carry their kind.
func InContainer(conn shared.Connection) bool {
	if conn == nil || shared.WindowsNative(conn) {
		return false
	}
	// Only files are read below. The capability check stands for "this is
	// a live system", which a connection that only offers files isn't.
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return false
	}
	return inContainerFS(conn.FileSystem())
}

func inContainerFS(fs afero.Fs) bool {
	if fs == nil {
		return false
	}
	for _, f := range markerFiles {
		if exists(fs, f) {
			return true
		}
	}
	if content, err := afero.ReadFile(fs, systemdContainerFile); err == nil &&
		len(bytes.TrimSpace(content)) > 0 {
		return true
	}
	// PID 1's environment is readable by root only. Container engines set
	// container= there (systemd's own detection reads it), and Kubernetes
	// sets KUBERNETES_SERVICE_HOST in every container.
	if content, err := afero.ReadFile(fs, "/proc/1/environ"); err == nil && environNamesContainer(content) {
		return true
	}
	if content, err := afero.ReadFile(fs, "/proc/1/cgroup"); err == nil && cgroupNamesContainer(string(content)) {
		return true
	}
	return exists(fs, kubernetesServiceAccountDir)
}

func exists(fs afero.Fs, path string) bool {
	_, err := fs.Stat(path)
	return err == nil
}

// environNamesContainer reads a NUL-separated /proc/<pid>/environ and reports
// whether it names a container manager.
func environNamesContainer(environ []byte) bool {
	for _, kv := range bytes.Split(environ, []byte{0}) {
		key, value, ok := bytes.Cut(kv, []byte("="))
		if !ok || len(value) == 0 {
			continue
		}
		switch string(key) {
		case "container", "KUBERNETES_SERVICE_HOST":
			return true
		}
	}
	return false
}

// cgroupNamesContainer reads /proc/<pid>/cgroup and reports whether a cgroup
// path names a container.
func cgroupNamesContainer(cgroup string) bool {
	for _, line := range strings.Split(cgroup, "\n") {
		// hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		for _, m := range cgroupContainerMarkers {
			if strings.Contains(path, m) {
				return true
			}
		}
	}
	return false
}

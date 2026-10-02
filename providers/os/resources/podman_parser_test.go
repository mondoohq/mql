// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captured from "podman ps -a --format json" on Podman 6
const podmanTestPs = `[
  {
    "AutoRemove": false,
    "Command": ["sleep", "3600"],
    "CreatedAt": "2 minutes ago",
    "Exited": false,
    "ExitCode": 0,
    "Id": "55a0b364793a3cef9ee0e17e8d5153f9979d827374e57437a9b910924bba0bfd",
    "Image": "localhost/mql-os-verify:latest",
    "ImageID": "8ce27058e51034510c145f57b370ef9df424693c82c57e86af500b141be2ccc8",
    "IsInfra": false,
    "Labels": {"demo": "true"},
    "Mounts": [],
    "Names": ["mql-verify-ctr"],
    "Networks": ["podman"],
    "Pid": 1234,
    "Pod": "",
    "PodName": "",
    "Ports": [
      {"host_ip": "", "container_port": 5432, "host_port": 40441, "range": 1, "protocol": "tcp"}
    ],
    "State": "running",
    "Status": "Up 2 minutes",
    "Created": 1784678819
  }
]`

func TestParsePodmanPs(t *testing.T) {
	entries, err := parsePodmanPs(podmanTestPs)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "55a0b364793a3cef9ee0e17e8d5153f9979d827374e57437a9b910924bba0bfd", entry.ID)
	assert.Equal(t, []string{"mql-verify-ctr"}, entry.Names)
	assert.Equal(t, "localhost/mql-os-verify:latest", entry.Image)
	assert.Equal(t, []string{"sleep", "3600"}, entry.Command)
	assert.Equal(t, "running", entry.State)
	assert.False(t, entry.IsInfra)
	assert.Equal(t, map[string]string{"demo": "true"}, entry.Labels)
	require.Len(t, entry.Ports, 1)
	assert.Equal(t, int64(5432), entry.Ports[0].ContainerPort)
	assert.Equal(t, int64(40441), entry.Ports[0].HostPort)
	assert.Equal(t, "tcp", entry.Ports[0].Protocol)
}

func TestParsePodmanPs_EmptyOutput(t *testing.T) {
	// some subcommands print nothing rather than an empty array
	for _, out := range []string{"", "  \n", "null", "[]"} {
		entries, err := parsePodmanPs(out)
		require.NoError(t, err, out)
		assert.Empty(t, entries, out)
	}
}

func TestParsePodmanInspect(t *testing.T) {
	entries, err := parsePodmanInspect(`[
  {
    "Id": "55a0b364793a",
    "EffectiveCaps": ["CAP_CHOWN", "CAP_DAC_OVERRIDE"],
    "BoundingCaps": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SYS_TIME"],
    "Config": {"User": "postgres"},
    "HostConfig": {
      "Privileged": false,
      "CapAdd": ["CAP_SYS_TIME"],
      "CapDrop": [],
      "SecurityOpt": ["seccomp=unconfined"],
      "ReadonlyRootfs": true,
      "NetworkMode": "bridge",
      "PidMode": "private",
      "UsernsMode": "",
      "RestartPolicy": {"Name": "always"}
    }
  }
]`)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.False(t, entry.HostConfig.Privileged)
	assert.Equal(t, []string{"CAP_SYS_TIME"}, entry.HostConfig.CapAdd)
	// the engine folds a dropped capability into the resulting set instead of
	// echoing the request back, so the bounding set is the one worth reading
	assert.Empty(t, entry.HostConfig.CapDrop)
	assert.Len(t, entry.BoundingCaps, 3)
	assert.Equal(t, []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE"}, entry.EffectiveCaps)
	assert.Equal(t, []string{"seccomp=unconfined"}, entry.HostConfig.SecurityOpt)
	assert.True(t, entry.HostConfig.ReadonlyRootfs)
	assert.Equal(t, "postgres", entry.Config.User)
	assert.Equal(t, "always", entry.HostConfig.RestartPolicy.Name)
}

func TestParsePodmanInfo(t *testing.T) {
	info, err := parsePodmanInfo(`{
  "host": {
    "cgroupManager": "systemd",
    "cgroupVersion": "v2",
    "networkBackend": "netavark",
    "ociRuntime": {"name": "crun"},
    "security": {
      "rootless": true,
      "seccompEnabled": true,
      "seccompProfilePath": "/usr/share/containers/seccomp.json",
      "apparmorEnabled": false,
      "selinuxEnabled": true
    }
  },
  "store": {"graphDriverName": "overlay"},
  "version": {"Version": "6.0.1"}
}`)
	require.NoError(t, err)

	assert.True(t, info.Host.Security.Rootless)
	assert.Equal(t, "systemd", info.Host.CgroupManager)
	assert.Equal(t, "v2", info.Host.CgroupVersion)
	assert.Equal(t, "crun", info.Host.OciRuntime.Name)
	assert.Equal(t, "netavark", info.Host.NetworkBackend)
	assert.Equal(t, "overlay", info.Store.GraphDriverName)
	assert.Equal(t, "6.0.1", info.Version.Version)
	assert.True(t, info.Host.Security.SeccompEnabled)
	assert.Equal(t, "/usr/share/containers/seccomp.json", info.Host.Security.SeccompProfilePath)
	assert.False(t, info.Host.Security.ApparmorEnabled)
	assert.True(t, info.Host.Security.SelinuxEnabled)
}

func TestParsePodmanNetworks(t *testing.T) {
	// the network API uses snake_case where the other subcommands use PascalCase
	entries, err := parsePodmanNetworks(`[
  {
    "name": "podman",
    "id": "2f259b",
    "driver": "bridge",
    "network_interface": "podman0",
    "created": "2026-07-21T09:12:33.123456789Z",
    "subnets": [{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}],
    "ipv6_enabled": false,
    "internal": false,
    "dns_enabled": true
  }
]`)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "podman", entry.Name)
	assert.Equal(t, "podman0", entry.NetworkInterface)
	assert.True(t, entry.DNSEnabled)
	assert.False(t, entry.Internal)
	require.Len(t, entry.Subnets, 1)
	assert.Equal(t, "10.88.0.0/16", entry.Subnets[0].Subnet)
	assert.Equal(t, "10.88.0.1", entry.Subnets[0].Gateway)
}

func TestParsePodmanVolumes(t *testing.T) {
	entries, err := parsePodmanVolumes(`[
  {"Name": "data", "Driver": "local", "Mountpoint": "/var/lib/containers/storage/volumes/data/_data",
   "CreatedAt": "2026-07-21T09:12:33.123456789Z", "Labels": {"app": "db"}, "Options": {"type": "tmpfs"},
   "Scope": "local", "Anonymous": false}
]`)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "data", entries[0].Name)
	assert.Equal(t, "/var/lib/containers/storage/volumes/data/_data", entries[0].Mountpoint)
	assert.Equal(t, map[string]string{"app": "db"}, entries[0].Labels)
	assert.False(t, entries[0].Anonymous)
}

// captured from "podman images --format json" on Podman 6. The second record is
// a dangling image, which podman reports with the "<none>" sentinel and no names.
const podmanTestImages = `[
  {
    "Id": "8ce27058e51034510c145f57b370ef9df424693c82c57e86af500b141be2ccc8",
    "ParentId": "8807a786fd2b5b04b9950007e1e8854de282eacbb30c1561669a2929a2e3ddfd",
    "RepoDigests": ["localhost/mql-os-verify@sha256:177b1f25aaa28928f54ce9463fa1a2abf207c1b83bc12ecf0bf168fa13d6850a"],
    "Size": 214938349,
    "Labels": {"io.buildah.version": "1.44.0"},
    "Containers": 0,
    "Arch": "arm64",
    "Digest": "sha256:177b1f25aaa28928f54ce9463fa1a2abf207c1b83bc12ecf0bf168fa13d6850a",
    "IsManifestList": false,
    "Names": ["localhost/mql-os-verify:latest"],
    "Os": "linux",
    "Created": 1786027416,
    "CreatedAt": "2026-08-06T14:43:36Z",
    "Repository": "localhost/mql-os-verify",
    "Tag": "latest"
  },
  {
    "Id": "e3977ed107958c94428d68db2d417e44880767cb33ab3c78fd9eafca2399f113",
    "RepoDigests": [],
    "Size": 213218571,
    "Labels": {"io.buildah.version": "1.44.0"},
    "Dangling": true,
    "Arch": "arm64",
    "Digest": "sha256:005b1330211ad742f4edfb3914be2a6f8b71eb12828d864943e05cc4ba281c40",
    "Os": "linux",
    "Created": 1786026911,
    "CreatedAt": "2026-08-06T14:35:11Z",
    "Repository": "<none>",
    "Tag": "<none>"
  }
]`

func TestParsePodmanImages(t *testing.T) {
	entries, err := parsePodmanImages(podmanTestImages)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	tagged := entries[0]
	assert.Equal(t, "8ce27058e51034510c145f57b370ef9df424693c82c57e86af500b141be2ccc8", tagged.ID)
	assert.Equal(t, []string{"localhost/mql-os-verify:latest"}, tagged.Names)
	assert.Equal(t, "localhost/mql-os-verify", tagged.Repository)
	assert.Equal(t, "latest", tagged.Tag)
	assert.Equal(t, "sha256:177b1f25aaa28928f54ce9463fa1a2abf207c1b83bc12ecf0bf168fa13d6850a", tagged.Digest)
	assert.Equal(t, []string{"localhost/mql-os-verify@sha256:177b1f25aaa28928f54ce9463fa1a2abf207c1b83bc12ecf0bf168fa13d6850a"}, tagged.RepoDigests)
	assert.Equal(t, int64(214938349), tagged.Size)
	assert.Equal(t, map[string]string{"io.buildah.version": "1.44.0"}, tagged.Labels)
	assert.Equal(t, "linux", tagged.Os)
	// podman spells the architecture "Arch", unlike every other list command
	assert.Equal(t, "arm64", tagged.Architecture)
	assert.Equal(t, int64(1786027416), tagged.Created)

	dangling := entries[1]
	assert.Equal(t, "e3977ed107958c94428d68db2d417e44880767cb33ab3c78fd9eafca2399f113", dangling.ID)
	assert.Empty(t, dangling.Names)
}

func TestParsePodmanImages_EmptyOutput(t *testing.T) {
	for _, out := range []string{"", "  \n", "null", "[]"} {
		entries, err := parsePodmanImages(out)
		require.NoError(t, err, out)
		assert.Empty(t, entries, out)
	}
}

// captured from "podman pod ps --format json" on Podman 6
const podmanTestPods = `[
  {
    "Cgroup": "user.slice",
    "Containers": [
      {"Id": "ed818215b9ec3f1d9406254590a10f9dc8ac67d2d23f3c97cc372ea32fc18640", "Names": "2521b4ff96c5-infra", "Status": "created", "RestartCount": 0}
    ],
    "Created": "2026-08-06T13:09:22.73838403-07:00",
    "Id": "2521b4ff96c5c138f1750030e0f86a31c966382739e1de5133550992bba964d1",
    "InfraId": "ed818215b9ec3f1d9406254590a10f9dc8ac67d2d23f3c97cc372ea32fc18640",
    "Name": "mql-fixture-pod",
    "Namespace": "",
    "Networks": ["podman"],
    "Status": "Created",
    "Labels": {"app": "db"}
  }
]`

func TestParsePodmanPods(t *testing.T) {
	entries, err := parsePodmanPods(podmanTestPods)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "2521b4ff96c5c138f1750030e0f86a31c966382739e1de5133550992bba964d1", entry.ID)
	assert.Equal(t, "mql-fixture-pod", entry.Name)
	assert.Equal(t, "Created", entry.Status)
	// the infra container id is spelled "InfraId", not "InfraID"
	assert.Equal(t, "ed818215b9ec3f1d9406254590a10f9dc8ac67d2d23f3c97cc372ea32fc18640", entry.InfraID)
	assert.Equal(t, map[string]string{"app": "db"}, entry.Labels)

	// pods carry an RFC 3339 timestamp with an offset, not a unix epoch
	created := podmanParseTime(entry.Created)
	require.NotNil(t, created)
	assert.Equal(t, 2026, created.Year())
	assert.Equal(t, time.August, created.Month())
}

func TestParsePodmanPods_EmptyOutput(t *testing.T) {
	for _, out := range []string{"", "  \n", "null", "[]"} {
		entries, err := parsePodmanPods(out)
		require.NoError(t, err, out)
		assert.Empty(t, entries, out)
	}
}

func TestPodmanImageRepoTag(t *testing.T) {
	tests := []struct {
		title      string
		entry      podmanImageEntry
		repository string
		tag        string
	}{
		{
			"reported by podman",
			podmanImageEntry{Repository: "localhost/mql-os-verify", Tag: "latest", Names: []string{"localhost/mql-os-verify:latest"}},
			"localhost/mql-os-verify", "latest",
		},
		{
			// a dangling image has no reference, and the sentinel must not surface
			// as a repository literally named "<none>"
			"dangling",
			podmanImageEntry{Repository: podmanNone, Tag: podmanNone},
			"", "",
		},
		{
			"untagged but still named",
			podmanImageEntry{Repository: podmanNone, Tag: podmanNone, Names: []string{"docker.io/library/debian:13"}},
			"docker.io/library/debian", "13",
		},
		{
			// older podman omits the fields entirely and only reports names
			"derived from the first reference",
			podmanImageEntry{Names: []string{"registry.local:5000/app:1.2", "registry.local:5000/app:latest"}},
			"registry.local:5000/app", "1.2",
		},
		{
			"nothing to report",
			podmanImageEntry{},
			"", "",
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			repository, tag := podmanImageRepoTag(test.entry)
			assert.Equal(t, test.repository, repository)
			assert.Equal(t, test.tag, tag)
		})
	}
}

func TestPodmanSplitReference(t *testing.T) {
	tests := []struct {
		title      string
		reference  string
		repository string
		tag        string
	}{
		{"tagged", "docker.io/library/debian:13", "docker.io/library/debian", "13"},
		{"local tagged", "localhost/mql-os-verify:latest", "localhost/mql-os-verify", "latest"},
		{"untagged", "docker.io/library/debian", "docker.io/library/debian", ""},
		{"registry port is not a tag", "registry.local:5000/app", "registry.local:5000/app", ""},
		{"registry port with tag", "registry.local:5000/app:1.2", "registry.local:5000/app", "1.2"},
		{"digest pinned", "docker.io/library/debian@sha256:abc123", "docker.io/library/debian@sha256:abc123", ""},
		{"empty", "", "", ""},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			repository, tag := podmanSplitReference(test.reference)
			assert.Equal(t, test.repository, repository)
			assert.Equal(t, test.tag, tag)
		})
	}
}

func TestPodmanPrimaryName(t *testing.T) {
	assert.Equal(t, "web", podmanPrimaryName([]string{"web", "web-alias"}))
	assert.Empty(t, podmanPrimaryName(nil))
	assert.Empty(t, podmanPrimaryName([]string{}))
}

func TestPodmanUnixTime(t *testing.T) {
	got := podmanUnixTime(1784678819)
	require.NotNil(t, got)
	assert.Equal(t, int64(1784678819), got.Unix())

	// a container that never ran carries no time, and the engine's sentinel for
	// that must not surface as a date in 1970
	assert.Nil(t, podmanUnixTime(0))
	assert.Nil(t, podmanUnixTime(-62135596800))
}

func TestPodmanParseTime(t *testing.T) {
	got := podmanParseTime("2026-07-21T09:12:33.123456789Z")
	require.NotNil(t, got)
	assert.Equal(t, 2026, got.Year())
	assert.Equal(t, time.July, got.Month())

	assert.Nil(t, podmanParseTime(""))
	assert.Nil(t, podmanParseTime("not a time"))
}

// captured from "podman ps -a --format json" on podman 4.9.4 (RHEL 8): a port
// published on every interface carries an empty host_ip, one bound to loopback
// carries the address
const podmanTestPsPorts = `[
  {
    "Id": "plocal",
    "Names": ["plocal"],
    "Ports": [
      {"host_ip": "", "container_port": 90, "host_port": 9090, "range": 1, "protocol": "udp"},
      {"host_ip": "127.0.0.1", "container_port": 80, "host_port": 8083, "range": 1, "protocol": "tcp"}
    ]
  }
]`

func TestPodmanPortDicts(t *testing.T) {
	entries, err := parsePodmanPs(podmanTestPsPorts)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	ports := podmanPortDicts(entries[0].Ports)
	require.Len(t, ports, 2)
	assert.Equal(t, map[string]any{
		"hostIp":        "0.0.0.0",
		"hostPort":      int64(9090),
		"containerPort": int64(90),
		"protocol":      "udp",
		"range":         int64(1),
	}, ports[0], "an empty host_ip is every interface")
	assert.Equal(t, "127.0.0.1", ports[1].(map[string]any)["hostIp"], "a bound address is kept")
	assert.Empty(t, podmanPortDicts(nil))
}

// captured from "podman info --format json" on podman 1.6.4 (RHEL 7), trimmed
const podmanTestInfoV1 = `{
    "host": {
        "BuildahVersion": "1.11.7",
        "CgroupVersion": "v1",
        "OCIRuntime": {"name": "runc", "path": "/usr/bin/runc"},
        "os": "linux",
        "rootless": false
    },
    "registries": {"search": ["docker.io"]},
    "store": {"GraphDriverName": "overlay"}
}`

func TestParsePodmanInfo_V1HasNoSecurity(t *testing.T) {
	info, err := parsePodmanInfo(podmanTestInfoV1)
	require.NoError(t, err)
	assert.Nil(t, info.Host.Security, "podman 1.x reports no security block")
	assert.Equal(t, "", info.Version.Version, "podman 1.x reports no version")
}

func TestParsePodmanVersionOutput(t *testing.T) {
	assert.Equal(t, "1.6.4", parsePodmanVersionOutput("podman version 1.6.4\n"))
	assert.Equal(t, "4.9.4-rhel", parsePodmanVersionOutput("podman version 4.9.4-rhel\n"))
	assert.Equal(t, "5.8.2", parsePodmanVersionOutput("podman version 5.8.2"))
	assert.Equal(t, "", parsePodmanVersionOutput(""))
	assert.Equal(t, "", parsePodmanVersionOutput("podman version"))
}

func TestPodmanCheckSupported(t *testing.T) {
	err := podmanCheckSupported("1.6.4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "podman 1.6.4 is not supported")

	assert.NoError(t, podmanCheckSupported("2.0.0"))
	assert.NoError(t, podmanCheckSupported("4.9.4-rhel"))
	assert.NoError(t, podmanCheckSupported("5.8.2"))
	assert.NoError(t, podmanCheckSupported(""), "an unreadable version blocks nothing")
}

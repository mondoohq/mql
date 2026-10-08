// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		"allInterfaces": true,
	}, ports[0], "an empty host_ip is every interface")
	assert.Equal(t, "127.0.0.1", ports[1].(map[string]any)["hostIp"], "a bound address is kept")
	assert.Equal(t, false, ports[1].(map[string]any)["allInterfaces"], "a bound address is not every interface")
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

// captured from "podman images --format json" on Podman 3.4.2 (Debian 10), with
// quay.io/libpod/alpine:latest also tagged localhost/g08fix:extra. The image is
// listed once per tag, and its repo digests lack the repository.
const podmanTestImagesV3 = `[
  {
    "Id": "ed210e3e4a5bae1237f1bb44d72a05a2f1e5c6bfe7a7e73da179e2534269c459",
    "ParentId": "",
    "RepoTags": null,
    "RepoDigests": [
      "sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
      "sha256:369201a612f7b2b585a8e6ca99f77a36bcdbd032463d815388a96800b63ef2c8"
    ],
    "Size": 689969,
    "SharedSize": 0,
    "VirtualSize": 689969,
    "Labels": null,
    "Containers": 2,
    "Names": ["k8s.gcr.io/pause:3.5"],
    "Digest": "sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
    "History": ["k8s.gcr.io/pause:3.5"],
    "Created": 1615900617,
    "CreatedAt": "2021-03-16T13:16:57Z"
  },
  {
    "Id": "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
    "ParentId": "",
    "RepoTags": null,
    "RepoDigests": [
      "sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
      "sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00"
    ],
    "Size": 5847966,
    "Labels": null,
    "Containers": 8,
    "Names": ["quay.io/libpod/alpine:latest", "localhost/g08fix:extra"],
    "Digest": "sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
    "History": ["localhost/g08fix:extra", "quay.io/libpod/alpine:latest"],
    "Created": 1566332395,
    "CreatedAt": "2019-08-20T20:19:55Z"
  },
  {
    "Id": "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
    "ParentId": "",
    "RepoTags": null,
    "RepoDigests": [
      "sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
      "sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00"
    ],
    "Size": 5847966,
    "Labels": null,
    "Containers": 8,
    "Names": ["quay.io/libpod/alpine:latest", "localhost/g08fix:extra"],
    "Digest": "sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
    "History": ["localhost/g08fix:extra", "quay.io/libpod/alpine:latest"],
    "Created": 1566332395,
    "CreatedAt": "2019-08-20T20:19:55Z"
  }
]`

// captured from "podman images --format json" on Podman 5.4.2 (Debian 13): repo
// digests carry the repository, but there is no platform
const podmanTestImagesV5 = `[
  {
    "Id": "f0b02e9d092d905d0d87a8455a1ae3e9bb47b4aa3dc125125ca5cd10d6441c9f",
    "ParentId": "",
    "RepoTags": null,
    "RepoDigests": [
      "quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d",
      "quay.io/libpod/busybox@sha256:c9249fdf56138f0d929e2080ae98ee9cb2946f71498fc1484288e6a935b5e5bc"
    ],
    "Size": 1454611,
    "SharedSize": 0,
    "VirtualSize": 1454611,
    "Labels": null,
    "Containers": 1,
    "Digest": "sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d",
    "History": ["quay.io/libpod/busybox:latest"],
    "Names": ["quay.io/libpod/busybox:latest"],
    "Created": 1602670054,
    "CreatedAt": "2020-10-14T10:07:34Z"
  }
]`

// captured from "podman image inspect 961769676411 ed210e3e4a5b" on Podman 3.4.2
// (Debian 10), trimmed to the keys the image list leaves out
const podmanTestImageInspectV3 = `[
  {
    "Id": "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4",
    "Digest": "sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
    "RepoTags": ["quay.io/libpod/alpine:latest", "localhost/g08fix:extra"],
    "RepoDigests": [
      "localhost/g08fix@sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
      "localhost/g08fix@sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f",
      "quay.io/libpod/alpine@sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
      "quay.io/libpod/alpine@sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f"
    ],
    "Os": "linux",
    "Architecture": "amd64"
  },
  {
    "Id": "ed210e3e4a5bae1237f1bb44d72a05a2f1e5c6bfe7a7e73da179e2534269c459",
    "Digest": "sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
    "RepoTags": ["k8s.gcr.io/pause:3.5"],
    "RepoDigests": [
      "k8s.gcr.io/pause@sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
      "k8s.gcr.io/pause@sha256:369201a612f7b2b585a8e6ca99f77a36bcdbd032463d815388a96800b63ef2c8"
    ],
    "Os": "linux",
    "Architecture": "amd64"
  }
]`

func TestPodmanUniqueImages(t *testing.T) {
	entries, err := parsePodmanImages(podmanTestImagesV3)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	unique := podmanUniqueImages(entries)
	require.Len(t, unique, 2)
	assert.Equal(t, "ed210e3e4a5bae1237f1bb44d72a05a2f1e5c6bfe7a7e73da179e2534269c459", unique[0].ID)
	assert.Equal(t, "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4", unique[1].ID)
	assert.Equal(t, []string{"quay.io/libpod/alpine:latest", "localhost/g08fix:extra"}, unique[1].Names)
}

func TestPodmanImageNeedsInspect(t *testing.T) {
	v3, err := parsePodmanImages(podmanTestImagesV3)
	require.NoError(t, err)
	assert.True(t, podmanImageNeedsInspect(v3[0]), "podman 3 lists bare repo digests and no platform")

	v5, err := parsePodmanImages(podmanTestImagesV5)
	require.NoError(t, err)
	assert.True(t, podmanImageNeedsInspect(v5[0]), "podman 5 lists no platform")

	v6, err := parsePodmanImages(podmanTestImages)
	require.NoError(t, err)
	assert.False(t, podmanImageNeedsInspect(v6[0]), "podman 6 lists everything")
	assert.False(t, podmanImageNeedsInspect(v6[1]), "a dangling image with no repo digests needs nothing more")

	bareDigest := v6[0]
	bareDigest.RepoDigests = []string{"sha256:177b1f25aaa28928f54ce9463fa1a2abf207c1b83bc12ecf0bf168fa13d6850a"}
	assert.True(t, podmanImageNeedsInspect(bareDigest))
}

func TestParsePodmanImageInspect(t *testing.T) {
	records, err := parsePodmanImageInspect(podmanTestImageInspectV3)
	require.NoError(t, err)
	require.Len(t, records, 2)

	alpine := records[0]
	assert.Equal(t, "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4", alpine.ID)
	assert.Equal(t, "linux", alpine.Os)
	assert.Equal(t, "amd64", alpine.Architecture)
	assert.Contains(t, alpine.RepoDigests, "quay.io/libpod/alpine@sha256:fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f")
	assert.Len(t, alpine.RepoDigests, 4)

	for _, out := range []string{"", "null", "[]"} {
		records, err := parsePodmanImageInspect(out)
		require.NoError(t, err, out)
		assert.Empty(t, records, out)
	}
}

func TestPodmanMergeImageInspect(t *testing.T) {
	entries, err := parsePodmanImages(podmanTestImagesV3)
	require.NoError(t, err)
	records, err := parsePodmanImageInspect(podmanTestImageInspectV3)
	require.NoError(t, err)

	pause := entries[0]
	podmanMergeImageInspect(&pause, records[1])
	assert.Equal(t, []string{
		"k8s.gcr.io/pause@sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07",
		"k8s.gcr.io/pause@sha256:369201a612f7b2b585a8e6ca99f77a36bcdbd032463d815388a96800b63ef2c8",
	}, pause.RepoDigests)
	assert.Equal(t, "linux", pause.Os)
	assert.Equal(t, "amd64", pause.Architecture)
	// the list keeps what inspect has no say in
	assert.Equal(t, "sha256:1ff6c18fbef2045af6b9c16bf034cc421a29027b800e4f9b68ae9b1cb3e9ae07", pause.Digest)
	assert.Equal(t, int64(689969), pause.Size)
	assert.False(t, podmanImageNeedsInspect(pause))

	// with no repo digests from inspect, the list's bare digests are dropped
	unpushed := entries[1]
	podmanMergeImageInspect(&unpushed, podmanImageInspectEntry{ID: unpushed.ID, Os: "linux", Architecture: "arm64"})
	assert.Empty(t, unpushed.RepoDigests)
	assert.Equal(t, "arm64", unpushed.Architecture)

	// but the list's repository-qualified digests are kept
	v5, err := parsePodmanImages(podmanTestImagesV5)
	require.NoError(t, err)
	busybox := v5[0]
	podmanMergeImageInspect(&busybox, podmanImageInspectEntry{ID: busybox.ID, Os: "linux", Architecture: "amd64"})
	assert.Equal(t, []string{
		"quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d",
		"quay.io/libpod/busybox@sha256:c9249fdf56138f0d929e2080ae98ee9cb2946f71498fc1484288e6a935b5e5bc",
	}, busybox.RepoDigests)
}

// captured from "podman ps -a --format json" on podman 3.4.2 (Ubuntu 20.04)
// and 3.0.1 (Debian 11): podman 3 spells the port mapping in camelCase and has
// no range
const podmanTestPsPortsV3 = `[
  {
    "Id": "pweb",
    "Names": ["pweb"],
    "Ports": [{"hostPort": 8081, "containerPort": 80, "protocol": "tcp", "hostIP": ""}]
  },
  {
    "Id": "plocal",
    "Names": ["plocal"],
    "Ports": [{"hostPort": 8083, "containerPort": 80, "protocol": "tcp", "hostIP": "127.0.0.1"}]
  },
  {
    "Id": "pexit",
    "Names": ["pexit"],
    "Ports": null
  }
]`

func TestPodmanPortDicts_Podman3(t *testing.T) {
	entries, err := parsePodmanPs(podmanTestPsPortsV3)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	assert.Equal(t, []any{map[string]any{
		"hostIp":        "0.0.0.0",
		"hostPort":      int64(8081),
		"containerPort": int64(80),
		"protocol":      "tcp",
		"range":         int64(1),
		"allInterfaces": true,
	}}, podmanPortDicts(entries[0].Ports), "published on every interface")
	assert.Equal(t, []any{map[string]any{
		"hostIp":        "127.0.0.1",
		"hostPort":      int64(8083),
		"containerPort": int64(80),
		"protocol":      "tcp",
		"range":         int64(1),
		"allInterfaces": false,
	}}, podmanPortDicts(entries[1].Ports), "bound to loopback")
	assert.Empty(t, podmanPortDicts(entries[2].Ports))
}

// A port record that names no port in either spelling is not every interface.
func TestPodmanPortDicts_UndecodedPortIsNotAllInterfaces(t *testing.T) {
	entries, err := parsePodmanPs(`[{"Id": "x", "Ports": [{"protocol": "tcp"}]}]`)
	require.NoError(t, err)
	ports := podmanPortDicts(entries[0].Ports)
	require.Len(t, ports, 1)
	assert.Equal(t, "", ports[0].(map[string]any)["hostIp"])
	assert.Equal(t, false, ports[0].(map[string]any)["allInterfaces"])
}

func TestPodmanVersionFailure(t *testing.T) {
	cases := []struct {
		name         string
		exitCode     int64
		stderr       string
		notInstalled bool
		refused      bool
	}{
		// Debian/Ubuntu /bin/sh (dash)
		{"dash not found", 127, "sh: 1: podman: not found\n", true, false},
		{"bash not found", 127, "bash: line 1: podman: command not found\n", true, false},
		// sudo exits 1 when it cannot find the command
		{"sudo not found", 1, "sudo: podman: command not found\n", true, false},
		{"sudo not found, German locale", 1, "sudo: podman: Befehl nicht gefunden\n", true, false},
		// deb13 over SSH --sudo with "Defaults requiretty"
		{"sudo requiretty", 1, "sudo: sorry, you must have a tty to run sudo\n", false, true},
		{"sudo password", 1, "sudo: a password is required\n", false, true},
		{"not executable", 126, "sh: 1: podman: Permission denied\n", false, true},
		{"engine failure", 125, "Error: cannot re-exec process\n", false, false},
	}
	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			assert.Equal(t, kase.notInstalled, isPodmanNotInstalled(kase.exitCode, kase.stderr), "not installed")
			assert.Equal(t, kase.refused, isPodmanRefused(kase.exitCode, kase.stderr), "refused")
		})
	}
}

func readPodmanFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "podman", name))
	require.NoError(t, err)
	return string(b)
}

// podmanInspectFixture returns the inspect records of the containers podman
// 5.8.7 ran with these settings:
//
//	plain       no options
//	hardened    --read-only --security-opt no-new-privileges --cap-drop ALL
//	            --cap-add NET_BIND_SERVICE --memory 64m --cpus 0.5
//	            --cpu-shares 512 --pids-limit 100 --ulimit nofile=1024:2048
//	            --user 1000:1000 --health-cmd true --health-interval 10s
//	            -p 127.0.0.1:8080:80 --device /dev/fuse -v data:/data:ro
//	            --tmpfs /scratch:ro,size=1m
//	priv        --privileged --network host --pid host --ipc host --uts host
//	            --cgroupns host -v /run/podman/podman.sock:/run/podman/podman.sock
//	            -v /etc:/host/etc:ro,rshared
//	unconfined  --security-opt seccomp=unconfined --security-opt apparmor=unconfined
//	            --security-opt label=disable -p 9090:90/udp -p 7000-7002:7000-7002
//	            --pids-limit 0
//	allowall    --security-opt seccomp=/tmp/allow.json (a profile allowing every
//	            call) --ipc shareable --health-cmd "exit 1" --health-interval 5s
func podmanInspectFixture(t *testing.T) map[string]*podmanInspectEntry {
	t.Helper()
	entries, err := parsePodmanInspect(readPodmanFixture(t, "inspect.json"))
	require.NoError(t, err)
	ps, err := parsePodmanPs(readPodmanFixture(t, "ps.json"))
	require.NoError(t, err)
	names := map[string]string{}
	for _, p := range ps {
		names[p.ID] = podmanPrimaryName(p.Names)
	}
	res := map[string]*podmanInspectEntry{}
	for i := range entries {
		res[names[entries[i].ID]] = &entries[i]
	}
	require.Len(t, res, 5)
	return res
}

func TestParsePodmanInspectConfinement(t *testing.T) {
	c := podmanInspectFixture(t)

	plain := c["plain"]
	assert.Equal(t, "shareable", plain.HostConfig.IpcMode)
	assert.Equal(t, "private", plain.HostConfig.UTSMode)
	assert.Equal(t, "private", plain.HostConfig.CgroupMode)
	assert.Equal(t, int64(2048), plain.HostConfig.PidsLimit, "podman's default limit")
	assert.Equal(t, int64(0), plain.HostConfig.Memory)
	assert.Nil(t, plain.Config.Healthcheck)
	assert.Equal(t, "", plain.healthStatus())
	assert.False(t, securityOptNoNewPrivileges(plain.HostConfig.SecurityOpt))

	hard := c["hardened"]
	assert.True(t, securityOptNoNewPrivileges(hard.HostConfig.SecurityOpt))
	assert.Equal(t, int64(67108864), hard.HostConfig.Memory)
	assert.Equal(t, int64(500000000), hard.HostConfig.NanoCpus)
	assert.Equal(t, int64(512), hard.HostConfig.CPUShares)
	assert.Equal(t, int64(100), hard.HostConfig.PidsLimit)
	require.Len(t, hard.HostConfig.Ulimits, 2)
	assert.Equal(t, "nofile", podmanUlimitName(hard.HostConfig.Ulimits[0].Name))
	assert.Equal(t, int64(1024), hard.HostConfig.Ulimits[0].Soft)
	assert.Equal(t, int64(2048), hard.HostConfig.Ulimits[0].Hard)
	require.Len(t, hard.HostConfig.Devices, 1)
	assert.Equal(t, "/dev/fuse", hard.HostConfig.Devices[0].PathOnHost)
	assert.Equal(t, "/dev/fuse", hard.HostConfig.Devices[0].PathInContainer)
	assert.True(t, healthcheckDefined(hard.Config.Healthcheck))
	assert.Equal(t, []string{"CMD-SHELL", "true"}, hard.Config.Healthcheck.Test)
	secs, ok := healthcheckIntervalSeconds(hard.Config.Healthcheck)
	assert.True(t, ok)
	assert.Equal(t, int64(10), secs)
	assert.Equal(t, "starting", hard.healthStatus())

	mounts := containerMounts(hard.Mounts, hard.HostConfig.Tmpfs)
	require.Len(t, mounts, 2)
	assert.Equal(t, "volume", string(mounts[0].Type))
	assert.Equal(t, "data", mounts[0].Name)
	assert.Equal(t, "/var/lib/containers/storage/volumes/data/_data", mounts[0].Source)
	assert.Equal(t, "/data", mounts[0].Destination)
	assert.False(t, mounts[0].RW)
	assert.Equal(t, "local", mounts[0].Driver)
	assert.Equal(t, "tmpfs", string(mounts[1].Type), "a --tmpfs mount is only in HostConfig.Tmpfs")
	assert.Equal(t, "/scratch", mounts[1].Destination)
	assert.False(t, mounts[1].RW)

	priv := c["priv"]
	assert.Equal(t, "host", priv.HostConfig.IpcMode)
	assert.Equal(t, "host", priv.HostConfig.UTSMode)
	assert.Equal(t, "host", priv.HostConfig.CgroupMode)
	assert.Equal(t, "host", priv.HostConfig.PidMode)
	mounts = containerMounts(priv.Mounts, priv.HostConfig.Tmpfs)
	require.Len(t, mounts, 2)
	assert.Equal(t, "bind", string(mounts[0].Type))
	assert.Equal(t, "/run/podman/podman.sock", mounts[0].Source)
	assert.True(t, mounts[0].RW)
	assert.Equal(t, "/etc", mounts[1].Source)
	assert.False(t, mounts[1].RW)
	assert.Equal(t, "rshared", string(mounts[1].Propagation))

	assert.Equal(t, int64(0), c["unconfined"].HostConfig.PidsLimit, "--pids-limit 0 is unlimited")
	assert.Equal(t, "starting", c["allowall"].healthStatus())
	secs, ok = healthcheckIntervalSeconds(c["allowall"].Config.Healthcheck)
	assert.True(t, ok)
	assert.Equal(t, int64(5), secs)
}

func TestPodmanSeccompProfile(t *testing.T) {
	c := podmanInspectFixture(t)
	info, err := parsePodmanInfo(readPodmanFixture(t, "info.json"))
	require.NoError(t, err)
	engine := info.Host.Security
	require.NotNil(t, engine)
	assert.Equal(t, "/usr/share/containers/seccomp.json", engine.SeccompProfilePath)

	allowAll := `{"defaultAction":"SCMP_ACT_ALLOW"}`
	files := map[string]string{"/tmp/allow.json": allowAll, "/etc/custom.json": `{"defaultAction":"SCMP_ACT_ERRNO"}`}
	read := func(p string) string { return files[p] }
	profile := func(name string) string {
		e := c[name]
		return podmanSeccompProfile(e.HostConfig.Privileged, e.HostConfig.SecurityOpt, nil, engine, read)
	}

	assert.Equal(t, "default", profile("plain"))
	assert.Equal(t, "default", profile("hardened"))
	assert.Equal(t, "unconfined", profile("priv"), "privileged")
	assert.Equal(t, "unconfined", profile("unconfined"))
	assert.Equal(t, "unconfined", profile("allowall"), "its profile allows every call")

	// a profile that filters
	assert.Equal(t, "custom", podmanSeccompProfile(false, []string{"seccomp=/etc/custom.json"}, nil, engine, read))
	// one that cannot be read is not assumed to allow everything
	assert.Equal(t, "custom", podmanSeccompProfile(false, []string{"seccomp=/missing.json"}, nil, engine, read))
	// the engine's profile from containers.conf
	allowEngine := &podmanInfoSecurity{SeccompEnabled: true, SeccompProfilePath: "/tmp/allow.json"}
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, nil, nil, allowEngine, read))
	assert.Equal(t, "custom", podmanSeccompProfile(false, nil, nil, &podmanInfoSecurity{SeccompEnabled: true, SeccompProfilePath: "/etc/custom.json"}, read))
	unconfinedEngine := &podmanInfoSecurity{SeccompEnabled: true, SeccompProfilePath: "unconfined"}
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, nil, nil, unconfinedEngine, read))
	// a host without seccomp
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, nil, nil, &podmanInfoSecurity{SeccompEnabled: false}, read))

	// The spec embeds the filter the container was created with, so with a
	// spec no profile file is read at all: plain was created with the default
	// profile and stays filtered after the engine's profile changes.
	noRead := func(p string) string {
		t.Errorf("a profile file was read although the spec was available: %s", p)
		return ""
	}
	plainSpec, err := parseOCISpec([]byte(readPodmanFixture(t, "config-plain.json")))
	require.NoError(t, err)
	assert.Equal(t, "default", podmanSeccompProfile(false, nil, plainSpec, engine, noRead))
	assert.Equal(t, "default", podmanSeccompProfile(false, nil, plainSpec, unconfinedEngine, noRead))
	assert.Equal(t, "custom", podmanSeccompProfile(false, nil, plainSpec, allowEngine, noRead),
		"filtered, and the engine names a profile other than the packaged one")
	assert.Equal(t, "custom", podmanSeccompProfile(false, []string{"seccomp=/etc/custom.json"}, plainSpec, engine, noRead))
	// a container naming a profile that allows everything: the spec says so
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, []string{"seccomp=/tmp/allow.json"}, &ociSpec{}, engine, noRead))
	unconfinedSpec, err := parseOCISpec([]byte(readPodmanFixture(t, "config-unconfined.json")))
	require.NoError(t, err)
	e := c["unconfined"]
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, e.HostConfig.SecurityOpt, unconfinedSpec, engine, noRead))
	assert.Equal(t, "unconfined", podmanSeccompProfile(false, nil, unconfinedSpec, engine, noRead), "the spec has no profile")
}

func TestPodmanStoragePath(t *testing.T) {
	info, err := parsePodmanInfo(readPodmanFixture(t, "info.json"))
	require.NoError(t, err)
	roots := []string{info.Store.GraphRoot, info.Store.RunRoot}
	assert.Equal(t, "/var/lib/containers/storage", info.Store.GraphRoot)

	for _, e := range podmanInspectFixture(t) {
		assert.True(t, podmanStoragePath(e.OCIConfigPath, roots...), e.OCIConfigPath)
	}
	assert.True(t, podmanStoragePath("/run/containers/storage/overlay-containers/x/userdata/config.json", roots...))
	assert.False(t, podmanStoragePath("/dev/zero", roots...))
	assert.False(t, podmanStoragePath("/var/lib/containers/storage/../../../dev/zero", roots...))
	assert.False(t, podmanStoragePath("/var/lib/containers/storage-other/config.json", roots...))
	assert.False(t, podmanStoragePath("var/lib/containers/storage/x/config.json", roots...), "relative")
	assert.False(t, podmanStoragePath("", roots...))
	assert.False(t, podmanStoragePath("/var/lib/containers/storage/x", "", "relative/root"))
}

func TestPodmanUlimitName(t *testing.T) {
	assert.Equal(t, "nofile", podmanUlimitName("RLIMIT_NOFILE"))
	assert.Equal(t, "nproc", podmanUlimitName("RLIMIT_NPROC"))
	assert.Equal(t, "core", podmanUlimitName("core"))
}

// podman 4.3 and older name the health state Healthcheck
func TestPodmanInspectHealthStatusOldName(t *testing.T) {
	entries, err := parsePodmanInspect(`[{"Id":"x","State":{"Status":"running","Healthcheck":{"Status":"healthy"}},"Config":{"Healthcheck":{"Test":["CMD-SHELL","true"]}}}]`)
	require.NoError(t, err)
	assert.Equal(t, "healthy", entries[0].healthStatus())
}

// A stopped container keeps the last status of its health check, which is no
// longer checked.
func TestPodmanInspectHealthStatusStopped(t *testing.T) {
	entries, err := parsePodmanInspect(`[{"Id":"x","State":{"Status":"exited","Health":{"Status":"unhealthy"}},"Config":{"Healthcheck":{"Test":["CMD-SHELL","exit 1"]}}}]`)
	require.NoError(t, err)
	assert.Equal(t, "", entries[0].healthStatus())
}

// Podman 4.3.1 on Debian 12, with AppArmor: the privileged container's inspect
// record names no profile, and its process runs unconfined
// (/proc/<pid>/attr/current reads "unconfined").
func TestPodmanAppArmorProfile(t *testing.T) {
	entries, err := parsePodmanInspect(readPodmanFixture(t, "debian12-inspect.json"))
	require.NoError(t, err)
	info, err := parsePodmanInfo(readPodmanFixture(t, "debian12-info.json"))
	require.NoError(t, err)
	require.True(t, info.Host.Security.ApparmorEnabled)

	var named []struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	}
	require.NoError(t, json.Unmarshal([]byte(readPodmanFixture(t, "debian12-inspect.json")), &named))
	names := map[string]string{}
	for _, n := range named {
		names[n.ID] = n.Name
	}
	got := map[string]string{}
	for _, e := range entries {
		got[names[e.ID]] = podmanAppArmorProfile(e.AppArmorProfile, e.HostConfig.Privileged, info.Host.Security)
	}
	assert.Equal(t, map[string]string{
		"p-plain":  "containers-default-0.50.1",
		"p-priv":   "unconfined",
		"p-unconf": "unconfined",
	}, got)

	// without AppArmor on the host there is no profile to report
	assert.Equal(t, "", podmanAppArmorProfile("", true, &podmanInfoSecurity{}))
	assert.Equal(t, "", podmanAppArmorProfile("", true, nil))
}

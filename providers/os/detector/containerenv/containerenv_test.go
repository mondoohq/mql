// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package containerenv

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func memFS(t *testing.T, files map[string]string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for path, content := range files {
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	return fs
}

func TestInContainerFS(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		// docker run on Docker Desktop: /.dockerenv is an empty file,
		// PID 1 carries container=oci, cgroup v2 reads 0::/
		{name: "docker", files: map[string]string{"/.dockerenv": ""}, want: true},
		{name: "podman", files: map[string]string{"/run/.containerenv": "engine=\"podman-5.4.0\"\n"}, want: true},
		{name: "systemd container file", files: map[string]string{"/run/systemd/container": "lxc\n"}, want: true},
		{name: "empty systemd container file", files: map[string]string{"/run/systemd/container": "\n"}, want: false},
		{
			name:  "PID 1 environ",
			files: map[string]string{"/proc/1/environ": "PATH=/usr/local/sbin:/usr/bin\x00HOSTNAME=c1\x00container=oci\x00HOME=/root\x00"},
			want:  true,
		},
		{
			name:  "kubernetes pod",
			files: map[string]string{"/var/run/secrets/kubernetes.io/serviceaccount/token": "x"},
			want:  true,
		},
		{
			name:  "cgroup v1 docker",
			files: map[string]string{"/proc/1/cgroup": "12:memory:/docker/4f1c2e\n11:cpu,cpuacct:/docker/4f1c2e\n"},
			want:  true,
		},
		// a systemd host: PID 1 sits in init.scope, its environ has no
		// container=, and no marker file exists
		{
			name: "systemd host",
			files: map[string]string{
				"/proc/1/environ": "HOME=/\x00TERM=linux\x00BOOT_IMAGE=/vmlinuz-6.12.0\x00",
				"/proc/1/cgroup":  "0::/init.scope\n",
			},
			want: false,
		},
		{
			name:  "cgroup v1 host",
			files: map[string]string{"/proc/1/cgroup": "12:memory:/\n1:name=systemd:/init.scope\n"},
			want:  false,
		},
		// cgroup v2 inside a private cgroup namespace looks like a host
		// whose init is not systemd, so it is no signal on its own
		{name: "cgroup v2 root only", files: map[string]string{"/proc/1/cgroup": "0::/\n"}, want: false},
		{name: "nothing", files: map[string]string{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, inContainerFS(memFS(t, tt.files)))
		})
	}
}

func TestEnvironNamesContainer(t *testing.T) {
	assert.True(t, environNamesContainer([]byte("container=podman\x00")))
	assert.True(t, environNamesContainer([]byte("A=1\x00KUBERNETES_SERVICE_HOST=10.96.0.1\x00")))
	assert.False(t, environNamesContainer([]byte("container=\x00")), "an empty value names nothing")
	assert.False(t, environNamesContainer([]byte("mycontainer=1\x00container_id\x00")))
	assert.False(t, environNamesContainer(nil))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The fixtures in testdata/docker are `docker inspect` output from Docker
// Desktop 29.8.2 for containers started as follows:
//
//	default:  docker run -d alpine:3.22 sleep 3600
//	host:     --privileged --pid=host --network=host --ipc=host --uts=host
//	          --cgroupns=host -v /var/run/docker.sock:/var/run/docker.sock
//	          --restart=always
//	hardened: --cap-drop ALL --cap-add NET_BIND_SERVICE
//	          --security-opt no-new-privileges --read-only --user 1000:1000
//	          --memory 128m --cpu-shares 512 --cpus 0.5 --pids-limit 100
//	          --ulimit nofile=1024:2048 --ulimit nproc=64 --health-cmd true
//	          --health-interval 30s -p 127.0.0.1:8081:80 --restart on-failure:3
//	          --tmpfs /tmp:rw,size=16m -v dcs-vol:/data:ro
//	loose:    --security-opt seccomp=unconfined --security-opt apparmor=unconfined
//	          --security-opt no-new-privileges:false -p 0.0.0.0:8080:80
//	          -p 8082:80/udp -p 9000 --pids-limit -1
//	          --device /dev/fuse:/dev/fuse:rwm -v /tmp:/host-tmp --userns=host
//	seccomp:  --security-opt seccomp=<file with a custom profile>
//	          --mount type=tmpfs,destination=/scratch,readonly
//	stopped:  docker create --no-healthcheck alpine:3.22 true
func loadDockerInspect(t *testing.T, name string) *container.InspectResponse {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "docker", "inspect-"+name+".json"))
	require.NoError(t, err)
	var res []container.InspectResponse
	require.NoError(t, json.Unmarshal(data, &res))
	require.Len(t, res, 1)
	require.NotNil(t, res[0].HostConfig)
	require.NotNil(t, res[0].Config)
	return &res[0]
}

func TestDockerInspectDecode(t *testing.T) {
	def := loadDockerInspect(t, "default")
	assert.False(t, def.HostConfig.Privileged)
	assert.False(t, def.HostConfig.ReadonlyRootfs)
	assert.Empty(t, def.Config.User)
	assert.Equal(t, "bridge", string(def.HostConfig.NetworkMode))
	assert.Equal(t, "", string(def.HostConfig.PidMode))
	assert.Equal(t, "private", string(def.HostConfig.IpcMode))
	assert.Equal(t, "private", string(def.HostConfig.CgroupnsMode))
	assert.Equal(t, "no", string(def.HostConfig.RestartPolicy.Name))
	assert.Nil(t, def.HostConfig.CapAdd)

	host := loadDockerInspect(t, "host")
	assert.True(t, host.HostConfig.Privileged)
	assert.Equal(t, "host", string(host.HostConfig.NetworkMode))
	assert.Equal(t, "host", string(host.HostConfig.PidMode))
	assert.Equal(t, "host", string(host.HostConfig.IpcMode))
	assert.Equal(t, "host", string(host.HostConfig.UTSMode))
	assert.Equal(t, "host", string(host.HostConfig.CgroupnsMode))
	assert.Equal(t, "always", string(host.HostConfig.RestartPolicy.Name))

	hard := loadDockerInspect(t, "hardened")
	assert.True(t, hard.HostConfig.ReadonlyRootfs)
	assert.Equal(t, "1000:1000", hard.Config.User)
	assert.Equal(t, []string{"CAP_NET_BIND_SERVICE"}, hard.HostConfig.CapAdd)
	assert.Equal(t, []string{"ALL"}, hard.HostConfig.CapDrop)
	assert.Equal(t, "on-failure", string(hard.HostConfig.RestartPolicy.Name))
	assert.Equal(t, 3, hard.HostConfig.RestartPolicy.MaximumRetryCount)
	require.Len(t, hard.HostConfig.Ulimits, 2)
	assert.Equal(t, "nofile", hard.HostConfig.Ulimits[0].Name)
	assert.Equal(t, int64(1024), hard.HostConfig.Ulimits[0].Soft)
	assert.Equal(t, int64(2048), hard.HostConfig.Ulimits[0].Hard)
	assert.Equal(t, "healthy", string(hard.State.Health.Status))

	loose := loadDockerInspect(t, "loose")
	assert.Equal(t, "host", string(loose.HostConfig.UsernsMode))
	require.Len(t, loose.HostConfig.Devices, 1)
	assert.Equal(t, "/dev/fuse", loose.HostConfig.Devices[0].PathOnHost)
	assert.Equal(t, "rwm", loose.HostConfig.Devices[0].CgroupPermissions)
	assert.Nil(t, loose.State.Health, "no health check means no health status")
}

// loadDockerInfoSecurityOptions reads `docker info --format
// '{{json .SecurityOptions}}'` from Docker 29.8.2 daemons: Docker Desktop
// (desktop), and docker:29-dind started with --seccomp-profile=unconfined
// (unconfined) and with --seccomp-profile=/etc/dsc.json (custom).
func loadDockerInfoSecurityOptions(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "docker", "info-securityoptions-"+name+".json"))
	require.NoError(t, err)
	var res []string
	require.NoError(t, json.Unmarshal(data, &res))
	return res
}

func TestParseDockerDaemonSeccomp(t *testing.T) {
	assert.Equal(t, dockerDaemonSeccomp{supported: true, profile: "default"},
		parseDockerDaemonSeccomp(loadDockerInfoSecurityOptions(t, "desktop")))
	assert.Equal(t, dockerDaemonSeccomp{supported: true, profile: "unconfined"},
		parseDockerDaemonSeccomp(loadDockerInfoSecurityOptions(t, "unconfined")))
	assert.Equal(t, dockerDaemonSeccomp{supported: true, profile: "custom"},
		parseDockerDaemonSeccomp(loadDockerInfoSecurityOptions(t, "custom")))
	// a kernel without seccomp: the daemon reports no seccomp entry
	assert.Equal(t, dockerDaemonSeccomp{supported: false, profile: "unconfined"},
		parseDockerDaemonSeccomp([]string{"name=cgroupns"}))
	assert.False(t, parseDockerDaemonSeccomp(nil).supported)
}

func TestDockerSeccompProfile(t *testing.T) {
	builtin := parseDockerDaemonSeccomp(loadDockerInfoSecurityOptions(t, "desktop"))
	cases := map[string]string{
		"default":  "default",
		"hardened": "default",
		// privileged runs without seccomp although it names no profile
		"host":  "unconfined",
		"loose": "unconfined",
		// {"defaultAction":"SCMP_ACT_ALLOW"} filters nothing
		"seccomp": "unconfined",
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want, dockerSeccompProfile(loadDockerInspect(t, name).HostConfig, builtin))
		})
	}

	// a container naming no profile runs with the daemon's
	unconfinedDaemon := parseDockerDaemonSeccomp(loadDockerInfoSecurityOptions(t, "unconfined"))
	def := loadDockerInspect(t, "default").HostConfig
	assert.Equal(t, "unconfined", dockerSeccompProfile(def, unconfinedDaemon))
	assert.Equal(t, "custom", dockerSeccompProfile(def, dockerDaemonSeccomp{supported: true, profile: "custom"}))
	assert.Equal(t, "unconfined", dockerSeccompProfile(def, dockerDaemonSeccomp{supported: false, profile: "unconfined"}))
	// ...unless it names one
	assert.Equal(t, "default", dockerSeccompProfile(&container.HostConfig{SecurityOpt: []string{"seccomp=builtin"}}, unconfinedDaemon))
	// a kernel without seccomp filters nothing, whatever the container asks for
	assert.Equal(t, "unconfined", dockerSeccompProfile(&container.HostConfig{SecurityOpt: []string{"seccomp=builtin"}}, dockerDaemonSeccomp{}))

	assert.Equal(t, "unconfined", dockerSeccompProfile(&container.HostConfig{SecurityOpt: []string{"seccomp:unconfined"}}, builtin))
	restrictive := `seccomp={"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`
	assert.Equal(t, "custom", dockerSeccompProfile(&container.HostConfig{SecurityOpt: []string{restrictive}}, builtin))
	assert.Equal(t, "default", dockerSeccompProfile(nil, builtin))
}

func TestDockerSeccompAllowsAll(t *testing.T) {
	assert.True(t, seccompAllowsAll(`{"defaultAction":"SCMP_ACT_ALLOW"}`))
	assert.True(t, seccompAllowsAll(`{"defaultAction":"SCMP_ACT_LOG","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ALLOW"}]}`))
	assert.False(t, seccompAllowsAll(`{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO"}]}`),
		"an allow-by-default profile that denies one call still filters")
	assert.False(t, seccompAllowsAll(`{"defaultAction":"SCMP_ACT_ERRNO"}`))
	assert.False(t, seccompAllowsAll(`not json`))
}

func TestDockerNoNewPrivileges(t *testing.T) {
	assert.False(t, dockerNoNewPrivileges(loadDockerInspect(t, "default").HostConfig.SecurityOpt))
	assert.True(t, dockerNoNewPrivileges(loadDockerInspect(t, "hardened").HostConfig.SecurityOpt))
	assert.False(t, dockerNoNewPrivileges(loadDockerInspect(t, "loose").HostConfig.SecurityOpt),
		"no-new-privileges:false must not count as enabled")

	assert.True(t, dockerNoNewPrivileges([]string{"no-new-privileges:true"}))
	assert.True(t, dockerNoNewPrivileges([]string{"no-new-privileges=true"}))
	assert.False(t, dockerNoNewPrivileges([]string{"no-new-privileges=bogus"}))
	assert.False(t, dockerNoNewPrivileges([]string{"label=disable"}))
}

func TestDockerPositiveLimit(t *testing.T) {
	hard := loadDockerInspect(t, "hardened").HostConfig
	v, ok := dockerPositiveLimit(&hard.Memory)
	assert.True(t, ok)
	assert.Equal(t, int64(134217728), v)
	v, ok = dockerPositiveLimit(hard.PidsLimit)
	assert.True(t, ok)
	assert.Equal(t, int64(100), v)
	v, ok = dockerPositiveLimit(&hard.CPUShares)
	assert.True(t, ok)
	assert.Equal(t, int64(512), v)
	v, ok = dockerPositiveLimit(&hard.NanoCPUs)
	assert.True(t, ok)
	assert.Equal(t, int64(500000000), v)

	def := loadDockerInspect(t, "default").HostConfig
	_, ok = dockerPositiveLimit(&def.Memory)
	assert.False(t, ok, "memory 0 is unlimited")
	_, ok = dockerPositiveLimit(def.PidsLimit)
	assert.False(t, ok, "absent pids limit is unlimited")
	// --pids-limit -1 is stored as no limit at all
	_, ok = dockerPositiveLimit(loadDockerInspect(t, "loose").HostConfig.PidsLimit)
	assert.False(t, ok)

	minusOne, zero := int64(-1), int64(0)
	_, ok = dockerPositiveLimit(&minusOne)
	assert.False(t, ok)
	_, ok = dockerPositiveLimit(&zero)
	assert.False(t, ok)
}

func TestDockerHealthcheck(t *testing.T) {
	hard := loadDockerInspect(t, "hardened").Config.Healthcheck
	assert.True(t, dockerHasHealthcheck(hard))
	secs, ok := dockerHealthcheckInterval(hard)
	assert.True(t, ok)
	assert.Equal(t, int64(30), secs)

	assert.False(t, dockerHasHealthcheck(loadDockerInspect(t, "default").Config.Healthcheck))
	stopped := loadDockerInspect(t, "stopped").Config.Healthcheck
	require.NotNil(t, stopped)
	assert.Equal(t, []string{"NONE"}, stopped.Test)
	assert.False(t, dockerHasHealthcheck(stopped), "--no-healthcheck disables the check")
	_, ok = dockerHealthcheckInterval(stopped)
	assert.False(t, ok)

	secs, ok = dockerHealthcheckInterval(&container.HealthConfig{Test: []string{"CMD", "true"}})
	assert.True(t, ok)
	assert.Equal(t, int64(30), secs, "an unset interval is the engine default")
}

func TestDockerPortBindings(t *testing.T) {
	loose := dockerPortBindings(loadDockerInspect(t, "loose").HostConfig)
	assert.Equal(t, []dockerPortBinding{
		{hostIP: "0.0.0.0", hostPort: 8080, containerPort: 80, protocol: "tcp"},
		{hostIP: "", hostPort: 8082, containerPort: 80, protocol: "udp"},
		{hostIP: "", hostPort: 0, containerPort: 9000, protocol: "tcp"},
	}, loose)
	for _, b := range loose {
		assert.True(t, b.allInterfaces(), "%+v", b)
	}

	hard := dockerPortBindings(loadDockerInspect(t, "hardened").HostConfig)
	require.Len(t, hard, 1)
	assert.Equal(t, dockerPortBinding{hostIP: "127.0.0.1", hostPort: 8081, containerPort: 80, protocol: "tcp"}, hard[0])
	assert.False(t, hard[0].allInterfaces())

	assert.True(t, dockerPortBinding{hostIP: "::"}.allInterfaces())
	assert.False(t, dockerPortBinding{hostIP: "::1"}.allInterfaces())
	assert.Empty(t, dockerPortBindings(loadDockerInspect(t, "default").HostConfig))
}

func TestDockerMounts(t *testing.T) {
	host := dockerMounts(loadDockerInspect(t, "host"))
	require.Len(t, host, 1)
	assert.Equal(t, "bind", string(host[0].Type))
	assert.Equal(t, "/var/run/docker.sock", host[0].Source)
	assert.Equal(t, "/var/run/docker.sock", host[0].Destination)
	assert.True(t, host[0].RW)
	assert.Equal(t, "rprivate", string(host[0].Propagation))

	hard := dockerMounts(loadDockerInspect(t, "hardened"))
	require.Len(t, hard, 2)
	assert.Equal(t, "volume", string(hard[0].Type))
	assert.Equal(t, "dcs-vol", hard[0].Name)
	assert.Equal(t, "/data", hard[0].Destination)
	assert.Equal(t, "local", hard[0].Driver)
	assert.False(t, hard[0].RW)
	// --tmpfs is recorded only in HostConfig.Tmpfs
	assert.Equal(t, "tmpfs", string(hard[1].Type))
	assert.Equal(t, "/tmp", hard[1].Destination)
	assert.Equal(t, "rw,size=16m", hard[1].Mode)
	assert.True(t, hard[1].RW)

	// --mount type=tmpfs is in Mounts and must not be listed twice
	sc := dockerMounts(loadDockerInspect(t, "seccomp"))
	require.Len(t, sc, 1)
	assert.Equal(t, "/scratch", sc[0].Destination)
	assert.False(t, sc[0].RW)

	ro := dockerMounts(&container.InspectResponse{HostConfig: &container.HostConfig{Tmpfs: map[string]string{"/run": "ro,noexec"}}})
	require.Len(t, ro, 1)
	assert.False(t, ro[0].RW)

	assert.Empty(t, dockerMounts(loadDockerInspect(t, "default")))
}

func TestClassifyDockerError(t *testing.T) {
	status := http.StatusForbidden
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"refused"}`))
	}))
	defer srv.Close()

	cl, err := client.New(client.WithHost("tcp://"+srv.Listener.Addr().String()), client.WithAPIVersion("1.47"))
	require.NoError(t, err)
	defer cl.Close()

	_, err = cl.ContainerInspect(context.Background(), "abc", client.ContainerInspectOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(classifyDockerError(err), llx.ErrForbidden), "403 from the daemon: %v", err)

	status = http.StatusNotFound
	_, err = cl.ContainerInspect(context.Background(), "abc", client.ContainerInspectOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(classifyDockerError(err), llx.ErrNotFound), "404 from the daemon: %v", err)

	status = http.StatusInternalServerError
	_, err = cl.ContainerInspect(context.Background(), "abc", client.ContainerInspectOptions{})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyDockerError(err)))

	assert.NoError(t, classifyDockerError(nil))
}

// A socket the user may not open is a refusal, not a daemon that is down.
func TestClassifyDockerErrorSocketPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores socket permissions")
	}
	dir, err := os.MkdirTemp("", "dsock")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on a unix socket here: %v", err)
	}
	defer l.Close()
	require.NoError(t, os.Chmod(sock, 0o000))

	cl, err := client.New(client.WithHost("unix://"+sock), client.WithAPIVersion("1.47"))
	require.NoError(t, err)
	defer cl.Close()
	_, err = cl.ContainerInspect(context.Background(), "abc", client.ContainerInspectOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(classifyDockerError(err), llx.ErrForbidden), "%v", err)

	// a socket that does not exist is not a refusal
	cl2, err := client.New(client.WithHost("unix://"+filepath.Join(dir, "missing.sock")), client.WithAPIVersion("1.47"))
	require.NoError(t, err)
	defer cl2.Close()
	_, err = cl2.ContainerInspect(context.Background(), "abc", client.ContainerInspectOptions{})
	require.Error(t, err)
	assert.False(t, errors.Is(classifyDockerError(err), llx.ErrForbidden), "%v", err)
}

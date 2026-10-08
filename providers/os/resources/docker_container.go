// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

type mqlDockerContainerInternal struct {
	// endpoints and volumeNames come from the container listing, so the
	// network and volume edges need no call per container.
	endpoints   []dockerContainerEndpoint
	volumeNames []string

	lock       sync.Mutex
	inspected  atomic.Bool
	inspect    *container.InspectResponse
	inspectErr error
}

type mqlDockerInternal struct {
	lock             sync.Mutex
	infoFetched      atomic.Bool
	daemonSeccompVal dockerDaemonSeccomp
	daemonInfoErr    error
}

// daemonSeccomp reads the daemon's seccomp setting once per scan.
func (p *mqlDocker) daemonSeccomp() (dockerDaemonSeccomp, error) {
	if p.infoFetched.Load() {
		return p.daemonSeccompVal, p.daemonInfoErr
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.infoFetched.Load() {
		return p.daemonSeccompVal, p.daemonInfoErr
	}

	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		p.daemonInfoErr = err
	} else {
		defer cl.Close()
		info, err := cl.Info(context.Background(), client.InfoOptions{})
		if err != nil {
			p.daemonInfoErr = classifyDockerError(err)
		} else {
			p.daemonSeccompVal = parseDockerDaemonSeccomp(info.Info.SecurityOptions)
		}
	}
	p.infoFetched.Store(true)
	return p.daemonSeccompVal, p.daemonInfoErr
}

// classifyDockerError turns a refusal from the Docker daemon into a typed
// error. The client reports a socket the user may not open as a connection
// failure whose message starts with "permission denied" and drops the
// underlying os.ErrPermission, so the message is all that is left to read.
func classifyDockerError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case cerrdefs.IsPermissionDenied(err):
		return llx.Forbidden(err)
	case client.IsErrConnectionFailed(err) && strings.HasPrefix(err.Error(), "permission denied"):
		return llx.Forbidden(err)
	case cerrdefs.IsNotFound(err):
		return llx.NotFound(err)
	}
	return err
}

// loadInspect reads the container's full configuration, which the container
// listing does not carry, once per container. Every confinement field and
// hostConfig share this one call.
func (p *mqlDockerContainer) loadInspect() (*container.InspectResponse, error) {
	if p.inspected.Load() {
		return p.inspect, p.inspectErr
	}

	p.lock.Lock()
	defer p.lock.Unlock()
	if p.inspected.Load() {
		return p.inspect, p.inspectErr
	}

	p.inspect, p.inspectErr = p.fetchInspect()
	p.inspected.Store(true)
	return p.inspect, p.inspectErr
}

func (p *mqlDockerContainer) fetchInspect() (*container.InspectResponse, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	res, err := cl.ContainerInspect(context.Background(), p.Id.Data, client.ContainerInspectOptions{})
	if err != nil {
		return nil, classifyDockerError(err)
	}
	if res.Container.HostConfig == nil || res.Container.Config == nil {
		return nil, llx.MalformedData(fmt.Errorf("docker returned no configuration for container %q", p.Id.Data))
	}
	return &res.Container, nil
}

func (p *mqlDockerContainer) hostConfig() (any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(inspect.HostConfig)
}

// sourceImage resolves the container's image from the host's image list, which
// is read once for every container.
func (p *mqlDockerContainer) sourceImage() (*mqlDockerImage, error) {
	imageID := p.Imageid.Data
	if imageID != "" {
		d, err := NewResource(p.MqlRuntime, "docker", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}
		images := d.(*mqlDocker).GetImages()
		if images.Error != nil {
			return nil, images.Error
		}
		for _, x := range images.Data {
			if img, ok := x.(*mqlDockerImage); ok && img.Id.Data == imageID {
				return img, nil
			}
		}
	}
	p.SourceImage.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (p *mqlDockerContainer) privileged() (bool, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return false, err
	}
	return inspect.HostConfig.Privileged, nil
}

func (p *mqlDockerContainer) capAdd() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(normalizeCapabilityNames(inspect.HostConfig.CapAdd)), nil
}

func (p *mqlDockerContainer) capDrop() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(normalizeCapabilityNames(inspect.HostConfig.CapDrop)), nil
}

// normalizeCapabilityNames writes Linux capability names the way the engines
// apply them: upper case with the CAP_ prefix, and ALL as it is. Docker
// Engine before 23, and the containers.conf and crio.conf files, keep a name
// as it was given (`net_admin`, `NET_ADMIN`), so without this the same
// capability reads differently from host to host.
func normalizeCapabilityNames(caps []string) []string {
	res := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if c != "ALL" && !strings.HasPrefix(c, "CAP_") {
			c = "CAP_" + c
		}
		res = append(res, c)
	}
	return res
}

func (p *mqlDockerContainer) securityOptions() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.HostConfig.SecurityOpt), nil
}

func (p *mqlDockerContainer) seccompProfile() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	d, err := NewResource(p.MqlRuntime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	daemon, err := d.(*mqlDocker).daemonSeccomp()
	if err != nil {
		return "", err
	}
	return dockerSeccompProfile(inspect.HostConfig, daemon), nil
}

func (p *mqlDockerContainer) apparmorProfile() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.AppArmorProfile, nil
}

func (p *mqlDockerContainer) noNewPrivileges() (bool, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return false, err
	}
	return securityOptNoNewPrivileges(inspect.HostConfig.SecurityOpt), nil
}

func (p *mqlDockerContainer) readOnlyRootfs() (bool, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return false, err
	}
	return inspect.HostConfig.ReadonlyRootfs, nil
}

func (p *mqlDockerContainer) user() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Config.User, nil
}

func (p *mqlDockerContainer) networkMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.NetworkMode), nil
}

func (p *mqlDockerContainer) pidMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.PidMode), nil
}

func (p *mqlDockerContainer) ipcMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.IpcMode), nil
}

func (p *mqlDockerContainer) utsMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.UTSMode), nil
}

func (p *mqlDockerContainer) usernsMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.UsernsMode), nil
}

func (p *mqlDockerContainer) cgroupnsMode() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.CgroupnsMode), nil
}

func (p *mqlDockerContainer) restartPolicy() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return string(inspect.HostConfig.RestartPolicy.Name), nil
}

func (p *mqlDockerContainer) restartMaxRetries() (int64, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return 0, err
	}
	return int64(inspect.HostConfig.RestartPolicy.MaximumRetryCount), nil
}

// positiveLimit reports a resource limit, or false when the engine
// treats the value as unlimited or unset (0, a negative value, or none).
func positiveLimit(v *int64) (int64, bool) {
	if v == nil || *v <= 0 {
		return 0, false
	}
	return *v, true
}

func (p *mqlDockerContainer) limitField(field *plugin.TValue[int64], get func(*container.HostConfig) *int64) (int64, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return 0, err
	}
	v, ok := positiveLimit(get(inspect.HostConfig))
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (p *mqlDockerContainer) memoryLimit() (int64, error) {
	return p.limitField(&p.MemoryLimit, func(hc *container.HostConfig) *int64 { return &hc.Memory })
}

func (p *mqlDockerContainer) cpuShares() (int64, error) {
	return p.limitField(&p.CpuShares, func(hc *container.HostConfig) *int64 { return &hc.CPUShares })
}

func (p *mqlDockerContainer) nanoCpus() (int64, error) {
	return p.limitField(&p.NanoCpus, func(hc *container.HostConfig) *int64 { return &hc.NanoCPUs })
}

func (p *mqlDockerContainer) pidsLimit() (int64, error) {
	return p.limitField(&p.PidsLimit, func(hc *container.HostConfig) *int64 { return hc.PidsLimit })
}

func (p *mqlDockerContainer) ulimits() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, u := range inspect.HostConfig.Ulimits {
		if u == nil {
			continue
		}
		r, err := CreateResource(p.MqlRuntime, "docker.container.ulimit", map[string]*llx.RawData{
			"__id": llx.StringData("docker.container.ulimit/" + p.Id.Data + "/" + u.Name),
			"name": llx.StringData(u.Name),
			"soft": llx.IntData(u.Soft),
			"hard": llx.IntData(u.Hard),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (p *mqlDockerContainer) hasHealthcheck() (bool, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return false, err
	}
	return healthcheckDefined(inspect.Config.Healthcheck), nil
}

func (p *mqlDockerContainer) healthcheckTest() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	if inspect.Config.Healthcheck == nil {
		return []any{}, nil
	}
	return convert.SliceAnyToInterface(inspect.Config.Healthcheck.Test), nil
}

func (p *mqlDockerContainer) healthcheckInterval() (int64, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return 0, err
	}
	secs, ok := healthcheckIntervalSeconds(inspect.Config.Healthcheck)
	if !ok {
		p.HealthcheckInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return secs, nil
}

func (p *mqlDockerContainer) healthStatus() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	if inspect.State == nil || inspect.State.Health == nil || inspect.State.Health.Status == "" {
		p.HealthStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(inspect.State.Health.Status), nil
}

func (p *mqlDockerContainer) ports() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, b := range dockerPortBindings(inspect.HostConfig) {
		r, err := CreateResource(p.MqlRuntime, "docker.container.port", map[string]*llx.RawData{
			"__id":          llx.StringData(fmt.Sprintf("docker.container.port/%s/%d/%s/%s/%d", p.Id.Data, b.containerPort, b.protocol, b.hostIP, b.hostPort)),
			"hostIp":        llx.StringData(b.hostIP),
			"hostPort":      llx.IntData(b.hostPort),
			"containerPort": llx.IntData(b.containerPort),
			"protocol":      llx.StringData(b.protocol),
			"allInterfaces": llx.BoolData(b.allInterfaces()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (p *mqlDockerContainer) devices() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, d := range inspect.HostConfig.Devices {
		r, err := CreateResource(p.MqlRuntime, "docker.container.device", map[string]*llx.RawData{
			"__id":          llx.StringData("docker.container.device/" + p.Id.Data + "/" + d.PathInContainer),
			"hostPath":      llx.StringData(d.PathOnHost),
			"containerPath": llx.StringData(d.PathInContainer),
			"permissions":   llx.StringData(d.CgroupPermissions),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (p *mqlDockerContainer) mounts() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, m := range dockerMounts(inspect) {
		r, err := CreateResource(p.MqlRuntime, "docker.container.mount", map[string]*llx.RawData{
			"__id":          llx.StringData("docker.container.mount/" + p.Id.Data + "/" + m.Destination),
			"type":          llx.StringData(string(m.Type)),
			"name":          llx.StringData(m.Name),
			"hostPath":      llx.StringData(m.Source),
			"containerPath": llx.StringData(m.Destination),
			"readOnly":      llx.BoolData(!m.RW),
			"mode":          llx.StringData(m.Mode),
			"propagation":   llx.StringData(string(m.Propagation)),
			"driver":        llx.StringData(m.Driver),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// dockerDaemonSeccomp is the seccomp setting of the daemon, which applies to
// every container that names no profile of its own.
type dockerDaemonSeccomp struct {
	// supported is false when the daemon reports no seccomp support, so no
	// container it runs is filtered.
	supported bool
	// profile is "default", "unconfined", or "custom".
	profile string
}

// parseDockerDaemonSeccomp reads the daemon's seccomp setting from the
// SecurityOptions of the Engine API's /info, entries such as
// `name=seccomp,profile=builtin`. A daemon without a `name=seccomp` entry
// runs on a kernel without seccomp, and filters nothing.
func parseDockerDaemonSeccomp(securityOptions []string) dockerDaemonSeccomp {
	for _, opt := range securityOptions {
		var name, profile string
		for _, kv := range strings.Split(opt, ",") {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "name":
				name = v
			case "profile":
				profile = v
			}
		}
		if name != "seccomp" {
			continue
		}
		switch profile {
		case "", "builtin", "default":
			return dockerDaemonSeccomp{supported: true, profile: "default"}
		case "unconfined":
			return dockerDaemonSeccomp{supported: true, profile: "unconfined"}
		default:
			// a profile file on the daemon's host, which the API does not return
			return dockerDaemonSeccomp{supported: true, profile: "custom"}
		}
	}
	return dockerDaemonSeccomp{supported: false, profile: "unconfined"}
}

// dockerSeccompProfile reports the seccomp profile the container effectively
// runs with. Docker applies no seccomp filter to a privileged container, even
// when a profile was named. A container that names no profile runs with the
// daemon's. The CLI sends a custom profile's JSON content rather than its path,
// so the profile itself can be read: one that allows every system call is
// reported as unconfined.
func dockerSeccompProfile(hc *container.HostConfig, daemon dockerDaemonSeccomp) string {
	if hc != nil && hc.Privileged {
		return "unconfined"
	}
	if !daemon.supported {
		return "unconfined"
	}
	profile := daemon.profile
	if hc == nil {
		return profile
	}
	for _, opt := range hc.SecurityOpt {
		key, value, ok := splitSecurityOpt(opt)
		if !ok || key != "seccomp" {
			continue
		}
		switch value {
		case "unconfined":
			profile = "unconfined"
		case "builtin":
			profile = "default"
		case "":
			// an empty value names no profile, so the daemon's applies
		default:
			if seccompAllowsAll(value) {
				profile = "unconfined"
			} else {
				profile = "custom"
			}
		}
	}
	return profile
}

// seccompPermissiveActions are the seccomp actions that let a system
// call run.
var seccompPermissiveActions = map[string]struct{}{
	"SCMP_ACT_ALLOW": {},
	"SCMP_ACT_LOG":   {},
}

// seccompAllowsAll reports whether a seccomp profile lets every system
// call run: its default action and every rule's action allow or only log the
// call. A profile that cannot be parsed is not assumed to allow everything.
func seccompAllowsAll(profileJSON string) bool {
	var profile struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Action string `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		return false
	}
	if _, ok := seccompPermissiveActions[profile.DefaultAction]; !ok {
		return false
	}
	for _, sc := range profile.Syscalls {
		if _, ok := seccompPermissiveActions[sc.Action]; !ok {
			return false
		}
	}
	return true
}

// securityOptNoNewPrivileges reports whether the no-new-privileges security option
// is on. The daemon accepts it bare, or with a boolean value after `:` or `=`.
func securityOptNoNewPrivileges(opts []string) bool {
	enabled := false
	for _, opt := range opts {
		key, value, ok := splitSecurityOpt(opt)
		if key != "no-new-privileges" {
			continue
		}
		if !ok {
			enabled = true
			continue
		}
		b, err := strconv.ParseBool(value)
		enabled = err == nil && b
	}
	return enabled
}

// splitSecurityOpt splits a security option into its key and value. The
// daemon accepts both `key=value` and the older `key:value`.
func splitSecurityOpt(opt string) (string, string, bool) {
	if k, v, ok := strings.Cut(opt, "="); ok {
		return k, v, true
	}
	return strings.Cut(opt, ":")
}

func healthcheckDefined(hc *container.HealthConfig) bool {
	return hc != nil && len(hc.Test) > 0 && hc.Test[0] != "NONE"
}

// defaultHealthcheckInterval is the interval the engine uses when a
// health check does not set one.
const defaultHealthcheckInterval = 30 * time.Second

func healthcheckIntervalSeconds(hc *container.HealthConfig) (int64, bool) {
	if !healthcheckDefined(hc) {
		return 0, false
	}
	interval := hc.Interval
	if interval <= 0 {
		interval = defaultHealthcheckInterval
	}
	return int64(interval / time.Second), true
}

type dockerPortBinding struct {
	hostIP        string
	hostPort      int64
	containerPort int64
	protocol      string
}

func (b dockerPortBinding) allInterfaces() bool {
	return b.hostIP == "" || b.hostIP == "0.0.0.0" || b.hostIP == "::"
}

// dockerPortBindings flattens the configured port bindings, ordered by
// container port and protocol so the list is stable across scans.
func dockerPortBindings(hc *container.HostConfig) []dockerPortBinding {
	if hc == nil {
		return nil
	}
	res := []dockerPortBinding{}
	for port, bindings := range hc.PortBindings {
		for _, b := range bindings {
			hostIP := ""
			if b.HostIP.IsValid() {
				hostIP = b.HostIP.String()
			}
			hostPort, _ := strconv.ParseInt(b.HostPort, 10, 64)
			res = append(res, dockerPortBinding{
				hostIP:        hostIP,
				hostPort:      hostPort,
				containerPort: int64(port.Num()),
				protocol:      string(port.Proto()),
			})
		}
	}
	sort.Slice(res, func(i, j int) bool {
		a, b := res[i], res[j]
		if a.containerPort != b.containerPort {
			return a.containerPort < b.containerPort
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		if a.hostIP != b.hostIP {
			return a.hostIP < b.hostIP
		}
		return a.hostPort < b.hostPort
	})
	return res
}

// dockerMounts lists the container's mounts.
func dockerMounts(inspect *container.InspectResponse) []container.MountPoint {
	var tmpfs map[string]string
	if inspect.HostConfig != nil {
		tmpfs = inspect.HostConfig.Tmpfs
	}
	return containerMounts(inspect.Mounts, tmpfs)
}

// containerMounts lists the mounts Docker or Podman report for a container. A
// tmpfs mount requested with `--tmpfs` is recorded only in HostConfig.Tmpfs,
// not in Mounts, so it is added here, read-only when its options say `ro`.
func containerMounts(mounts []container.MountPoint, tmpfsMounts map[string]string) []container.MountPoint {
	res := []container.MountPoint{}
	seen := map[string]struct{}{}
	for _, m := range mounts {
		res = append(res, m)
		seen[m.Destination] = struct{}{}
	}
	tmpfs := make([]string, 0, len(tmpfsMounts))
	for dest := range tmpfsMounts {
		if _, ok := seen[dest]; !ok {
			tmpfs = append(tmpfs, dest)
		}
	}
	sort.Strings(tmpfs)
	for _, dest := range tmpfs {
		opts := tmpfsMounts[dest]
		readOnly := false
		for _, o := range strings.Split(opts, ",") {
			if o == "ro" {
				readOnly = true
			}
		}
		res = append(res, container.MountPoint{
			Type:        mount.TypeTmpfs,
			Destination: dest,
			Mode:        opts,
			RW:          !readOnly,
		})
	}
	return res
}

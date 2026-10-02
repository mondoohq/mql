// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

type mqlPodmanInternal struct {
	lock   sync.Mutex
	loaded atomic.Bool
	info   *podmanInfo
	err    error

	versionLock   sync.Mutex
	versionLoaded atomic.Bool
	engineVersion string
	versionErr    error
}

func (p *mqlPodman) id() (string, error) {
	return "podman", nil
}

// runPodman runs a podman subcommand through the command resource, so it works
// across every connection the provider supports rather than only a local one.
func runPodman(runtime *plugin.Runtime, args ...string) (string, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(shellquote.Join(append([]string{"podman"}, args...)...)),
	})
	if err != nil {
		return "", err
	}
	cmd := o.(*mqlCommand)

	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", exit.Error
	}
	if exit.Data != 0 {
		return "", fmt.Errorf("podman %s failed: %s", args[0], cmd.Stderr.Data)
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return "", stdout.Error
	}
	return stdout.Data, nil
}

// loadInfo reads the engine settings once and shares them across every field.
func (p *mqlPodman) loadInfo() (*podmanInfo, error) {
	if p.loaded.Load() {
		return p.info, p.err
	}

	p.lock.Lock()
	defer p.lock.Unlock()
	if p.loaded.Load() {
		return p.info, p.err
	}

	out, err := runPodman(p.MqlRuntime, "info", "--format", "json")
	if err == nil {
		p.info, p.err = parsePodmanInfo(out)
	} else {
		p.err = err
	}
	p.loaded.Store(true)

	return p.info, p.err
}

// installed reports whether the podman binary is on the system. The engine
// settings answer that on their own when they load, and every other field needs
// them anyway, so read them first and let the whole resource share one call. A
// binary that is present but cannot reach an engine still fails that read, so
// fall back to the version probe rather than report podman as absent.
func (p *mqlPodman) installed() (bool, error) {
	if _, err := p.loadInfo(); err == nil {
		return true, nil
	}
	if _, err := runPodman(p.MqlRuntime, "--version"); err != nil {
		log.Debug().Err(err).Msg("podman> engine not available")
		return false, nil
	}
	return true, nil
}

// loadVersion reads the podman release once. The engine settings carry it from
// podman 2.0 on; older releases, and an engine that cannot be reached, only
// answer "podman --version".
func (p *mqlPodman) loadVersion() (string, error) {
	if p.versionLoaded.Load() {
		return p.engineVersion, p.versionErr
	}

	p.versionLock.Lock()
	defer p.versionLock.Unlock()
	if p.versionLoaded.Load() {
		return p.engineVersion, p.versionErr
	}

	info, infoErr := p.loadInfo()
	if infoErr == nil && info.Version.Version != "" {
		p.engineVersion = info.Version.Version
	} else {
		out, err := runPodman(p.MqlRuntime, "--version")
		switch {
		case err != nil && infoErr != nil:
			p.versionErr = infoErr
		case err != nil:
			p.versionErr = err
		default:
			p.engineVersion = parsePodmanVersionOutput(out)
			if p.engineVersion == "" {
				p.versionErr = fmt.Errorf("cannot read the podman version from %q", out)
			}
		}
	}
	p.versionLoaded.Store(true)

	return p.engineVersion, p.versionErr
}

// checkSupported returns an error when the engine is a podman release whose
// output the podman resources cannot decode. A version that cannot be read does
// not block anything; the command that follows reports its own failure.
func (p *mqlPodman) checkSupported() error {
	version, err := p.loadVersion()
	if err != nil {
		return nil
	}
	return podmanCheckSupported(version)
}

// supportedInfo returns the engine settings of a supported podman release.
func (p *mqlPodman) supportedInfo() (*podmanInfo, error) {
	info, err := p.loadInfo()
	if err != nil {
		return nil, err
	}
	if err := p.checkSupported(); err != nil {
		return nil, err
	}
	return info, nil
}

// security returns the confinement settings the engine reports.
func (p *mqlPodman) security() (*podmanInfoSecurity, error) {
	info, err := p.supportedInfo()
	if err != nil {
		return nil, err
	}
	if info.Host.Security == nil {
		return nil, errors.New("podman info did not report security settings")
	}
	return info.Host.Security, nil
}

// checkPodmanSupported is checkSupported for code that holds only the runtime.
func checkPodmanSupported(runtime *plugin.Runtime) error {
	podman, err := CreateResource(runtime, "podman", map[string]*llx.RawData{})
	if err != nil {
		return err
	}
	return podman.(*mqlPodman).checkSupported()
}

func (p *mqlPodman) version() (string, error) {
	return p.loadVersion()
}

func (p *mqlPodman) rootless() (bool, error) {
	security, err := p.security()
	if err != nil {
		return false, err
	}
	return security.Rootless, nil
}

func (p *mqlPodman) cgroupManager() (string, error) {
	info, err := p.supportedInfo()
	if err != nil {
		return "", err
	}
	return info.Host.CgroupManager, nil
}

func (p *mqlPodman) cgroupVersion() (string, error) {
	info, err := p.loadInfo()
	if err != nil {
		return "", err
	}
	return info.Host.CgroupVersion, nil
}

func (p *mqlPodman) ociRuntime() (string, error) {
	info, err := p.loadInfo()
	if err != nil {
		return "", err
	}
	return info.Host.OciRuntime.Name, nil
}

func (p *mqlPodman) networkBackend() (string, error) {
	info, err := p.supportedInfo()
	if err != nil {
		return "", err
	}
	return info.Host.NetworkBackend, nil
}

func (p *mqlPodman) storageDriver() (string, error) {
	info, err := p.loadInfo()
	if err != nil {
		return "", err
	}
	return info.Store.GraphDriverName, nil
}

func (p *mqlPodman) seccompEnabled() (bool, error) {
	security, err := p.security()
	if err != nil {
		return false, err
	}
	return security.SeccompEnabled, nil
}

func (p *mqlPodman) seccompProfilePath() (string, error) {
	security, err := p.security()
	if err != nil {
		return "", err
	}
	return security.SeccompProfilePath, nil
}

func (p *mqlPodman) apparmorEnabled() (bool, error) {
	security, err := p.security()
	if err != nil {
		return false, err
	}
	return security.ApparmorEnabled, nil
}

func (p *mqlPodman) selinuxEnabled() (bool, error) {
	security, err := p.security()
	if err != nil {
		return false, err
	}
	return security.SelinuxEnabled, nil
}

func (p *mqlPodman) containers() ([]any, error) {
	return listPodmanContainers(p.MqlRuntime)
}

func (p *mqlPodman) images() ([]any, error) {
	return listPodmanImages(p.MqlRuntime)
}

func (p *mqlPodman) pods() ([]any, error) {
	return listPodmanPods(p.MqlRuntime)
}

func (p *mqlPodman) volumes() ([]any, error) {
	if err := p.checkSupported(); err != nil {
		return nil, err
	}

	out, err := runPodman(p.MqlRuntime, "volume", "ls", "--format", "json")
	if err != nil {
		return nil, err
	}

	entries, err := parsePodmanVolumes(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		resource, err := CreateResource(p.MqlRuntime, "podman.volume", map[string]*llx.RawData{
			"__id":       llx.StringData("podman.volume/" + entry.Name),
			"name":       llx.StringData(entry.Name),
			"driver":     llx.StringData(entry.Driver),
			"mountpoint": llx.StringData(entry.Mountpoint),
			"createdAt":  llx.TimeDataPtr(podmanParseTime(entry.CreatedAt)),
			"labels":     llx.MapData(convert.MapToInterfaceMap(entry.Labels), types.String),
			"options":    llx.MapData(convert.MapToInterfaceMap(entry.Options), types.String),
			"scope":      llx.StringData(entry.Scope),
			"anonymous":  llx.BoolData(entry.Anonymous),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (p *mqlPodman) networks() ([]any, error) {
	if err := p.checkSupported(); err != nil {
		return nil, err
	}

	out, err := runPodman(p.MqlRuntime, "network", "ls", "--format", "json")
	if err != nil {
		return nil, err
	}

	entries, err := parsePodmanNetworks(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for i := range entries {
		entry := entries[i]

		subnets := make([]any, 0, len(entry.Subnets))
		for _, subnet := range entry.Subnets {
			subnets = append(subnets, map[string]any{
				"subnet":  subnet.Subnet,
				"gateway": subnet.Gateway,
			})
		}

		resource, err := CreateResource(p.MqlRuntime, "podman.network", map[string]*llx.RawData{
			"__id":             llx.StringData("podman.network/" + entry.Name),
			"id":               llx.StringData(entry.ID),
			"name":             llx.StringData(entry.Name),
			"driver":           llx.StringData(entry.Driver),
			"networkInterface": llx.StringData(entry.NetworkInterface),
			"subnets":          llx.ArrayData(subnets, types.Dict),
			"ipv6Enabled":      llx.BoolData(entry.IPv6Enabled),
			"internal":         llx.BoolData(entry.Internal),
			"dnsEnabled":       llx.BoolData(entry.DNSEnabled),
			"createdAt":        llx.TimeDataPtr(podmanParseTime(entry.Created)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// =============================================================================
// podman.container
// =============================================================================

type mqlPodmanContainerInternal struct {
	lock       sync.Mutex
	inspected  atomic.Bool
	inspect    *podmanInspectEntry
	inspectErr error
	cachePodID string
}

func (c *mqlPodmanContainer) id() (string, error) {
	return "podman.container/" + c.Id.Data, nil
}

func listPodmanContainers(runtime *plugin.Runtime, filters ...string) ([]any, error) {
	if err := checkPodmanSupported(runtime); err != nil {
		return nil, err
	}

	args := []string{"ps", "--all", "--format", "json"}
	args = append(args, filters...)

	out, err := runPodman(runtime, args...)
	if err != nil {
		return nil, err
	}

	entries, err := parsePodmanPs(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for i := range entries {
		resource, err := newPodmanContainerResource(runtime, entries[i])
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func newPodmanContainerResource(runtime *plugin.Runtime, entry podmanPsEntry) (plugin.Resource, error) {
	ports := podmanPortDicts(entry.Ports)

	resource, err := CreateResource(runtime, "podman.container", map[string]*llx.RawData{
		"__id":      llx.StringData("podman.container/" + entry.ID),
		"id":        llx.StringData(entry.ID),
		"name":      llx.StringData(podmanPrimaryName(entry.Names)),
		"names":     llx.ArrayData(convert.SliceAnyToInterface(entry.Names), types.String),
		"imageName": llx.StringData(entry.Image),
		"imageId":   llx.StringData(entry.ImageID),
		"command":   llx.ArrayData(convert.SliceAnyToInterface(entry.Command), types.String),
		"state":     llx.StringData(entry.State),
		"status":    llx.StringData(entry.Status),
		"labels":    llx.MapData(convert.MapToInterfaceMap(entry.Labels), types.String),
		"isInfra":   llx.BoolData(entry.IsInfra),
		"exitCode":  llx.IntData(entry.ExitCode),
		"createdAt": llx.TimeDataPtr(podmanUnixTime(entry.Created)),
		"networks":  llx.ArrayData(convert.SliceAnyToInterface(entry.Networks), types.String),
		"ports":     llx.ArrayData(ports, types.Dict),
	})
	if err != nil {
		return nil, err
	}

	// the pod id comes from the listing but is resolved only when asked for
	resource.(*mqlPodmanContainer).cachePodID = entry.Pod

	return resource, nil
}

func initPodmanContainer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("cannot initialize podman.container, need at least an id")
	}
	id, ok := x.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("cannot look for a podman container with an empty id")
	}

	containers, err := listPodmanContainers(runtime, "--filter", "id="+id)
	if err != nil {
		return nil, nil, err
	}
	for _, container := range containers {
		if c, ok := container.(*mqlPodmanContainer); ok && c.Id.Data == id {
			return nil, c, nil
		}
	}

	return nil, nil, fmt.Errorf("podman.container with id %q not found", id)
}

// loadInspect reads the confinement settings, which the container listing does
// not carry, once per container.
func (c *mqlPodmanContainer) loadInspect() (*podmanInspectEntry, error) {
	if c.inspected.Load() {
		return c.inspect, c.inspectErr
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	if c.inspected.Load() {
		return c.inspect, c.inspectErr
	}

	out, err := runPodman(c.MqlRuntime, "inspect", "--type", "container", "--format", "json", c.Id.Data)
	if err != nil {
		c.inspectErr = err
	} else {
		entries, parseErr := parsePodmanInspect(out)
		switch {
		case parseErr != nil:
			c.inspectErr = parseErr
		case len(entries) == 0:
			c.inspectErr = fmt.Errorf("podman inspect returned no record for container %q", c.Id.Data)
		default:
			c.inspect = &entries[0]
		}
	}
	c.inspected.Store(true)

	return c.inspect, c.inspectErr
}

func (c *mqlPodmanContainer) privileged() (bool, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return false, err
	}
	return inspect.HostConfig.Privileged, nil
}

func (c *mqlPodmanContainer) capAdd() ([]any, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.HostConfig.CapAdd), nil
}

func (c *mqlPodmanContainer) capDrop() ([]any, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.HostConfig.CapDrop), nil
}

func (c *mqlPodmanContainer) effectiveCapabilities() ([]any, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.EffectiveCaps), nil
}

func (c *mqlPodmanContainer) boundingCapabilities() ([]any, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.BoundingCaps), nil
}

func (c *mqlPodmanContainer) securityOptions() ([]any, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.HostConfig.SecurityOpt), nil
}

func (c *mqlPodmanContainer) readOnlyRootfs() (bool, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return false, err
	}
	return inspect.HostConfig.ReadonlyRootfs, nil
}

func (c *mqlPodmanContainer) user() (string, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Config.User, nil
}

func (c *mqlPodmanContainer) networkMode() (string, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.HostConfig.NetworkMode, nil
}

func (c *mqlPodmanContainer) pidMode() (string, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.HostConfig.PidMode, nil
}

func (c *mqlPodmanContainer) usernsMode() (string, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.HostConfig.UsernsMode, nil
}

func (c *mqlPodmanContainer) restartPolicy() (string, error) {
	inspect, err := c.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.HostConfig.RestartPolicy.Name, nil
}

func (c *mqlPodmanContainer) image() (*mqlPodmanImage, error) {
	imageID := c.ImageId.Data
	if imageID == "" {
		c.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resource, err := NewResource(c.MqlRuntime, "podman.image", map[string]*llx.RawData{
		"id": llx.StringData(imageID),
	})
	if err != nil {
		// an image removed while its container survives is a real state, not a
		// query failure
		log.Debug().Err(err).Str("image", imageID).Msg("podman> cannot resolve container image")
		c.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return resource.(*mqlPodmanImage), nil
}

func (c *mqlPodmanContainer) pod() (*mqlPodmanPod, error) {
	if c.cachePodID == "" {
		c.Pod.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resource, err := NewResource(c.MqlRuntime, "podman.pod", map[string]*llx.RawData{
		"id": llx.StringData(c.cachePodID),
	})
	if err != nil {
		log.Debug().Err(err).Str("pod", c.cachePodID).Msg("podman> cannot resolve container pod")
		c.Pod.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return resource.(*mqlPodmanPod), nil
}

// =============================================================================
// podman.image
// =============================================================================

func (i *mqlPodmanImage) id() (string, error) {
	return "podman.image/" + i.Id.Data, nil
}

func listPodmanImages(runtime *plugin.Runtime, filters ...string) ([]any, error) {
	if err := checkPodmanSupported(runtime); err != nil {
		return nil, err
	}

	args := []string{"images", "--format", "json"}
	args = append(args, filters...)

	out, err := runPodman(runtime, args...)
	if err != nil {
		return nil, err
	}

	entries, err := parsePodmanImages(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for i := range entries {
		resource, err := newPodmanImageResource(runtime, entries[i])
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func newPodmanImageResource(runtime *plugin.Runtime, entry podmanImageEntry) (plugin.Resource, error) {
	repository, tag := podmanImageRepoTag(entry)

	return CreateResource(runtime, "podman.image", map[string]*llx.RawData{
		"__id":         llx.StringData("podman.image/" + entry.ID),
		"id":           llx.StringData(entry.ID),
		"names":        llx.ArrayData(convert.SliceAnyToInterface(entry.Names), types.String),
		"repository":   llx.StringData(repository),
		"tag":          llx.StringData(tag),
		"repoDigests":  llx.ArrayData(convert.SliceAnyToInterface(entry.RepoDigests), types.String),
		"digest":       llx.StringData(entry.Digest),
		"size":         llx.IntData(entry.Size),
		"labels":       llx.MapData(convert.MapToInterfaceMap(entry.Labels), types.String),
		"os":           llx.StringData(entry.Os),
		"architecture": llx.StringData(entry.Architecture),
		"createdAt":    llx.TimeDataPtr(podmanUnixTime(entry.Created)),
	})
}

func initPodmanImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("cannot initialize podman.image, need at least an id")
	}
	id, ok := x.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("cannot look for a podman image with an empty id")
	}

	images, err := listPodmanImages(runtime, "--filter", "id="+id)
	if err != nil {
		return nil, nil, err
	}
	for _, image := range images {
		if i, ok := image.(*mqlPodmanImage); ok && i.Id.Data == id {
			return nil, i, nil
		}
	}

	return nil, nil, fmt.Errorf("podman.image with id %q not found", id)
}

// =============================================================================
// podman.pod
// =============================================================================

type mqlPodmanPodInternal struct {
	cacheInfraID string
}

func (p *mqlPodmanPod) id() (string, error) {
	return "podman.pod/" + p.Id.Data, nil
}

func listPodmanPods(runtime *plugin.Runtime, filters ...string) ([]any, error) {
	if err := checkPodmanSupported(runtime); err != nil {
		return nil, err
	}

	args := []string{"pod", "ps", "--format", "json"}
	args = append(args, filters...)

	out, err := runPodman(runtime, args...)
	if err != nil {
		return nil, err
	}

	entries, err := parsePodmanPods(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for i := range entries {
		resource, err := newPodmanPodResource(runtime, entries[i])
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func newPodmanPodResource(runtime *plugin.Runtime, entry podmanPodEntry) (plugin.Resource, error) {
	resource, err := CreateResource(runtime, "podman.pod", map[string]*llx.RawData{
		"__id":      llx.StringData("podman.pod/" + entry.ID),
		"id":        llx.StringData(entry.ID),
		"name":      llx.StringData(entry.Name),
		"status":    llx.StringData(entry.Status),
		"createdAt": llx.TimeDataPtr(podmanParseTime(entry.Created)),
		"labels":    llx.MapData(convert.MapToInterfaceMap(entry.Labels), types.String),
	})
	if err != nil {
		return nil, err
	}

	resource.(*mqlPodmanPod).cacheInfraID = entry.InfraID

	return resource, nil
}

func initPodmanPod(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("cannot initialize podman.pod, need at least an id")
	}
	id, ok := x.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("cannot look for a podman pod with an empty id")
	}

	pods, err := listPodmanPods(runtime, "--filter", "id="+id)
	if err != nil {
		return nil, nil, err
	}
	for _, pod := range pods {
		if p, ok := pod.(*mqlPodmanPod); ok && p.Id.Data == id {
			return nil, p, nil
		}
	}

	return nil, nil, fmt.Errorf("podman.pod with id %q not found", id)
}

func (p *mqlPodmanPod) containers() ([]any, error) {
	return listPodmanContainers(p.MqlRuntime, "--filter", "pod="+p.Id.Data)
}

func (p *mqlPodmanPod) infraContainer() (*mqlPodmanContainer, error) {
	if p.cacheInfraID == "" {
		p.InfraContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resource, err := NewResource(p.MqlRuntime, "podman.container", map[string]*llx.RawData{
		"id": llx.StringData(p.cacheInfraID),
	})
	if err != nil {
		log.Debug().Err(err).Str("container", p.cacheInfraID).Msg("podman> cannot resolve infra container")
		p.InfraContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return resource.(*mqlPodmanContainer), nil
}

// =============================================================================
// podman.volume and podman.network
// =============================================================================

func (v *mqlPodmanVolume) id() (string, error) {
	return "podman.volume/" + v.Name.Data, nil
}

func (n *mqlPodmanNetwork) id() (string, error) {
	return "podman.network/" + n.Name.Data, nil
}

// podmanNameArg reads the single name argument an init was given.
func podmanNameArg(resource string, args map[string]*llx.RawData) (string, error) {
	x, ok := args["name"]
	if !ok {
		return "", fmt.Errorf("cannot initialize %s, need at least a name", resource)
	}
	name, ok := x.Value.(string)
	if !ok || name == "" {
		return "", fmt.Errorf("cannot look for a %s with an empty name", resource)
	}
	return name, nil
}

func initPodmanVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	name, err := podmanNameArg("podman.volume", args)
	if err != nil {
		return nil, nil, err
	}

	podman, err := CreateResource(runtime, "podman", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	volumes := podman.(*mqlPodman).GetVolumes()
	if volumes.Error != nil {
		return nil, nil, volumes.Error
	}

	for _, volume := range volumes.Data {
		if v, ok := volume.(*mqlPodmanVolume); ok && v.Name.Data == name {
			return nil, v, nil
		}
	}

	return nil, nil, fmt.Errorf("podman.volume with name %q not found", name)
}

func initPodmanNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	name, err := podmanNameArg("podman.network", args)
	if err != nil {
		return nil, nil, err
	}

	podman, err := CreateResource(runtime, "podman", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	networks := podman.(*mqlPodman).GetNetworks()
	if networks.Error != nil {
		return nil, nil, networks.Error
	}

	for _, network := range networks.Data {
		if n, ok := network.(*mqlPodmanNetwork); ok && n.Name.Data == name {
			return nil, n, nil
		}
	}

	return nil, nil, fmt.Errorf("podman.network with name %q not found", name)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/image"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

type mqlDockerImageInternal struct {
	lock       sync.Mutex
	inspected  atomic.Bool
	inspect    *image.InspectResponse
	inspectErr error
}

// loadInspect reads the image's configuration, which the image listing does
// not carry, once per image. Every configuration field shares this one call.
func (p *mqlDockerImage) loadInspect() (*image.InspectResponse, error) {
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

func (p *mqlDockerImage) fetchInspect() (*image.InspectResponse, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	res, err := cl.ImageInspect(context.Background(), p.Id.Data)
	if err != nil {
		return nil, classifyDockerError(err)
	}
	return &res.InspectResponse, nil
}

// loadImageConfig returns the image's run configuration. An image without
// one, such as an imported root filesystem, reads as the empty configuration:
// no user, no command, no health check.
func (p *mqlDockerImage) loadImageConfig() (*dockerspec.DockerOCIImageConfig, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return dockerImageConfig(inspect), nil
}

func dockerImageConfig(inspect *image.InspectResponse) *dockerspec.DockerOCIImageConfig {
	if inspect == nil || inspect.Config == nil {
		return &dockerspec.DockerOCIImageConfig{}
	}
	return inspect.Config
}

// dockerImageCreated parses the image's build time. The engine omits it when
// the image does not record one.
func dockerImageCreated(created string) (*time.Time, error) {
	if created == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse image creation time %q: %w", created, err))
	}
	return &t, nil
}

// sortedPorts lists the declared ports in a stable order.
func sortedPorts(ports map[string]struct{}) []any {
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return convert.SliceAnyToInterface(keys)
}

// imageUserIsRoot reports whether an image's USER runs as root: an empty user,
// or a user part (before any `:group`) of `0` or `root`.
func imageUserIsRoot(user string) bool {
	u, _, _ := strings.Cut(user, ":")
	return isRootUser(u)
}

func (p *mqlDockerImage) createdAt() (*time.Time, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	t, err := dockerImageCreated(inspect.Created)
	if err != nil {
		return nil, err
	}
	if t == nil {
		p.CreatedAt.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return t, nil
}

func (p *mqlDockerImage) author() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Author, nil
}

func (p *mqlDockerImage) os() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Os, nil
}

func (p *mqlDockerImage) architecture() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Architecture, nil
}

func (p *mqlDockerImage) variant() (string, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return "", err
	}
	return inspect.Variant, nil
}

func (p *mqlDockerImage) user() (string, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return "", err
	}
	return cfg.User, nil
}

func (p *mqlDockerImage) runsAsRoot() (bool, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return false, err
	}
	return imageUserIsRoot(cfg.User), nil
}

func (p *mqlDockerImage) entrypoint() ([]any, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(cfg.Entrypoint), nil
}

func (p *mqlDockerImage) cmd() ([]any, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(cfg.Cmd), nil
}

func (p *mqlDockerImage) workingDir() (string, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return "", err
	}
	return cfg.WorkingDir, nil
}

func (p *mqlDockerImage) exposedPorts() ([]any, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return nil, err
	}
	return sortedPorts(cfg.ExposedPorts), nil
}

func (p *mqlDockerImage) hasHealthcheck() (bool, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return false, err
	}
	return healthcheckDefined(cfg.Healthcheck), nil
}

func (p *mqlDockerImage) healthcheckTest() ([]any, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Healthcheck == nil {
		return []any{}, nil
	}
	return convert.SliceAnyToInterface(cfg.Healthcheck.Test), nil
}

func (p *mqlDockerImage) healthcheckInterval() (int64, error) {
	cfg, err := p.loadImageConfig()
	if err != nil {
		return 0, err
	}
	secs, ok := healthcheckIntervalSeconds(cfg.Healthcheck)
	if !ok {
		p.HealthcheckInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return secs, nil
}

func (p *mqlDockerImage) layers() ([]any, error) {
	inspect, err := p.loadInspect()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(inspect.RootFS.Layers), nil
}

// containers lists the host's containers created from this image, from the
// container list every image shares.
func (p *mqlDockerImage) containers() ([]any, error) {
	d, err := NewResource(p.MqlRuntime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := d.(*mqlDocker).GetContainers()
	if all.Error != nil {
		return nil, all.Error
	}
	res := []any{}
	for _, x := range all.Data {
		if c, ok := x.(*mqlDockerContainer); ok && c.Imageid.Data == p.Id.Data {
			res = append(res, c)
		}
	}
	return res, nil
}

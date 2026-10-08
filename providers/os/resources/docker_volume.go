// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// dockerAnonymousVolumeLabel is the label Docker Engine 23.0 and later set on
// a volume it creates for a container's unnamed volume.
const dockerAnonymousVolumeLabel = "com.docker.volume.anonymous"

func dockerVolumeAnonymous(v volume.Volume) bool {
	_, ok := v.Labels[dockerAnonymousVolumeLabel]
	return ok
}

// dockerVolumeCreated parses a volume's creation time. A volume driver may
// leave it out or report it in its own format; either reads as unknown rather
// than failing the whole volume list.
func dockerVolumeCreated(created string) *time.Time {
	if created == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		log.Debug().Err(err).Str("created", created).Msg("docker> cannot parse volume creation time")
		return nil
	}
	return &t
}

// dockerContainerVolumeNames lists the volumes a container from the container
// listing mounts.
func dockerContainerVolumeNames(c container.Summary) []string {
	res := []string{}
	for _, m := range c.Mounts {
		if m.Type == mount.TypeVolume && m.Name != "" {
			res = append(res, m.Name)
		}
	}
	return res
}

func (p *mqlDocker) volumes() ([]any, error) {
	cl, err := dockerClient(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	list, err := cl.VolumeList(context.Background(), client.VolumeListOptions{})
	if err != nil {
		return nil, classifyDockerError(err)
	}

	res := make([]any, 0, len(list.Items))
	for _, v := range list.Items {
		r, err := CreateResource(p.MqlRuntime, "docker.volume", map[string]*llx.RawData{
			"name":       llx.StringData(v.Name),
			"driver":     llx.StringData(v.Driver),
			"mountpoint": llx.StringData(v.Mountpoint),
			"createdAt":  llx.TimeDataPtr(dockerVolumeCreated(v.CreatedAt)),
			"labels":     llx.MapData(convert.MapToInterfaceMap(v.Labels), types.String),
			"options":    llx.MapData(convert.MapToInterfaceMap(v.Options), types.String),
			"scope":      llx.StringData(v.Scope),
			"anonymous":  llx.BoolData(dockerVolumeAnonymous(v)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (p *mqlDockerVolume) id() (string, error) {
	return "docker.volume/" + p.Name.Data, nil
}

// containers lists the containers that mount the volume, from the container
// list every volume shares.
func (p *mqlDockerVolume) containers() ([]any, error) {
	all, err := dockerHostContainers(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, c := range all {
		for _, name := range c.volumeNames {
			if name == p.Name.Data {
				res = append(res, c)
				break
			}
		}
	}
	return res, nil
}

func initDockerVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	name, err := podmanNameArg("docker.volume", args)
	if err != nil {
		return nil, nil, err
	}

	d, err := NewResource(runtime, "docker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	volumes := d.(*mqlDocker).GetVolumes()
	if volumes.Error != nil {
		return nil, nil, volumes.Error
	}
	for _, x := range volumes.Data {
		if v, ok := x.(*mqlDockerVolume); ok && v.Name.Data == name {
			return nil, v, nil
		}
	}
	return nil, nil, fmt.Errorf("docker.volume with name %q not found", name)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

func (r *mqlDigitalocean) microDroplets() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	instances, err := paginate(context.Background(), client.MicroVMs.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(instances))
	for i := range instances {
		args, err := microDropletArgs(&instances[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.microDroplet", args)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// microDropletArgs maps a MicroVM to its MQL fields. DigitalOcean renamed the
// product from MicroDroplets to MicroVMs; the resource keeps its shipped name.
//
// The optional blocks are decoded to the reading that holds when they are
// absent rather than to a null: a MicroDroplet with no auto-pause block does
// not pause itself, and saying so as false keeps an assertion over these
// fields from passing on an instance nothing was read from.
func microDropletArgs(md *godo.MicroVM) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.microDroplet", md.ID)
	if err != nil {
		return nil, err
	}

	autoPauseEnabled := false
	autoPauseIdleTimeout := ""
	if md.AutoPause != nil {
		autoPauseEnabled = md.AutoPause.Enabled != nil && *md.AutoPause.Enabled
		autoPauseIdleTimeout = md.AutoPause.IdleTimeout
	}

	image := ""
	if md.Source != nil {
		image = md.Source.OCIRef
	}

	vcpus, memoryMib, diskGb := microVMSizeArgs(md.Size)

	return map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"id":                   llx.StringData(md.ID),
		"name":                 llx.StringData(md.Name),
		"region":               llx.StringData(md.Region),
		"state":                llx.StringData(string(md.State)),
		"size":                 llx.NilData,
		"vcpus":                vcpus,
		"memoryMib":            memoryMib,
		"diskGb":               diskGb,
		"ports":                llx.ArrayData(microVMPorts(md.Ports), "\x05"),
		"urls":                 llx.ArrayData(microVMURLs(md.URLs), "\x13"),
		"httpProtocol":         llx.StringData(string(md.HTTPProtocol)),
		"tags":                 llx.ArrayData(toStringSlice(md.Tags), "\x02"),
		"failureReason":        llx.StringData(md.FailureReason),
		"networking":           llx.StringData(string(md.Networking)),
		"image":                llx.StringData(image),
		"endpoint":             llx.StringData(microVMEndpoint(md.URLs)),
		"autoPauseEnabled":     llx.BoolData(autoPauseEnabled),
		"autoPauseIdleTimeout": llx.StringData(autoPauseIdleTimeout),
		"autoResumeEnabled":    llx.BoolData(md.AutoResume != nil && *md.AutoResume),
		"createdAt":            llx.TimeDataPtr(parseDoTime(md.Created)),
	}, nil
}

func initDigitaloceanMicroDroplet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		return nil, nil, errors.New("digitalocean.microDroplet requires an id")
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	md, _, err := conn.Client().MicroVMs.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// Returning no resource and no error here would have the runtime build a
	// blank MicroDroplet from the id alone, leaving every other field unset.
	if md == nil {
		return nil, nil, fmt.Errorf("digitalocean.microDroplet with id %q not found", id)
	}
	mdArgs, err := microDropletArgs(md)
	if err != nil {
		return nil, nil, err
	}
	return mdArgs, nil, nil
}

// microDropletIsPublic reports whether an instance answers on an address
// reachable from the internet.
//
// Only a VPC placement makes an instance private. Every other value,
// including a mode the API does not name, counts as reachable, so an
// instance whose placement cannot be established is reported as exposed
// rather than quietly passing an exposure check.
func microDropletIsPublic(networking godo.MicroVMNetworking) bool {
	return !strings.EqualFold(string(networking), string(godo.MicroVMNetworkingVPC))
}

// microVMEndpoint returns the hostname the instance serves traffic on: the
// URL marked default, or the first one when none is.
func microVMEndpoint(urls []godo.MicroVMURL) string {
	for _, u := range urls {
		if u.Default {
			return u.Hostname
		}
	}
	if len(urls) > 0 {
		return urls[0].Hostname
	}
	return ""
}

func (r *mqlDigitaloceanMicroDroplet) isPublic() (bool, error) {
	return microDropletIsPublic(godo.MicroVMNetworking(r.Networking.Data)), nil
}

// microVMPorts converts the container ports an instance exposes.
func microVMPorts(ports []uint32) []any {
	out := make([]any, 0, len(ports))
	for _, p := range ports {
		out = append(out, int64(p))
	}
	return out
}

// microVMURLs converts the ingress URLs of an instance to dicts.
func microVMURLs(urls []godo.MicroVMURL) []any {
	out := make([]any, 0, len(urls))
	for _, u := range urls {
		out = append(out, map[string]any{
			"hostname": u.Hostname,
			"port":     int64(u.Port),
			"default":  u.Default,
			"status":   string(u.Status),
		})
	}
	return out
}

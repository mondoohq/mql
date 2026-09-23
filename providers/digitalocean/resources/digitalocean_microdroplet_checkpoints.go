// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// mqlDigitaloceanMicroDropletCheckpointInternal keeps the id of the
// MicroDroplet a checkpoint was captured from, so microDroplet() and the
// per-instance checkpoints() can match against the cached lists.
type mqlDigitaloceanMicroDropletCheckpointInternal struct {
	microVMID string
}

// microVMSizeArgs maps an optional MicroVM size to its three fields, all
// null when the size is absent.
func microVMSizeArgs(size *godo.MicroVMSize) (vcpus, memoryMib, diskGb *llx.RawData) {
	if size == nil {
		return llx.NilData, llx.NilData, llx.NilData
	}
	return llx.IntData(int64(size.CPU)), llx.IntData(int64(size.Memory)), llx.IntData(int64(size.Disk))
}

// listMicroVMCheckpoints walks every checkpoint of the team.
func listMicroVMCheckpoints(ctx context.Context, svc godo.MicroVMsService) ([]godo.MicroVMCheckpoint, error) {
	return paginate(ctx, func(ctx context.Context, opt *godo.ListOptions) ([]godo.MicroVMCheckpoint, *godo.Response, error) {
		return svc.ListCheckpoints(ctx, &godo.ListMicroVMCheckpointsOptions{ListOptions: *opt})
	})
}

func microDropletCheckpointArgs(cp *godo.MicroVMCheckpoint) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.microDroplet.checkpoint", cp.ID)
	if err != nil {
		return nil, err
	}
	vcpus, memoryMib, diskGb := microVMSizeArgs(cp.Size)
	return map[string]*llx.RawData{
		"__id":             llx.StringData(id),
		"id":               llx.StringData(cp.ID),
		"name":             llx.StringData(cp.Name),
		"region":           llx.StringData(cp.Region),
		"status":           llx.StringData(string(cp.Status)),
		"microDropletName": llx.StringData(cp.MicroVMName),
		"memoryBytes":      llx.IntData(int64(cp.MemoryBytes)),
		"diskBytes":        llx.IntData(int64(cp.DiskBytes)),
		"vcpus":            vcpus,
		"memoryMib":        memoryMib,
		"diskGb":           diskGb,
		"createdAt":        llx.TimeDataPtr(parseDoTime(cp.Created)),
	}, nil
}

func (r *mqlDigitalocean) microDropletCheckpoints() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	checkpoints, err := listMicroVMCheckpoints(context.Background(), conn.Client().MicroVMs)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(checkpoints))
	for i := range checkpoints {
		args, err := microDropletCheckpointArgs(&checkpoints[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.microDroplet.checkpoint", args)
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanMicroDropletCheckpoint).microVMID = checkpoints[i].MicroVMID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanMicroDropletCheckpoint) id() (string, error) {
	return r.Id.Data, nil
}

// microDroplet resolves the source instance from the cached MicroDroplet
// list. A checkpoint outlives the instance it was taken from, so a miss is
// a real answer (the instance is gone) and resolves to null.
func (r *mqlDigitaloceanMicroDropletCheckpoint) microDroplet() (*mqlDigitaloceanMicroDroplet, error) {
	if r.microVMID == "" {
		r.MicroDroplet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	instances := parent.GetMicroDroplets()
	if instances.Error != nil {
		return nil, instances.Error
	}
	if md := findMicroDroplet(instances.Data, r.microVMID); md != nil {
		return md, nil
	}
	r.MicroDroplet.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// findMicroDroplet returns the listed instance with the given id, or nil.
func findMicroDroplet(instances []any, id string) *mqlDigitaloceanMicroDroplet {
	for _, x := range instances {
		if md, ok := x.(*mqlDigitaloceanMicroDroplet); ok && md.Id.Data == id {
			return md
		}
	}
	return nil
}

// checkpoints filters the account-wide checkpoint list down to the ones
// captured from this instance, so N instances cost one list walk.
func (r *mqlDigitaloceanMicroDroplet) checkpoints() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	all := parent.GetMicroDropletCheckpoints()
	if all.Error != nil {
		return nil, all.Error
	}
	return checkpointsOf(all.Data, r.Id.Data), nil
}

// checkpointsOf returns the checkpoints captured from the given instance.
func checkpointsOf(checkpoints []any, microVMID string) []any {
	out := []any{}
	if microVMID == "" {
		return out
	}
	for _, x := range checkpoints {
		if cp, ok := x.(*mqlDigitaloceanMicroDropletCheckpoint); ok && cp.microVMID == microVMID {
			out = append(out, cp)
		}
	}
	return out
}

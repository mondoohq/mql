// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// sharedVpcTopology is the project's position in the Shared VPC graph, resolved
// once and shared by every accessor that reports on it.
type sharedVpcTopology struct {
	// hostProject is the project lending its networks to this one, empty when
	// this project is not a service project.
	hostProject string
	// serviceProjects are the projects using this project's networks, empty
	// unless this project is a host.
	serviceProjects []string
}

// sharedVpcState caches the resolved topology on the compute service resource.
// Both booleans and both accessors read from one pair of API calls.
//
// This uses double-check locking rather than the sync.Once that the
// service-enabled gates use. The two shapes mark different jobs: sync.Once for a
// gate that mirrors the provider-wide convention in asset.go and its siblings,
// double-check locking with an atomic flag for a lazily fetched data cache, which
// is what the whoCan analysis and effective org policy caches also use.
type sharedVpcState struct {
	topology *sharedVpcTopology
	err      error
	loaded   atomic.Bool
	lock     sync.Mutex
}

// sharedVpc resolves the project's Shared VPC topology.
//
// Two calls are needed because the two directions are separate endpoints and a
// project can be neither, one, or (for a host that is itself attached elsewhere)
// reported by both. GetXpnHost returns the host project of a service project;
// GetXpnResources returns the resources attached to a host.
func (g *mqlGcpProjectComputeService) sharedVpc() (*sharedVpcTopology, error) {
	if g.sharedVpcState.loaded.Load() {
		return g.sharedVpcState.topology, g.sharedVpcState.err
	}
	g.sharedVpcState.lock.Lock()
	defer g.sharedVpcState.lock.Unlock()
	if g.sharedVpcState.loaded.Load() {
		return g.sharedVpcState.topology, g.sharedVpcState.err
	}
	defer g.sharedVpcState.loaded.Store(true)

	g.sharedVpcState.topology, g.sharedVpcState.err = g.fetchSharedVpc()
	return g.sharedVpcState.topology, g.sharedVpcState.err
}

func (g *mqlGcpProjectComputeService) fetchSharedVpc() (*sharedVpcTopology, error) {
	enabled, err := g.enabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return &sharedVpcTopology{}, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	out := &sharedVpcTopology{}

	// A project with no host returns an empty project rather than an error, so an
	// empty name means "not a service project" and is not a failure.
	if host, err := computeSvc.Projects.GetXpnHost(projectId).Context(ctx).Do(); err != nil {
		if !isSkippable(err) {
			return nil, err
		}
		log.Debug().Err(err).Str("project", projectId).Msg("could not read Shared VPC host project")
	} else if host != nil {
		out.hostProject = host.Name
	}

	if err := computeSvc.Projects.GetXpnResources(projectId).Pages(ctx, func(page *compute.ProjectsGetXpnResources) error {
		for _, r := range page.Resources {
			// Only PROJECT-type resources name a service project; the field is a
			// discriminated union and other types are not projects.
			if r == nil || r.Type != "PROJECT" || r.Id == "" {
				continue
			}
			out.serviceProjects = append(out.serviceProjects, r.Id)
		}
		return nil
	}); err != nil {
		if !isSkippable(err) && !isNotSharedVpcHost(err) {
			return nil, err
		}
		log.Debug().Err(err).Str("project", projectId).Msg("could not read Shared VPC service projects")
	}

	return out, nil
}

// isNotSharedVpcHost reports whether the error is Compute's way of saying the
// project simply is not a Shared VPC host. GetXpnResources answers that case
// with HTTP 400 invalidResourceUsage rather than an empty list, so without this
// the common case (a project that hosts nothing) fails every Shared VPC
// accessor instead of reporting false.
func isNotSharedVpcHost(err error) bool {
	gerr, ok := err.(*googleapi.Error)
	if !ok || gerr.Code != http.StatusBadRequest {
		return false
	}
	if strings.Contains(gerr.Message, "is not a shared VPC host project") {
		return true
	}
	for _, e := range gerr.Errors {
		if e.Reason == "invalidResourceUsage" {
			return true
		}
	}
	return false
}

// isSharedVpcHost reports whether other projects run workloads on this project's
// networks.
func (g *mqlGcpProjectComputeService) isSharedVpcHost() (bool, error) {
	topology, err := g.sharedVpc()
	if err != nil {
		return false, err
	}
	return len(topology.serviceProjects) > 0, nil
}

// isSharedVpcServiceProject reports whether this project's workloads run on
// another project's networks.
func (g *mqlGcpProjectComputeService) isSharedVpcServiceProject() (bool, error) {
	topology, err := g.sharedVpc()
	if err != nil {
		return false, err
	}
	return topology.hostProject != "", nil
}

// sharedVpcHost resolves the project that owns the networks this project's
// workloads sit on, so a review can follow the edge to the firewall rules and
// subnets that actually apply.
func (g *mqlGcpProjectComputeService) sharedVpcHost() (*mqlGcpProject, error) {
	topology, err := g.sharedVpc()
	if err != nil {
		return nil, err
	}
	if topology.hostProject == "" {
		g.SharedVpcHost.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(topology.hostProject),
	})
	if err != nil {
		// The caller can be permitted to see the host project's name without
		// being permitted to read the project itself.
		log.Debug().Err(err).Str("host", topology.hostProject).Msg("could not resolve Shared VPC host project")
		g.SharedVpcHost.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlGcpProject), nil
}

// sharedVpcServiceProjects resolves the projects whose workloads this project's
// network configuration governs, the blast radius of its firewall rules.
func (g *mqlGcpProjectComputeService) sharedVpcServiceProjects() ([]any, error) {
	topology, err := g.sharedVpc()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(topology.serviceProjects))
	for _, id := range topology.serviceProjects {
		project, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// Skip a service project the caller cannot read rather than failing the
			// whole list; the attachment is still reported by isSharedVpcHost.
			log.Debug().Err(err).Str("project", id).Msg("could not resolve Shared VPC service project")
			continue
		}
		res = append(res, project)
	}
	return res, nil
}

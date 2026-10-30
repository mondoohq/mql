// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// serviceGate answers "is this API enabled on this project" once per service
// resource, from whichever construction path reaches it first.
//
// The problem it exists to make impossible: a gcp.project.<service> resource is
// reachable three ways -- through the gcp.project.<service>() accessor, by its
// own type name (gcp.project.cloudRunService.services), or built by another
// resource's init with CreateResource -- and only the first of those knows
// whether the API is enabled. A resource that stores that answer in a plain
// bool therefore reads the Go zero value `false` on the other two paths, and
// every collection on it returns an empty list with no error.
//
// An empty list is the worst possible wrong answer here. It is an authoritative
// "there is nothing in this project", so a posture check over it passes
// vacuously rather than failing or erroring. This was verified live: with the
// bare flag, gcp.project.cloudRunService.services returned [] while
// gcp.project.cloudRun.services returned the real service.
//
// Embed this in the resource's Internal struct and the resolution comes with
// it, so a new service cannot reintroduce the bug by forgetting to copy 25
// lines:
//
//	type mqlGcpProjectBatchServiceInternal struct {
//		serviceGate
//	}
//
//	func (g *mqlGcpProjectBatchService) isEnabled() (bool, error) {
//		return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_batch)
//	}
type serviceGate struct {
	once    sync.Once
	enabled bool
	err     error
}

// resolveEnabled reports whether service is enabled on the project, resolving
// it at most once. It is safe to call from concurrent field accessors.
//
// A resolution failure -- a serviceusage permission gap, the Service Usage API
// itself disabled, the phantom empty-project-id discovery asset -- is returned,
// never folded into `false`. Callers must propagate it: reporting "nothing
// here" for a project that was never successfully checked is the vacuous-pass
// failure this whole type exists to prevent.
func (s *serviceGate) resolveEnabled(runtime *plugin.Runtime, projectId plugin.TValue[string], service string) (bool, error) {
	s.once.Do(func() {
		if projectId.Error != nil {
			s.err = projectId.Error
			return
		}
		// NewResource, not CreateResource, for the reason spelled out on
		// serviceEnabledForInit below: CreateResource would cache a gcp.project
		// holding nothing but an id, and NewResource returns whatever is already
		// cached even after building the full record -- so a husk cached here
		// wins for every later caller, and its name/state/parentId/labels/
		// createTime/number are placeholders that only ever return
		// "not implemented".
		proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
			"id": llx.StringData(projectId.Data),
		})
		if err != nil {
			s.err = err
			return
		}
		s.enabled, s.err = proj.(*mqlGcpProject).isServiceEnabled(service)
	})
	return s.enabled, s.err
}

// recordEnabled stores an answer the gcp.project.<service>() accessor already
// computed, so the common path does not pay for a second lookup.
//
// It claims the same sync.Once rather than writing the field directly, which is
// what makes it race-free against a concurrent resolveEnabled: whichever call
// arrives first wins and the other becomes a no-op. Both compute the same
// answer, so the order does not matter -- except that a resolveEnabled which
// already failed keeps its error rather than having it overwritten by a later
// recordEnabled.
func (s *serviceGate) recordEnabled(enabled bool) {
	s.once.Do(func() {
		s.enabled = enabled
	})
}

// serviceEnabledForInit reports whether service is enabled on projectId.
//
// The serviceGate above is embedded in a service resource's Internal struct,
// which init functions cannot use: they are plain functions with no receiver to
// hang state on. They need the check just as much, though, and for a more
// expensive reason -- an init that goes straight to a per-resource Get against a
// disabled API fails, and the failure is not cached, so it is repeated for every
// referrer on every asset. One scan of a project with Vertex AI and Memcache
// switched off spent 1,050 calls that way, 40% of all its API traffic, on five
// Get methods that could not have succeeded.
//
// The answer is memoized on the gcp.project resource (sync.Once around the
// enabled-services map), and gcp.project is itself cached by id, so this costs
// at most one ServiceUsage call per project no matter how many inits ask.
//
// NewResource, not CreateResource. CreateResource would build a gcp.project
// carrying nothing but an id and cache it under that id, and initGcpProject
// hands whatever is cached to every later caller -- so whichever ran first
// decided what everyone got. A stub does not fill itself in later either: name,
// state, parentId, labels, createTime and number are declared as computed
// fields but implemented as placeholders that return "not implemented", because
// they are meant to be populated by the init. Asking whether an API is enabled
// must therefore resolve the project properly rather than leave a husk behind.
// It costs one Projects.Get per project, which initGcpProject then caches.
//
// A resolution failure is returned rather than folded into false, for the same
// reason resolveEnabled does it: reporting "not enabled" for a project that was
// never successfully checked would turn an unknown into a confident wrong answer.
func serviceEnabledForInit(runtime *plugin.Runtime, projectId, service string) (bool, error) {
	if projectId == "" {
		return false, errors.New("project id required to check whether " + service + " is enabled")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectId),
	})
	if err != nil {
		return false, err
	}
	p, ok := proj.(*mqlGcpProject)
	if !ok {
		return false, errors.New("unexpected resource type for gcp.project")
	}
	return p.isServiceEnabled(service)
}

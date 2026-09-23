// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strconv"
	"sync"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// discoveredProjects holds the projects discovery already listed, so the
// per-asset connections it spawns do not each re-fetch their own.
//
// Discovery finds project assets by listing a group's projects, and that
// listing returns the full project object. Every asset it emits then builds its
// own GitLabConnection, whose Project() did a GetProject for the record
// discovery already had: on a 36-project group that was 36 of the scan's 41
// remaining API calls.
//
// The resource cache cannot serve this. It is attached to a child runtime only
// after Connect() returns (plugin/service.go), so detect() -- which runs inside
// Connect() -- has nothing to read, and the MQL gitlab.project resources exist
// only if some policy happened to query gitlab.group.projects. Discovery's list
// is fetched unconditionally, which is what makes it the reliable source.
//
// Keyed by instance URL as well as project id, because one process can scan
// more than one GitLab and ids are only unique within an instance.
var discoveredProjects = struct {
	sync.RWMutex
	byKey map[string]*gitlab.Project
}{byKey: map[string]*gitlab.Project{}}

func projectCacheKey(url string, id int) string {
	return url + "\x00" + strconv.Itoa(id)
}

// CacheDiscoveredProjects records projects a listing already returned. Called by
// discovery; a nil entry or a project with no id is skipped rather than stored,
// so a partial listing cannot poison a later lookup.
func CacheDiscoveredProjects(url string, projects []*gitlab.Project) {
	if len(projects) == 0 {
		return
	}
	discoveredProjects.Lock()
	defer discoveredProjects.Unlock()
	for _, p := range projects {
		if p == nil || p.ID == 0 {
			continue
		}
		discoveredProjects.byKey[projectCacheKey(url, int(p.ID))] = p
	}
}

// cachedDiscoveredProject returns a project a listing already fetched, or nil.
func cachedDiscoveredProject(url string, id int) *gitlab.Project {
	if id == 0 {
		return nil
	}
	discoveredProjects.RLock()
	defer discoveredProjects.RUnlock()
	return discoveredProjects.byKey[projectCacheKey(url, id)]
}

// FlushDiscoveredProjects drops everything cached. Exported for tests, which
// would otherwise leak state between cases.
func FlushDiscoveredProjects() {
	discoveredProjects.Lock()
	defer discoveredProjects.Unlock()
	clear(discoveredProjects.byKey)
}

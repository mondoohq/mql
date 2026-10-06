// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// enumerateConcurrency bounds how many projects are listed at once. Azure
// DevOps throttles by cost, so a modest number keeps a large organization from
// being slowed down by its own listing.
const enumerateConcurrency = 4

// RepoStatus says whether a repository is scanned, and if not, why.
type RepoStatus string

const (
	// RepoReady is a repository with a default branch that can be read.
	RepoReady RepoStatus = "ready"
	// RepoEmpty is a repository with no commits, so no default branch.
	RepoEmpty RepoStatus = "empty"
	// RepoDisabled is a repository an administrator disabled.
	RepoDisabled RepoStatus = "disabled"
)

// Status classifies the repository. A disabled repository is disabled even when
// it also has no commits.
func (r Repository) Status() RepoStatus {
	switch {
	case r.IsDisabled:
		return RepoDisabled
	case r.IsEmpty():
		return RepoEmpty
	default:
		return RepoReady
	}
}

// ProjectListing is one project with the repositories the principal can list.
type ProjectListing struct {
	Project Project
	Repos   []Repository
	// NoAccess is set, and Repos is empty, when the principal may not list the
	// repositories of the project. It holds the answer Azure DevOps gave. A
	// project the credential cannot see holds a 404 here, so IsNoAccess(NoAccess)
	// is false for it: detect an unreadable project with NoAccess != nil or with
	// Listing.Unreadable, never with IsNoAccess.
	NoAccess error
}

// ListedRepo is a repository with the project it was listed under.
type ListedRepo struct {
	Project Project
	Repo    Repository
}

// FullName is "<project>/<repo>", the form repository filters match.
func (l ListedRepo) FullName() string {
	return l.Project.Name + "/" + l.Repo.Name
}

// Listing is every project of an organization with its repositories.
type Listing struct {
	Projects []ProjectListing
}

// Repos flattens the listing. The order is the order of the projects, then the
// order Azure DevOps listed the repositories in.
func (l *Listing) Repos() []ListedRepo {
	var out []ListedRepo
	for _, p := range l.Projects {
		for _, r := range p.Repos {
			out = append(out, ListedRepo{Project: p.Project, Repo: r})
		}
	}
	return out
}

// Unreadable names the projects whose repositories the principal cannot list.
func (l *Listing) Unreadable() []string {
	var out []string
	for _, p := range l.Projects {
		if p.NoAccess != nil {
			out = append(out, p.Project.Name)
		}
	}
	return out
}

// Enumerate lists every project and its repositories. A project the principal
// cannot read (401, 403 or 404 on its repository list) is reported on its
// ProjectListing and does not fail the call; any other error does.
func (c *Client) Enumerate(ctx context.Context) (*Listing, error) {
	projects, err := c.Projects(ctx)
	if err != nil {
		return nil, err
	}

	out := &Listing{Projects: make([]ProjectListing, len(projects))}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(enumerateConcurrency)
	for i, p := range projects {
		out.Projects[i].Project = p
		g.Go(func() error {
			repos, err := c.Repositories(gctx, p.Name)
			if err != nil {
				// Azure DevOps answers 404 (TF200016, TF401019), not 403, for the
				// repository list of a project the principal cannot see.
				if IsNoAccess(err) || IsNotFound(err) {
					out.Projects[i].NoAccess = err
					return nil
				}
				return err
			}
			out.Projects[i].Repos = repos
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

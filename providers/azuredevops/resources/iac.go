// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	gopath "path"
	"strings"
	"time"

	"go.mondoo.com/mql/providers/azuredevops/connection"
	"golang.org/x/sync/errgroup"
)

const (
	// iacWalkConcurrency bounds how many repository trees are read at once.
	iacWalkConcurrency = 4
	// iacWalkTimeout bounds the tree walk of one repository.
	iacWalkTimeout = 2 * time.Minute
)

// repoIac holds the IaC entry points found in the tree of one repository.
type repoIac struct {
	// hasTerraform is set when the tree holds a file that ends in .tf.
	hasTerraform bool
	// hasKubernetes is set when the tree holds a YAML file that may be a
	// manifest. A child that holds no manifest ends in ErrNoMatch, which cnspec
	// drops silently for children.
	hasKubernetes bool
}

// classifyIacTree sorts the files of a repository tree into the IaC entry
// points the discovery targets ask for. It mirrors the GitHub provider's
// classifyIacTree: a path with a hidden segment (.github, .azure, a leading
// dot) is skipped, and mql.yaml and mql.yml are policy files, not manifests.
// Azure DevOps has no languages API, so Terraform is found by the .tf suffix.
func classifyIacTree(items []connection.Item) repoIac {
	var out repoIac
	for _, item := range items {
		if !item.IsBlob() || isHiddenPath(item.Path) {
			continue
		}
		base := gopath.Base(item.Path)
		switch {
		case strings.HasSuffix(base, ".tf"):
			out.hasTerraform = true
		case (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) &&
			base != "mql.yaml" && base != "mql.yml":
			out.hasKubernetes = true
		}
	}
	return out
}

// isHiddenPath reports whether any segment of a repository path starts with a
// dot. Azure DevOps paths begin with a slash, which only adds an empty segment.
func isHiddenPath(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	return false
}

// iacResult is the outcome of the tree walk of one repository.
type iacResult struct {
	iac repoIac
	// err is why the tree could not be read. The repository asset is still
	// emitted without its IaC children.
	err error
}

// walkIac reads the tree of every repository, a few at a time, and classifies
// it. The results are in the order of repos. A failure is recorded on the
// result, never returned: IaC discovery is best effort, so one repository that
// cannot be read must not cost the scan its other repositories.
func walkIac(ctx context.Context, client *connection.Client, repos []connection.ListedRepo) []iacResult {
	out := make([]iacResult, len(repos))
	var g errgroup.Group
	g.SetLimit(iacWalkConcurrency)
	for i, r := range repos {
		g.Go(func() error {
			walkCtx, cancel := context.WithTimeout(ctx, iacWalkTimeout)
			defer cancel()
			items, err := client.Items(walkCtx, r.Project.Name, r.Repo.ID)
			if err != nil {
				out[i].err = err
				return nil
			}
			out[i].iac = classifyIacTree(items)
			return nil
		})
	}
	_ = g.Wait()
	return out
}

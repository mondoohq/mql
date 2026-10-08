// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// maxRepoContextConfigSize matches the cap the SDK puts on a local file.
const maxRepoContextConfigSize = 1 << 20

// repoContextConfig reads the mondoo.yml at the root of the repository on its
// default branch, the ref every asset discovered from it is scanned at. Only
// the root is read: there is no lookup through subdirectories. It returns nil
// when there is no such file or it cannot be read; a config never fails
// discovery.
//
// The result is for the repository asset itself, whose asset path is empty: it
// has no path below the config, so only unscoped entries govern it.
func repoContextConfig(ctx context.Context, client *github.Client, owner string, repo *mqlGithubRepository) *inventory.ContextConfig {
	ref := repo.DefaultBranchName.Data
	file, _, resp, err := client.Repositories.GetContents(ctx, owner, repo.Name.Data, inventory.ContextConfigFilename,
		&github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		if resp == nil || resp.StatusCode != http.StatusNotFound {
			log.Warn().Err(err).Str("repository", owner+"/"+repo.Name.Data).Msg("cannot read config at repository root")
		}
		return nil
	}
	// A directory listing comes back as a nil file. A symlink is not followed:
	// the file at the root is the one that governs.
	if file == nil || file.GetType() != "file" {
		return nil
	}
	if file.GetSize() > maxRepoContextConfigSize {
		log.Warn().Str("repository", owner+"/"+repo.Name.Data).Msg("config at repository root is too large, ignoring it")
		return nil
	}
	content, err := file.GetContent()
	if err != nil {
		log.Warn().Err(err).Str("repository", owner+"/"+repo.Name.Data).Msg("cannot decode config at repository root")
		return nil
	}

	origin := &inventory.ConfigOrigin{
		Provider:   "github",
		Repository: repositoryName(repo.CloneUrl.Data, owner, repo.Name.Data),
		Ref:        ref,
		Path:       inventory.ContextConfigFilename,
	}
	return plugin.NewContextConfig([]byte(content), origin.Repository+"/"+origin.Path, origin, "")
}

// withAssetPath is the same config as it governs an asset at path, relative to
// the repository root.
func withAssetPath(cfg *inventory.ContextConfig, path string) *inventory.ContextConfig {
	if cfg == nil {
		return nil
	}
	res := cfg.CloneVT()
	res.AssetPath = path
	return res
}

// repositoryName names a repository by host and path, e.g.
// "github.com/org/repo", so GitHub Enterprise repositories keep their host.
func repositoryName(cloneURL string, owner string, name string) string {
	if u, err := url.Parse(cloneURL); err == nil && u.Host != "" {
		return u.Host + strings.TrimSuffix(u.Path, ".git")
	}
	return "github.com/" + owner + "/" + name
}

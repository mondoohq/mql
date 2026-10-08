// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover returns the assets an Azure DevOps connection fans out to. An
// organization connection yields the organization asset and one asset per
// repository, and a repository connection yields that repository. The
// Terraform and Kubernetes children of a repository follow it.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	defer logger.FuncDur(time.Now(), "provider.azuredevops.discover")

	conn := connectionOf(runtime)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}

	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return in, nil
	}

	targets := handleTargets(conf.Discover.Targets)
	list, err := discover(apiContext(), conn, conf, targets)
	if err != nil {
		return in, err
	}
	in.Spec.Assets = list
	return in, nil
}

// handleTargets expands "all". Unlike the GitHub provider there is no user
// target, so "all" is the organization, the repositories and both kinds of IaC
// child.
func handleTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		return []string{
			connection.DiscoveryOrganization,
			connection.DiscoveryRepos,
			connection.DiscoveryTerraform,
			connection.DiscoveryK8sManifests,
		}
	}
	return targets
}

func wantsOrganization(targets []string) bool {
	return stringx.ContainsAnyOf(targets, connection.DiscoveryOrganization, connection.DiscoveryAuto)
}

func wantsRepos(targets []string) bool {
	return stringx.ContainsAnyOf(targets, connection.DiscoveryRepos, connection.DiscoveryAuto)
}

func wantsTerraform(targets []string) bool {
	return stringx.Contains(targets, connection.DiscoveryTerraform)
}

func wantsKubernetes(targets []string) bool {
	return stringx.Contains(targets, connection.DiscoveryK8sManifests)
}

func wantsIac(targets []string) bool {
	return wantsTerraform(targets) || wantsKubernetes(targets)
}

func discover(ctx context.Context, conn *connection.AzuredevopsConnection, conf *inventory.Config, targets []string) ([]*inventory.Asset, error) {
	if conn.IsRepository() {
		return discoverRepository(ctx, conn, conf, targets)
	}
	return discoverOrganization(ctx, conn, conf, targets)
}

// discoverOrganization lists the organization asset and the repositories that
// pass the filter.
func discoverOrganization(ctx context.Context, conn *connection.AzuredevopsConnection, conf *inventory.Config, targets []string) ([]*inventory.Asset, error) {
	var assets []*inventory.Asset

	// As on GitHub, a repository filter means the user wants those repositories,
	// not the organization.
	if wantsOrganization(targets) && conn.Filter().Empty() {
		assets = append(assets, &inventory.Asset{
			PlatformIds: []string{connection.NewOrgIdentifier(conn.Organization())},
			Name:        conn.Organization(),
			Platform:    connection.NewOrgPlatform(conn.Organization()),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{childConfig(conf, conn)},
		})
	}

	if !wantsRepos(targets) && !wantsIac(targets) {
		return assets, nil
	}

	listing, err := conn.Listing(ctx)
	if err != nil {
		return nil, err
	}
	for _, name := range listing.Unreadable() {
		log.Warn().Str("project", name).Msg("azure devops: the credential cannot list the repositories of this project, skipping it")
	}

	sel := selectRepos(listing, conn.Filter())
	// A pattern is matched against "project/repository". One without a slash,
	// such as "ado-*", matches nothing, which is easy to do and looks like an
	// empty organization.
	if conn.Filter().HasInclude() && len(sel.ready)+len(sel.skipped) == 0 {
		log.Warn().
			Msg("azure devops: the repository include filter matched no repositories. Patterns are project/repository, for example scan-test/*, so a pattern without a slash matches nothing")
	}
	for _, s := range sel.skipped {
		log.Info().Str("repository", s.repo.FullName()).Str("status", string(s.status)).
			Msg("azure devops: skipping a repository that cannot be scanned")
	}

	repoAssets, err := repositoryAssets(ctx, conn, conf, targets, sel.ready)
	if err != nil {
		return nil, err
	}
	return append(assets, repoAssets...), nil
}

// discoverRepository emits the repository a repository connection names. An
// empty or disabled repository still yields its asset, because the user asked
// for it by name, but it has no tree, so it gets no IaC children.
func discoverRepository(ctx context.Context, conn *connection.AzuredevopsConnection, conf *inventory.Config, targets []string) ([]*inventory.Asset, error) {
	repo, err := conn.Client().Repository(ctx, conn.Project(), conn.Repository())
	if err != nil {
		return nil, err
	}
	project := connection.Project{ID: repo.Project.ID, Name: repo.Project.Name}
	if project.Name == "" {
		project.Name = conn.Project()
	}
	listed := connection.ListedRepo{Project: project, Repo: *repo}

	if status := repo.Status(); status != connection.RepoReady {
		log.Info().Str("repository", listed.FullName()).Str("status", string(status)).
			Msg("azure devops: the repository has no tree to scan, skipping its IaC children")
		targets = withoutIac(targets)
	}
	return repositoryAssets(ctx, conn, conf, targets, []connection.ListedRepo{listed})
}

// withoutIac drops the IaC targets.
func withoutIac(targets []string) []string {
	var out []string
	for _, t := range targets {
		if t != connection.DiscoveryTerraform && t != connection.DiscoveryK8sManifests {
			out = append(out, t)
		}
	}
	return out
}

// skippedRepo is a repository that discovery passes over, with the reason.
type skippedRepo struct {
	repo   connection.ListedRepo
	status connection.RepoStatus
}

// selection splits the listed repositories into those to scan and those that
// cannot be.
type selection struct {
	ready   []connection.ListedRepo
	skipped []skippedRepo
}

// selectRepos applies the repository filter, then sets aside the repositories
// that cannot be scanned. A disabled or empty repository is not an error, it is
// reported by its status and left out.
func selectRepos(listing *connection.Listing, filter *connection.RepoFilter) selection {
	var sel selection
	for _, r := range listing.Repos() {
		if !filter.Keep(r.Project.Name, r.Repo.Name) {
			continue
		}
		if status := r.Repo.Status(); status != connection.RepoReady {
			sel.skipped = append(sel.skipped, skippedRepo{repo: r, status: status})
			continue
		}
		sel.ready = append(sel.ready, r)
	}
	return sel
}

// repositoryAssets builds the assets of the repositories, each followed by its
// IaC children. The tree walk happens once per repository, and only when a
// target asks for an IaC child.
func repositoryAssets(ctx context.Context, conn *connection.AzuredevopsConnection, conf *inventory.Config, targets []string, repos []connection.ListedRepo) ([]*inventory.Asset, error) {
	var iac []iacResult
	var cred *vault.Credential
	if wantsIac(targets) {
		var err error
		cred, err = conn.GitCredential(ctx)
		if err != nil {
			return nil, err
		}
		iac = walkIac(ctx, conn.Client(), repos)
	}

	var assets []*inventory.Asset
	for i, r := range repos {
		if wantsRepos(targets) {
			assets = append(assets, repositoryAsset(conf, conn, r))
		}
		if iac == nil {
			continue
		}
		if iac[i].err != nil {
			log.Error().Err(iac[i].err).Str("repository", r.FullName()).
				Msg("azure devops: failed to walk the repository tree, skipping its IaC children")
			continue
		}
		if wantsTerraform(targets) && iac[i].iac.hasTerraform {
			assets = append(assets, terraformAsset(conn.Organization(), r, cred))
		}
		if wantsKubernetes(targets) && iac[i].iac.hasKubernetes {
			assets = append(assets, kubernetesAsset(r, cred))
		}
	}
	return assets, nil
}

// childConfig is the connection of a discovered asset: the parent's, without
// discovery, tied to the parent connection.
func childConfig(conf *inventory.Config, conn *connection.AzuredevopsConnection) *inventory.Config {
	return conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
}

func repositoryAsset(conf *inventory.Config, conn *connection.AzuredevopsConnection, r connection.ListedRepo) *inventory.Asset {
	cfg := childConfig(conf, conn)
	cfg.Options[connection.OPTION_PROJECT] = r.Project.Name
	cfg.Options[connection.OPTION_REPOSITORY] = r.Repo.Name
	return &inventory.Asset{
		PlatformIds: []string{connection.NewRepoIdentifier(conn.Organization(), r.Project.Name, r.Repo.Name)},
		Name:        r.FullName(),
		Platform:    connection.NewRepoPlatform(conn.Organization(), r.Project.Name),
		Labels:      map[string]string{},
		Connections: []*inventory.Config{cfg},
	}
}

// gitChild is a child asset that clones the repository and scans it with the
// given connection type. Both URLs are set because the clone reads http-url
// and the Terraform platform detector reads ssh-url. The git server option
// names Azure DevOps, which rejects go-git's default upload-pack request; the
// SDK clone adjusts the request only for a connection that carries it. The
// user is non-empty because Azure DevOps rejects a Basic credential with an
// empty one.
func gitChild(connType string, r connection.ListedRepo, cred *vault.Credential) *inventory.Asset {
	return &inventory.Asset{
		// The name is preset because the ssh url of every Azure DevOps remote
		// parses to the organization "v3", so the derived name is not unique.
		Name: r.FullName(),
		Connections: []*inventory.Config{{
			Type: connType,
			Options: map[string]string{
				"ssh-url":                 r.Repo.SSHURL,
				"http-url":                r.Repo.HTTPURL(),
				plugin.GitServerOptionKey: plugin.GitServerAzureDevOps,
			},
			Credentials: []*vault.Credential{cred.CloneVT()},
		}},
	}
}

// terraformAsset is the terraform-hcl-git child of a repository. Its platform
// id is preset for the same reason as its name.
func terraformAsset(org string, r connection.ListedRepo, cred *vault.Credential) *inventory.Asset {
	a := gitChild("terraform-hcl-git", r, cred)
	a.PlatformIds = []string{connection.NewTerraformRepoIdentifier(org, r.Project.Name, r.Repo.Name)}
	return a
}

// kubernetesAsset is the k8s child of a repository. It keeps the k8s
// provider's own id, which hashes the temporary clone path.
func kubernetesAsset(r connection.ListedRepo, cred *vault.Credential) *inventory.Asset {
	a := gitChild("k8s", r, cred)
	a.Connections[0].Discover = &inventory.Discovery{Targets: []string{"auto"}}
	return a
}

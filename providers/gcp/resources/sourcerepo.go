// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/option"
	sourcerepo "google.golang.org/api/sourcerepo/v1"
)

func (g *mqlGcpProject) sourceRepositories() (*mqlGcpProjectSourceRepositoriesService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.sourceRepositoriesService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSourceRepositoriesService), nil
}

func (g *mqlGcpProjectSourceRepositoriesService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/sourceRepositoriesService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectSourceRepositoriesService) repos() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(sourcerepo.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := sourcerepo.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	if err := svc.Projects.Repos.List(fmt.Sprintf("projects/%s", projectId)).Context(ctx).Pages(ctx, func(resp *sourcerepo.ListReposResponse) error {
		for _, repo := range resp.Repos {
			mirrorConfig, err := buildRepoMirrorConfig(g.MqlRuntime, repo.Name, repo.MirrorConfig)
			if err != nil {
				return err
			}

			args := map[string]*llx.RawData{
				"projectId": llx.StringData(projectId),
				"name":      llx.StringData(repo.Name),
				"url":       llx.StringData(repo.Url),
				"size":      llx.IntData(repo.Size),
			}
			if mirrorConfig != nil {
				args["mirrorConfig"] = llx.ResourceData(mirrorConfig, "gcp.project.sourceRepositoriesService.repo.mirrorConfig")
			}

			mqlRepo, err := CreateResource(g.MqlRuntime, "gcp.project.sourceRepositoriesService.repo", args)
			if err != nil {
				return err
			}
			if mirrorConfig == nil {
				r := mqlRepo.(*mqlGcpProjectSourceRepositoriesServiceRepo)
				r.MirrorConfig.State = plugin.StateIsNull | plugin.StateIsSet
			}
			res = append(res, mqlRepo)
		}
		return nil
	}); err != nil {
		// Cloud Source Repositories is off by default and is unavailable
		// altogether to projects that had not used it before June 2024, so a
		// 403 SERVICE_DISABLED is the COMMON case here, not an exceptional one.
		// service_sourcerepo is declared in services.go but was never wired to
		// a gate, so this accessor hard-failed on most projects.
		if isSkippable(err) {
			log.Warn().Err(err).Str("project", projectId).Msg("could not list Cloud Source Repositories")
			return nil, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectSourceRepositoriesServiceRepo) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/sourceRepositoriesService.repo/%s", g.ProjectId.Data, g.Name.Data), nil
}

func buildRepoMirrorConfig(runtime *plugin.Runtime, parentName string, mc *sourcerepo.MirrorConfig) (*mqlGcpProjectSourceRepositoriesServiceRepoMirrorConfig, error) {
	if mc == nil {
		return nil, nil
	}

	res, err := CreateResource(runtime, "gcp.project.sourceRepositoriesService.repo.mirrorConfig", map[string]*llx.RawData{
		"id":          llx.StringData(parentName + "/mirrorConfig"),
		"url":         llx.StringData(mc.Url),
		"deployKeyId": llx.StringData(mc.DeployKeyId),
		"webhookId":   llx.StringData(mc.WebhookId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSourceRepositoriesServiceRepoMirrorConfig), nil
}

func (g *mqlGcpProjectSourceRepositoriesServiceRepoMirrorConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

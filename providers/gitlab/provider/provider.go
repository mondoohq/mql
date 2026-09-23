// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strconv"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/providers/gitlab/resources"
)

const (
	ConnectionType          = "gitlab"
	GitlabGroupConnection   = "gitlab-group"
	GitlabProjectConnection = "gitlab-project"
)

const (
	DiscoveryAuto    = "auto"
	DiscoveryGroup   = "groups"
	DiscoveryProject = "projects"
	// -- chained git discovery options --
	DiscoveryTerraform      = "terraform"
	DiscoveryK8sManifests   = "k8s-manifests"
	DiscoveryCloudformation = "cloudformation"
	DiscoveryDockerfiles    = "dockerfiles"
	DiscoveryBicep          = "bicep"
	DiscoveryHelm           = "helm"
	DiscoveryKustomize      = "kustomize"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	conf := &inventory.Config{
		Type:    req.Connector,
		Options: map[string]string{},
	}

	token := ""
	if x, ok := flags["token"]; ok && len(x.Value) != 0 {
		token = string(x.Value)
	}
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if token == "" {
		return nil, errors.New("a valid GitLab token is required, pass --token '<yourtoken>' or set GITLAB_TOKEN environment variable")
	}
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", token))

	if x, ok := flags["group"]; ok && len(x.Value) != 0 {
		conf.Options["group"] = string(x.Value)
	}

	if x, ok := flags["project"]; ok && len(x.Value) != 0 {
		conf.Options["project"] = string(x.Value)
	}
	// it's ok if no group or project is defined.
	// we will discover all the groups
	if x, ok := flags["url"]; ok {
		conf.Options["url"] = string(x.Value)
	}

	conf.Discover = parseDiscover(flags)
	asset := inventory.Asset{
		Connections: []*inventory.Config{conf},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func parseDiscover(flags map[string]*llx.Primitive) *inventory.Discovery {
	var targets []string
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		targets = make([]string, 0, len(x.Array))
		for i := range x.Array {
			entry := string(x.Array[i].Value)
			targets = append(targets, entry)
		}
	} else {
		targets = []string{"auto"}
	}
	return &inventory.Discovery{Targets: targets}
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset information yet.
	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	inventory, err := s.discover(req.Asset, conn)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:        conn.ID(),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inventory,
		// Which kind this asset actually is; the static Root can only name one
		// for a provider serving several (ADR 031).
		Root: assetRoot(req.Asset.GetPlatform()),
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.GitLabConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewGitLabConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = connId
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.GitLabConnection), nil
}

func projectPlatform() *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "gitlab", "project"},
	}
	PlatformByName("gitlab-project").Apply(pf)
	return pf
}

func groupPlatform() *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "gitlab", "group"},
	}
	PlatformByName("gitlab-group").Apply(pf)
	return pf
}

func newGitLabGroupID(groupID int64) string {
	return "//platformid.api.mondoo.app/runtime/gitlab/group/" + strconv.FormatInt(groupID, 10)
}

func newGitLabGroupIDFromPath(groupPath string) string {
	return "//platformid.api.mondoo.app/runtime/gitlab/group/" + groupPath
}

func newGitLabProjectID(groupID int64, projectID int64) string {
	return "//platformid.api.mondoo.app/runtime/gitlab/group/" + strconv.FormatInt(groupID, 10) + "/project/" + strconv.FormatInt(projectID, 10)
}

func newGitLabProjectIDFromPaths(groupPath string, projectPath string) string {
	return "//platformid.api.mondoo.app/runtime/gitlab/group/" + groupPath + "/project/" + projectPath
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.GitLabConnection) error {
	asset.Id = conn.Conf.Type

	if !conn.IsGroup() && !conn.IsProject() {
		// that's ok, it means nothing was defined on connection.
		// we will discover the groups
		return nil
	}

	if conn.IsProject() {
		project, err := conn.Project()
		if err != nil {
			return err
		}
		// Resolve the owning group rather than reading it off the CLI options:
		// ParseCLI never sets group-id, so conn.GroupID() fell back to 0 and
		// produced platform id ".../group/0/project/<id>". Discovery stamps the
		// real group id, so the same project scanned both ways split into two
		// assets with separate history. Prefer the project's own namespace,
		// which is also correct for a project reached outside its group.
		groupID, groupFullPath := conn.GroupID(), conn.GroupName()
		if project.Namespace != nil && project.Namespace.ID > 0 {
			groupID, groupFullPath = project.Namespace.ID, project.Namespace.FullPath
		} else if group, gerr := conn.Group(); gerr == nil && group != nil {
			groupID, groupFullPath = group.ID, group.FullPath
		}
		s.detectAsProject(asset, groupID, groupFullPath, project)
	} else {
		group, err := conn.Group()
		if err != nil {
			return err
		}
		s.detectAsGroup(asset, group)
	}
	return nil
}

func (s *Service) detectAsProject(asset *inventory.Asset, groupID int64, groupFullPath string, project *gitlab.Project) {
	asset.Platform = projectPlatform()
	asset.Name = "GitLab Project " + project.Name
	asset.PlatformIds = []string{
		newGitLabProjectID(groupID, project.ID),
		newGitLabProjectIDFromPaths(groupFullPath, project.Path), // for backwards compatibility with v8
	}
}

func (s *Service) detectAsGroup(asset *inventory.Asset, group *gitlab.Group) error {
	asset.Platform = groupPlatform()
	asset.Name = "GitLab Group " + group.Name
	asset.PlatformIds = []string{
		newGitLabGroupID(group.ID),
		newGitLabGroupIDFromPath(group.FullPath), // for backwards compatibility with v8
	}
	return nil
}

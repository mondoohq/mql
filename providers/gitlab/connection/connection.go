// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	nethttp "net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type GitLabConnection struct {
	plugin.Connection
	Conf        *inventory.Config
	asset       *inventory.Asset
	group       *gitlab.Group
	project     *gitlab.Project
	projectID   string // only used for initial setup, use project.ID afterwards!
	groupName   string
	groupID     string
	projectName string
	client      *gitlab.Client
	url         string
}

func NewGitLabConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*GitLabConnection, error) {
	// check if the token was provided by the option. This way is deprecated since it does not pass the token as secret
	token := conf.Options["token"]

	// if no token was provided, lets read the env variable
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}

	// If credentials were supplied they are authoritative — falling back to the
	// option/env token when the only credential is one we can't use would
	// silently scan as a different account than the inventory asked for.
	if len(conf.Credentials) > 0 {
		token = ""
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
				break
			}
			log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for GitLab provider")
		}
		if token == "" {
			return nil, errors.New("gitlab provider requires a password/token credential, but none of the supplied credentials are usable")
		}
	}

	if token == "" {
		return nil, errors.New("you must provide GitLab token e.g. via GITLAB_TOKEN env")
	}

	var opts gitlab.ClientOptionFunc
	url := conf.Options["url"]
	if url != "" {
		opts = gitlab.WithBaseURL(url)
	}

	// Log every call at debug, the way the azure and gcp providers do. Without
	// it a slow GitLab scan cannot be attributed to anything: GitLab paginates
	// heavily and fans out per project, so "which call, how many times" is the
	// only question worth asking and there was previously no way to ask it.
	traced := &nethttp.Client{Transport: &apiTraceTransport{}}
	clientOpts := []gitlab.ClientOptionFunc{gitlab.WithHTTPClient(traced)}
	if opts != nil {
		clientOpts = append(clientOpts, opts)
	}

	client, err := gitlab.NewClient(token, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &GitLabConnection{
		Connection:  plugin.NewConnection(id, asset),
		Conf:        conf,
		asset:       asset,
		groupName:   conf.Options["group"],
		groupID:     conf.Options["group-id"],
		projectName: conf.Options["project"],
		projectID:   conf.Options["project-id"],
		url:         conf.Options["url"],
		client:      client,
	}, nil
}

func (c *GitLabConnection) Name() string {
	return "gitlab"
}

func (c *GitLabConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *GitLabConnection) GroupName() string {
	return c.groupName
}

func (c *GitLabConnection) GroupID() int64 {
	i, err := strconv.ParseInt(c.groupID, 10, 64)
	if err == nil {
		return i
	}
	return 0
}

func (c *GitLabConnection) Client() *gitlab.Client {
	return c.client
}

func (c *GitLabConnection) Group() (*gitlab.Group, error) {
	if c.group != nil {
		return c.group, nil
	}
	if c.groupName == "" && c.groupID == "" {
		return nil, errors.New("cannot look up gitlab group, no group name defined")
	}
	gid := c.groupID
	if gid == "" {
		gid = c.groupName
	}
	log.Debug().Str("id", gid).Msgf("finding group")

	// A full path ("acme/platform/api") is a valid group id for this endpoint:
	// the SDK URL-escapes it for us, so nested groups resolve in one call. The
	// previous subgroup traversal matched on the group's *display* name rather
	// than its path (so a group renamed away from its slug was unreachable)
	// and kept only the first two path segments, silently resolving "a/b" when
	// the caller asked for "a/b/c".
	var err error
	c.group, _, err = c.Client().Groups.GetGroup(gid, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot find gitlab group %q: %w", gid, err)
	}
	if c.group == nil {
		return nil, fmt.Errorf("gitlab group %q not found", gid)
	}
	return c.group, nil
}

func (c *GitLabConnection) IsGroup() bool {
	return c.groupName != ""
}

func (c *GitLabConnection) IsProject() bool {
	return c.projectName != "" || c.projectID != ""
}

func (c *GitLabConnection) GID() (any, error) {
	if c.groupName == "" {
		return nil, errors.New("cannot look up gitlab group, no group path defined")
	}
	return url.QueryEscape(c.groupName), nil
}

func (c *GitLabConnection) PID() (any, error) {
	if c.projectID != "" {
		return c.projectID, nil
	}

	if c.groupName == "" {
		return nil, errors.New("cannot look up gitlab group, no group path defined")
	}
	if c.projectName == "" {
		return nil, errors.New("cannot look up gitlab project, no project path defined")
	}

	return path.Join(c.groupName, c.projectName), nil
}

func (c *GitLabConnection) Project() (*gitlab.Project, error) {
	if c.project != nil {
		return c.project, nil
	}

	pid, err := c.PID()
	if err != nil {
		return nil, err
	}

	// Discovery listed this project already, and that listing returns the full
	// object. Reuse it rather than spending a GetProject per asset. Falls
	// through when the project was not discovered -- scanned directly, or
	// addressed by path rather than id -- so nothing depends on the cache.
	if idStr, ok := pid.(string); ok {
		if id, cerr := strconv.Atoi(idStr); cerr == nil {
			if p := cachedDiscoveredProject(c.url, id); p != nil {
				log.Debug().Int("id", id).Msg("using project from discovery")
				c.project = p
				return c.project, nil
			}
		}
	}

	log.Debug().Interface("id", pid).Msgf("finding project")

	c.project, _, err = c.Client().Projects.GetProject(pid, nil)
	return c.project, err
}

// DiscoverSubAndDescendantGroupsForGroup returns every group beneath rootGroup.
//
// GitLab's descendant_groups endpoint already returns direct children as well
// as deeper ones, so the two result sets overlap; entries are deduplicated by
// id. Without that, every direct subgroup was discovered twice, which in turn
// made discoverGroupProjects walk each of their project lists twice.
//
// A failure is surfaced rather than swallowed at debug level: a token that
// cannot read subgroups previously produced an empty tree that was
// indistinguishable from a group that genuinely has none, and the caller's
// error handling was unreachable because this always returned a nil error.
func DiscoverSubAndDescendantGroupsForGroup(conn *GitLabConnection, rootGroup string) ([]*gitlab.Group, error) {
	var list []*gitlab.Group
	var errs []error
	seen := map[int64]bool{}

	appendUnique := func(groups []*gitlab.Group) {
		for _, g := range groups {
			if g == nil || seen[g.ID] {
				continue
			}
			seen[g.ID] = true
			list = append(list, g)
		}
	}

	// discover subgroups
	subgroups, err := groupSubgroups(conn, rootGroup)
	if err != nil {
		log.Warn().Err(err).Msgf("cannot discover subgroups for %v; results may be incomplete", rootGroup)
		errs = append(errs, err)
	} else {
		appendUnique(subgroups)
	}
	// discover descendant groups
	descgroups, err := groupDescendantGroups(conn, rootGroup)
	if err != nil {
		log.Warn().Err(err).Msgf("cannot discover descendant groups for %v; results may be incomplete", rootGroup)
		errs = append(errs, err)
	} else {
		appendUnique(descgroups)
	}

	// Only a total failure is fatal: if either endpoint answered we still have
	// a usable (if partial) tree, and the warnings above say so.
	if len(list) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return list, nil
}

func groupDescendantGroups(conn *GitLabConnection, gid any) ([]*gitlab.Group, error) {
	log.Debug().Msgf("calling list descendant groups with %v", gid)
	perPage := int64(50)
	page := int64(1)
	groups := []*gitlab.Group{}
	for {
		grps, resp, err := conn.Client().Groups.ListDescendantGroups(gid, &gitlab.ListDescendantGroupsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		groups = append(groups, grps...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return groups, nil
}

func groupSubgroups(conn *GitLabConnection, gid any) ([]*gitlab.Group, error) {
	log.Debug().Msgf("calling list subgroups with %v", gid)
	perPage := int64(50)
	page := int64(1)
	groups := []*gitlab.Group{}
	for {
		grps, resp, err := conn.Client().Groups.ListSubGroups(gid, &gitlab.ListSubGroupsOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage}})
		if err != nil {
			return nil, err
		}
		groups = append(groups, grps...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return groups, nil
}

// apiTraceTransport logs every GitLab API request with its method, path, status
// and duration at debug level. The query string is dropped deliberately: it
// carries pagination cursors and, on some endpoints, tokens.
type apiTraceTransport struct{ base nethttp.RoundTripper }

func (t *apiTraceTransport) RoundTrip(r *nethttp.Request) (*nethttp.Response, error) {
	b := t.base
	if b == nil {
		b = nethttp.DefaultTransport
	}
	start := time.Now()
	resp, err := b.RoundTrip(r)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	log.Debug().
		Str("method", r.Method).
		Str("url", r.URL.Host+r.URL.Path).
		Int("status", status).
		Dur("duration", time.Since(start)).
		Err(err).
		Msg("gitlab api call")
	return resp, err
}

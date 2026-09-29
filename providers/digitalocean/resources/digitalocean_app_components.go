// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/url"
	"regexp"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// ----- Credential redaction -----

// userinfoPassword matches the password half of a URL's userinfo, for input
// url.Parse rejects.
var userinfoPassword = regexp.MustCompile(`(://[^/@:]*):[^/@]*@`)

// redactURLPassword removes a password embedded in a URL's userinfo, keeping
// the username, host, port and path. Log-sink and clone URLs are routinely
// written as https://user:password@host, and the address is worth reporting
// while the password must never be.
func redactURLPassword(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return userinfoPassword.ReplaceAllString(raw, "$1@")
	}
	if u.User == nil {
		return raw
	}
	if _, has := u.User.Password(); !has {
		return raw
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

// ----- App Platform components -----

// appComponentSource is the source of a component's code, flattened across
// the Git providers and container images.
type appComponentSource struct {
	sourceType        string
	repository        string
	branch            string
	deployOnPush      bool
	imageRegistryType string
	imageRegistry     string
	imageTag          string
	imageDigest       string
	hasRegistryCreds  bool
}

// buildableSource is the part of a component spec that names where its code
// comes from. Every component type except databases implements it.
type buildableSource interface {
	GetGit() *godo.GitSourceSpec
	GetGitHub() *godo.GitHubSourceSpec
	GetGitLab() *godo.GitLabSourceSpec
	GetBitbucket() *godo.BitbucketSourceSpec
}

// componentSource reads the source a component builds or deploys from.
//
// The registry credentials of an image source are a secret: only whether
// they are set is reported. A clone URL may embed a token, so its password
// is removed.
func componentSource(c godo.AppComponentSpec) appComponentSource {
	var s appComponentSource
	if ic, ok := c.(interface{ GetImage() *godo.ImageSourceSpec }); ok {
		if img := ic.GetImage(); img != nil {
			s.sourceType = "image"
			s.repository = img.Repository
			s.imageRegistryType = string(img.RegistryType)
			s.imageRegistry = img.Registry
			s.imageTag = img.Tag
			s.imageDigest = img.Digest
			s.hasRegistryCreds = img.RegistryCredentials != ""
			if img.DeployOnPush != nil {
				s.deployOnPush = img.DeployOnPush.Enabled
			}
			return s
		}
	}
	b, ok := c.(buildableSource)
	if !ok {
		return s
	}
	switch {
	case b.GetGitHub() != nil:
		g := b.GetGitHub()
		s.sourceType, s.repository, s.branch, s.deployOnPush = "github", g.Repo, g.Branch, g.DeployOnPush
	case b.GetGitLab() != nil:
		g := b.GetGitLab()
		s.sourceType, s.repository, s.branch, s.deployOnPush = "gitlab", g.Repo, g.Branch, g.DeployOnPush
	case b.GetBitbucket() != nil:
		g := b.GetBitbucket()
		s.sourceType, s.repository, s.branch, s.deployOnPush = "bitbucket", g.Repo, g.Branch, g.DeployOnPush
	case b.GetGit() != nil:
		g := b.GetGit()
		s.sourceType, s.repository, s.branch = "git", redactURLPassword(g.RepoCloneURL), g.Branch
	}
	return s
}

// appComponentRuntime is the sizing and networking of a component.
type appComponentRuntime struct {
	instanceSizeSlug string
	instanceCount    int64
	autoscaleMin     *int64
	autoscaleMax     *int64
	httpPort         *int64
	internalPorts    []any
	routes           []any
}

func routePaths(routes []*godo.AppRouteSpec) []any {
	out := []any{}
	for _, rt := range routes {
		if rt == nil {
			continue
		}
		out = append(out, rt.Path)
	}
	return out
}

func autoscaleBounds(a *godo.AppAutoscalingSpec) (lo, hi *int64) {
	if a == nil {
		return nil, nil
	}
	mn, mx := a.MinInstanceCount, a.MaxInstanceCount
	return &mn, &mx
}

// componentRuntime reads sizing, autoscaling, ports and routes. Fields a
// component type does not have stay at their empty value, or null for the
// autoscaling bounds and the HTTP port.
func componentRuntime(c godo.AppComponentSpec) appComponentRuntime {
	rt := appComponentRuntime{internalPorts: []any{}, routes: []any{}}
	switch t := c.(type) {
	case *godo.AppServiceSpec:
		rt.instanceSizeSlug, rt.instanceCount = t.InstanceSizeSlug, t.InstanceCount
		rt.autoscaleMin, rt.autoscaleMax = autoscaleBounds(t.Autoscaling)
		// An unset port means the platform default applies, which the spec
		// does not name, so it is reported as unknown rather than zero.
		if t.HTTPPort != 0 {
			port := t.HTTPPort
			rt.httpPort = &port
		}
		for _, p := range t.InternalPorts {
			rt.internalPorts = append(rt.internalPorts, p)
		}
		rt.routes = routePaths(t.Routes)
	case *godo.AppWorkerSpec:
		rt.instanceSizeSlug, rt.instanceCount = t.InstanceSizeSlug, t.InstanceCount
		rt.autoscaleMin, rt.autoscaleMax = autoscaleBounds(t.Autoscaling)
	case *godo.AppJobSpec:
		rt.instanceSizeSlug, rt.instanceCount = t.InstanceSizeSlug, t.InstanceCount
	case *godo.AppStaticSiteSpec:
		rt.routes = routePaths(t.Routes)
	case *godo.AppFunctionsSpec:
		rt.routes = routePaths(t.Routes)
	}
	return rt
}

// appComponentSpecs returns the components of an app spec, leaving out
// database components, which have no source, sizing or routes.
func appComponentSpecs(spec *godo.AppSpec) []godo.AppComponentSpec {
	var out []godo.AppComponentSpec
	// ForEachAppComponentSpec never returns an error when the callback doesn't.
	_ = spec.ForEachAppComponentSpec(func(c godo.AppComponentSpec) error {
		if c == nil || c.GetType() == godo.AppComponentTypeDatabase {
			return nil
		}
		out = append(out, c)
		return nil
	})
	return out
}

func (r *mqlDigitaloceanApp) components() ([]any, error) {
	appID := r.Id.Data
	if appID == "" {
		return nil, errors.New("cannot list app components without an app id")
	}

	out := []any{}
	for _, c := range appComponentSpecs(r.cacheSpec) {
		// Component names are unique within an app across all component
		// types; the type is part of the key anyway so a spec that reused
		// a name could not alias two components.
		id, err := resourceID("digitalocean.app.component", appID, string(c.GetType()), c.GetName())
		if err != nil {
			return nil, err
		}
		src := componentSource(c)
		rt := componentRuntime(c)
		res, err := CreateResource(r.MqlRuntime, "digitalocean.app.component", map[string]*llx.RawData{
			"__id":                          llx.StringData(id),
			"appId":                         llx.StringData(appID),
			"name":                          llx.StringData(c.GetName()),
			"type":                          llx.StringData(string(c.GetType())),
			"sourceType":                    llx.StringData(src.sourceType),
			"repository":                    llx.StringData(src.repository),
			"branch":                        llx.StringData(src.branch),
			"deployOnPush":                  llx.BoolData(src.deployOnPush),
			"imageRegistryType":             llx.StringData(src.imageRegistryType),
			"imageRegistry":                 llx.StringData(src.imageRegistry),
			"imageTag":                      llx.StringData(src.imageTag),
			"imageDigest":                   llx.StringData(src.imageDigest),
			"registryCredentialsConfigured": llx.BoolData(src.hasRegistryCreds),
			"instanceSizeSlug":              llx.StringData(rt.instanceSizeSlug),
			"instanceCount":                 llx.IntData(rt.instanceCount),
			"autoscalingMinInstances":       llx.IntDataPtr(rt.autoscaleMin),
			"autoscalingMaxInstances":       llx.IntDataPtr(rt.autoscaleMax),
			"httpPort":                      llx.IntDataPtr(rt.httpPort),
			"internalPorts":                 llx.ArrayData(rt.internalPorts, types.Int),
			"routes":                        llx.ArrayData(rt.routes, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

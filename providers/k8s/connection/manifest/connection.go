// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/utils/urlx"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/version"
)

var _ plugin.Closer = (*Connection)(nil)

type Option func(*Connection)

func WithNamespace(namespace string) Option {
	return func(p *Connection) {
		p.namespace = namespace
	}
}

func WithManifestFile(filename string) Option {
	return func(p *Connection) {
		p.manifestFile = filename
	}
}

func WithManifestContent(data []byte) Option {
	return func(p *Connection) {
		p.manifestContent = data
	}
}

func WithCloser(closer func()) Option {
	return func(p *Connection) {
		p.closer = closer
	}
}

type Connection struct {
	shared.ManifestParser
	plugin.Connection
	asset     *inventory.Asset
	namespace string

	manifestFile    string
	manifestContent []byte
	closer          func()

	// Raw manifest bytes retained for source context. Kept separate from
	// manifestContent, which drives the stdin-vs-file platform-id hashing.
	sourceRaw  []byte
	posOnce    sync.Once
	contentStr string
	positions  map[string]shared.SourcePosition
}

func NewGitConnection(id uint32, asset *inventory.Asset, opts ...Option) (shared.Connection, error) {
	path, closer, err := plugin.NewGitClone(asset)
	if err != nil {
		return nil, err
	}

	// After we have cloned the repo, we just work with the path. This makes sure consequent
	// connect calls will not trigger repo clone again.
	conf := asset.Connections[0]
	delete(conf.Options, shared.OPTION_GIT_HTTP)
	conf.Options[shared.OPTION_MANIFEST] = path

	opts = append(opts, WithCloser(closer), WithManifestFile(path))
	return NewConnection(id, asset, opts...)
}

func NewConnection(id uint32, asset *inventory.Asset, opts ...Option) (shared.Connection, error) {
	c := &Connection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		namespace:  asset.Connections[0].Options[shared.OPTION_NAMESPACE],
	}

	for _, option := range opts {
		option(c)
	}

	manifest := []byte{}
	var err error

	clusterName := ""
	if len(c.manifestContent) > 0 {
		manifest = c.manifestContent
		clusterName = "K8s Manifest"
	} else if c.manifestFile != "" {
		manifest, err = shared.LoadManifestFile(c.manifestFile)
		if err != nil {
			return nil, err
		}
		// Prefer the git repo (org/repo) for a stable, human-friendly name,
		// matching the Terraform static-analysis naming. The manifest path is a
		// temporary clone directory (e.g. mql-git-clone3841…) when discovered
		// from a git repository, so fall back to it only for local manifests.
		if url := asset.Connections[0].Options["ssh-url"]; url != "" {
			if _, org, repo, err := urlx.ParseGitSshUrl(url); err == nil {
				clusterName = "K8s Manifest " + org + "/" + repo
			}
		}
		if clusterName == "" {
			clusterName = "K8s Manifest " + shared.ProjectNameFromPath(c.manifestFile)
		}
	}
	// discovered assets pass by here
	// They already have a name, so do not override it here.
	if asset.Name == "" {
		asset.Name = clusterName
	}
	if gitPath := asset.Connections[0].Options[plugin.GitUrlOptionKey]; gitPath != "" {
		// if the GitUrlOptionKey is present, we want to sanitize the url and add it to the
		// asset labels so that we can later reference the git url where this object was found
		if asset.Labels == nil {
			asset.Labels = make(map[string]string)
		}
		asset.Labels[plugin.GitUrlOptionKey] = trimGitPath(gitPath)
	}
	// Retain the raw manifest so we can extract the source text a resource
	// spans for file-context. In the file case the bytes were only local.
	c.sourceRaw = manifest

	c.ManifestParser, err = shared.NewManifestParser(manifest, c.namespace, "")
	if err != nil {
		return nil, err
	}

	// Zero objects means nothing Kubernetes was here, and connecting anyway
	// would pass every policy on a folder nothing was ever read from. For a
	// directory this is a count and not an error check, deliberately:
	// LoadManifestFile's walk already drops every file that does not decode as
	// a Kubernetes object, so plain config YAML, Helm templates full of Go
	// templating and policy bundles all arrive here as an empty set -- while a
	// single file the user named keeps reporting its own parse error.
	if len(c.ManifestParser.Objects) == 0 {
		return nil, fmt.Errorf("no Kubernetes objects found in %s: %w", c.manifestFile, plugin.ErrNoMatch)
	}

	return c, nil
}

// ManifestSource returns the manifest text, the file path it was read from, and
// a per-resource source-position index keyed by object id (kind:namespace:name).
// The index is built lazily on first use. Resources not present in the manifest
// (e.g. synthesized CRDs) simply have no entry.
func (c *Connection) ManifestSource() (string, string, map[string]shared.SourcePosition) {
	c.posOnce.Do(func() {
		c.contentStr = string(c.sourceRaw)
		c.positions = shared.BuildManifestPositionIndex(c.sourceRaw, c.manifestFile)
	})
	return c.contentStr, c.manifestFile, c.positions
}

func trimGitPath(gitPath string) string {
	return strings.TrimSuffix(gitPath, ".git")
}

func (c *Connection) Close() {
	if c.closer != nil {
		c.closer()
	}
}

func (c *Connection) ServerVersion() *version.Info {
	return nil
}

func (c *Connection) SupportedResourceTypes() (*resources.ApiResourceIndex, error) {
	return c.ManifestParser.SupportedResourceTypes()
}

func (c *Connection) Name() string {
	return c.asset.Name
}

func (c *Connection) Runtime() string {
	return "k8s-manifest"
}

func (c *Connection) Platform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "k8s-manifest",
		Family:                []string{"k8s"},
		Kind:                  "code",
		Runtime:               c.Runtime(),
		Title:                 "Kubernetes Manifest",
		TechnologyUrlSegments: []string{"iac", "k8s-manifest"},
	}
}

func (c *Connection) Asset() *inventory.Asset {
	return c.asset
}

func (c *Connection) BasePlatformId() (string, error) {
	manifestHash, err := c.manifestHash()
	if err != nil {
		return "", err
	}
	return shared.IdPrefix + manifestHash, nil
}

func (c *Connection) AssetId() (string, error) {
	// If we are doing an admission control scan, we have 1 resource in the manifest and it has a UID.
	// Instead of using the file path to generate the ID, use the resource UID. We do this because for
	// CI/CD scans, the manifest is stored in a random file. This means we can potentially be scanning
	// the same resource multiple times but it will result in different assets because of the random
	// file name.

	if len(c.Objects) == 1 && c.asset.Platform.Runtime == "k8s-admission" {
		o, err := meta.Accessor(c.Objects[0])
		if err == nil {
			if o.GetUID() != "" {
				return shared.NewPlatformId(string(o.GetUID())), nil
			}
		}
	}

	manifestHash, err := c.manifestHash()
	if err != nil {
		return "", err
	}
	return shared.NewPlatformId(manifestHash), nil
}

func (c *Connection) manifestHash() (string, error) {
	h := sha256.New()

	// special handling for embedded content (e.g. piped in via stdin)
	if len(c.manifestContent) > 0 {
		h.Write([]byte("stdin"))
		return hex.EncodeToString(h.Sum(nil)), nil
	}

	_, err := os.Stat(c.manifestFile)
	if err != nil {
		return "", errors.Wrap(err, "could not determine platform identifier for "+c.manifestFile)
	}

	absPath, err := filepath.Abs(c.manifestFile)
	if err != nil {
		return "", errors.Wrap(err, "could not determine platform identifier for "+c.manifestFile)
	}

	h.Write([]byte(absPath))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Connection) InventoryConfig() *inventory.Config {
	return c.asset.Connections[0]
}

func (p *Connection) AdmissionReviews() ([]admissionv1.AdmissionReview, error) {
	return []admissionv1.AdmissionReview{}, nil
}

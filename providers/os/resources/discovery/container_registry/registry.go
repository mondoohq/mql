// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container_registry

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/container/auth"
	"go.mondoo.com/mql/providers/os/connection/container/image"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/containerid"
)

func RemoteOptionsFromConfigOptions(cfg *inventory.Config) ([]remote.Option, error) {
	opts := []remote.Option{}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// We usually are dealing with 2 hosts (at most), split MaxIdleConns between them.
		MaxIdleConnsPerHost: 50,
	}
	if containerProxy, ok := cfg.Options[shared.ContainerProxyOption]; ok {
		urlParsed, err := url.Parse(containerProxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(urlParsed)

	}

	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	opts = append(opts, remote.WithTransport(transport))
	opts = append(opts, auth.AuthOption("", cfg.Credentials))
	return opts, nil
}

// NewImageLister returns a helper that enumerates images and repositories in a
// container registry. It is not a Resolver in the sense of [Resolver.Resolve] —
// it lists what's there, it does not pick a connection type for a target.
func NewImageLister(opts ...remote.Option) *ImageLister {
	return &ImageLister{
		opts: opts,
	}
}

// ImageLister enumerates images and repositories in a container registry.
type ImageLister struct {
	opts     []remote.Option
	Insecure bool
}

func (a *ImageLister) remoteOptions(name string) []remote.Option {
	// either use the provided options or the default options
	if len(a.opts) > 0 {
		return a.opts
	}
	log.Debug().Str("name", name).Msg("using default remote options")
	return auth.DefaultOpts(name, a.Insecure)
}

func (a *ImageLister) Repositories(reg name.Registry) ([]string, error) {
	n := 100
	last := ""
	var res []string
	for {
		opts := a.remoteOptions(reg.Name())
		page, err := remote.CatalogPage(reg, last, n, opts...)
		if err != nil {
			return nil, err
		}

		if len(page) > 0 {
			last = page[len(page)-1]
			res = append(res, page...)
		}

		if len(page) < n {
			break
		}
	}

	return res, nil
}

// ListRegistry tries to iterate over all repositories in one registry
// eg. 1234567.dkr.ecr.us-east-1.amazonaws.com
func (a *ImageLister) ListRegistry(registry string) ([]*inventory.Asset, error) {
	reg, err := name.NewRegistry(registry)
	if err != nil {
		return nil, errors.Wrap(err, "resolve registry")
	}

	repos, err := a.Repositories(reg)
	if err != nil {
		return nil, err
	}

	assets := []*inventory.Asset{}
	for i := range repos {
		repoName := reg.RegistryStr() + "/" + repos[i]
		log.Debug().Str("repository", repoName).Msg("discovered repository")

		// iterate over all repository digests
		repoImages, err := a.ListRepository(repoName)
		if err != nil {
			return nil, err
		}
		assets = append(assets, repoImages...)
	}

	return assets, nil
}

// ListRepository tries to fetch all details about a specific repository
// index.docker.io/mondoo
// index.docker.io/mondoo/client
// harbor.lunalectric.com/library
// harbor.lunalectric.com/library/ubuntu
func (a *ImageLister) ListRepository(repoName string) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}

	repo, err := name.NewRepository(repoName)
	if err != nil {
		return nil, err
	}

	// fetch tags
	opts := a.remoteOptions(repo.Name())
	tags, err := remote.List(repo, opts...)
	if err != nil {
		return nil, handleUnauthorizedError(err, repo.Name())
	}

	foundAssets := map[string]*inventory.Asset{}
	for i := range tags {
		repoWithTag := repo.Name() + ":" + tags[i]

		ref, err := name.ParseReference(repoWithTag)
		if err != nil {
			return nil, fmt.Errorf("parsing reference %q: %v", repoWithTag, err)
		}

		a, err := a.toAsset(ref, nil, opts...)
		if err != nil {
			return nil, err
		}
		if foundAsset, ok := foundAssets[a.PlatformIds[0]]; ok {
			// only add tags to the first asset
			foundAsset.Labels["docker.io/tags"] = foundAsset.Labels["docker.io/tags"] + "," + a.Labels["docker.io/tags"]
			log.Debug().Str("tags", foundAsset.Labels["docker.io/tags"]).Str("image", foundAsset.Name).Msg("found additional tags for image")
			continue
		}
		foundAssets[a.PlatformIds[0]] = a
	}

	// flatten map
	for k := range foundAssets {
		assets = append(assets, foundAssets[k])
	}
	return assets, nil
}

// ListImages either takes a registry or a repository and tries to fetch as many images as possible
func (a *ImageLister) ListImages(repoName string) ([]*inventory.Asset, error) {
	url, err := url.Parse("//" + repoName)
	if err != nil {
		return nil, fmt.Errorf("registries must be valid RFC 3986 URI authorities: %s", repoName)
	}

	if url.Host == repoName {
		// fetch registry information
		return a.ListRegistry(repoName)
	} else {
		// fetch repo information
		return a.ListRepository(repoName)
	}
}

func (a *ImageLister) GetImage(ref name.Reference, creds []*vault.Credential, opts ...remote.Option) (*inventory.Asset, error) {
	return a.toAsset(ref, creds, opts...)
}

func (a *ImageLister) toAsset(ref name.Reference, creds []*vault.Credential, opts ...remote.Option) (*inventory.Asset, error) {
	desc, err := image.GetImageDescriptor(ref, opts...)
	if err != nil {
		return nil, handleUnauthorizedError(err, ref.Name())
	}
	return assetFromDescriptor(ref, desc, creds), nil
}

// assetFromDescriptor builds the asset for an already-fetched image descriptor.
// It makes no network calls.
func assetFromDescriptor(ref name.Reference, desc *remote.Descriptor, creds []*vault.Credential) *inventory.Asset {
	imgDigest := desc.Digest.String()
	repoName := ref.Context().Name()
	imgTag := ref.Context().Tag(ref.Identifier()).TagStr()
	name := repoName + "@" + containerid.ShortContainerImageID(imgDigest)
	imageUrl := repoName + "@" + imgDigest
	asset := &inventory.Asset{
		PlatformIds: []string{containerid.MondooContainerImageID(imgDigest)},
		Name:        name,
		Connections: []*inventory.Config{
			{
				Type:        string(shared.Type_RegistryImage),
				Host:        imageUrl,
				Credentials: creds,
			},
		},
		State:  inventory.State_STATE_ONLINE,
		Labels: make(map[string]string),
	}

	// The digest may be an index digest; the server resolves index to platform
	// digests. The manifest comes from the same remote.Get as the
	// digest, so the claim costs no extra request.
	asset.AddClaim(containerImageClaimFromDescriptor(imgDigest, desc.Manifest, imageUrl))

	// store digest and tag
	asset.Labels["docker.io/digest"] = imgDigest
	asset.Labels["docker.io/tags"] = imgTag
	log.Debug().Strs("platform-ids", asset.PlatformIds).Msg("asset platform ids")
	return asset
}

// containerImageClaimFromDescriptor builds the container-image claim for a
// discovered registry image: digest, ref and the base64-encoded raw manifest as
// proof of possession. Arch is left out because an index digest has no single
// architecture. An empty manifest leaves the manifest key out; the claim is
// still attached, just without the possession proof.
func containerImageClaimFromDescriptor(digest string, manifest []byte, ref string) *inventory.AssetClaim {
	claim := inventory.NewContainerImageClaim(digest, ref, "")
	if len(manifest) > 0 {
		claim.Claims[inventory.AssetClaimManifest] = base64.StdEncoding.EncodeToString(manifest)
	}
	return claim
}

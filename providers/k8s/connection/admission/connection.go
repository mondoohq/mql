// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	admission "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/version"
)

type Connection struct {
	shared.ManifestParser
	plugin.Connection
	asset     *inventory.Asset
	namespace string
}

func NewConnection(id uint32, asset *inventory.Asset, data string) (shared.Connection, error) {
	c := &Connection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		namespace:  asset.Connections[0].Options[shared.OPTION_NAMESPACE],
	}

	admission, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		log.Error().Err(err).Msg("failed to decode admission review")
		return nil, err
	}

	c.ManifestParser, err = shared.NewManifestParser(admission, "", "")
	if err != nil {
		return nil, err
	}

	res, err := c.AdmissionReviews()
	if err != nil {
		return nil, err
	}

	for _, r := range res {
		if r.Request == nil {
			continue
		}
		// For each admission we want to also parse the object as an individual asset so we
		// can show the admission review and the resource together in the CI/CD view.
		objs, err := resources.ResourcesFromManifest(bytes.NewReader(r.Request.Object.Raw))
		if err != nil {
			log.Error().Err(err).Msg("failed to parse object from admission review")
		}
		c.Objects = append(c.Objects, objs...)
	}
	return c, nil
}

func (c *Connection) ServerVersion() *version.Info {
	return nil
}

// Distro is unknown: there is no API server.
func (c *Connection) Distro() *distro.Result {
	return &distro.Result{Name: distro.Unknown, Evidence: map[string]distro.Evidence{}}
}

func (c *Connection) SupportedResourceTypes() (*resources.ApiResourceIndex, error) {
	return c.ManifestParser.SupportedResourceTypes()
}

func (c *Connection) Runtime() string {
	return "k8s-admission"
}

func (c *Connection) Asset() *inventory.Asset {
	return c.asset
}

func (c *Connection) InventoryConfig() *inventory.Config {
	return c.asset.Connections[0]
}

func (c *Connection) BasePlatformId() (string, error) {
	return c.AssetId()
}

func (c *Connection) AssetId() (string, error) {
	reviews, err := c.AdmissionReviews()
	if err != nil {
		return "", err
	}

	return shared.NewPlatformId(string(reviews[0].Request.UID)), nil
}

func (c *Connection) Name() string {
	return c.asset.Name
}

func (c *Connection) Platform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "k8s-admission",
		Family:                []string{"k8s"},
		Kind:                  "code",
		Runtime:               c.Runtime(),
		Title:                 "Kubernetes Admission",
		TechnologyUrlSegments: []string{"k8s"},
	}
}

func (c *Connection) AdmissionReviews() ([]admission.AdmissionReview, error) {
	res, err := c.Resources("admissionreview.v1.admission", "", "")
	if err != nil {
		return nil, err
	}

	if len(res.Resources) < 1 {
		return nil, fmt.Errorf("no admission review found")
	}

	reviews := make([]admission.AdmissionReview, 0, len(res.Resources))
	for _, r := range res.Resources {
		reviews = append(reviews, *r.(*admission.AdmissionReview))
	}
	return reviews, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

func newMqlPortainerLicense(runtime *plugin.Runtime, l *models.LiblicensePortainerLicense) (*mqlPortainerLicense, error) {
	res, err := CreateResource(runtime, "portainer.license", map[string]*llx.RawData{
		"__id":      llx.StringData("portainer.license/" + l.ID),
		"id":        llx.StringData(l.ID),
		"company":   llx.StringData(l.Company),
		"email":     llx.StringData(l.Email),
		"nodes":     llx.IntData(l.Nodes),
		"created":   llx.TimeDataPtr(unixTimePtr(l.Created)),
		"expiresAt": llx.TimeDataPtr(unixTimePtr(l.ExpiresAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerLicense), nil
}

func (r *mqlPortainer) licenses() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	licenses, err := conn.Client().ListLicenses()
	if err != nil {
		// Licensing is a Portainer Business/Enterprise feature; on Community
		// Edition the endpoint is absent and returns an error. Degrade to an
		// empty list rather than failing the whole scan, but log it so a real
		// failure (auth, network) is still visible.
		log.Warn().Err(err).Msg("could not list Portainer licenses; treating as none (expected on Community Edition)")
		return []any{}, nil
	}

	res := make([]any, 0, len(licenses))
	for _, l := range licenses {
		mqlLicense, err := newMqlPortainerLicense(r.MqlRuntime, l)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLicense)
	}
	return res, nil
}

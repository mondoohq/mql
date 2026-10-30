// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
)

type mqlGcpProjectStorageServiceHmacKeyInternal struct {
	// The service account email is already a field; the project the key was
	// listed under is kept so the account resolves against the right project even
	// when the connection is scoped to an organization or folder.
	projectId string
}

func (g *mqlGcpProjectStorageServiceHmacKey) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.AccessId.Error != nil {
		return "", g.AccessId.Error
	}
	// The access ID is unique per project, so qualify it to keep keys from two
	// projects in one runtime from colliding.
	return "gcp.project.storageService.hmacKey/" + g.ProjectId.Data + "/" + g.AccessId.Data, nil
}

// hmacKeys lists the project's HMAC keys.
//
// These are enumerated separately from service account keys and do not appear in
// a service account's own key list, so a credential-age audit that only walks
// serviceAccount.keys cannot see them.
func (g *mqlGcpProjectStorageService) hmacKeys() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Only the Storage scope: this lister calls nothing else, and serviceAccount()
	// resolves the account through its own resource with its own scopes. Listing
	// HMAC keys needs cloud-platform rather than a read-only Storage scope, which
	// the API does not accept for this method.
	client, err := conn.Client(storage.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	storageSvc, err := storage.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	call := storageSvc.Projects.HmacKeys.List(projectId)
	// Deleted keys are returned only when explicitly requested. They cannot
	// authenticate, so the default view of active and inactive keys is what an
	// audit needs.
	if err := call.Pages(ctx, func(page *storage.HmacKeysMetadata) error {
		for _, key := range page.Items {
			if key == nil {
				continue
			}

			mqlKey, err := CreateResource(g.MqlRuntime, "gcp.project.storageService.hmacKey", map[string]*llx.RawData{
				"accessId":            llx.StringData(key.AccessId),
				"projectId":           llx.StringData(projectId),
				"serviceAccountEmail": llx.StringData(key.ServiceAccountEmail),
				"state":               llx.StringData(key.State),
				"timeCreated":         llx.TimeDataPtr(parseTime(key.TimeCreated)),
				"updated":             llx.TimeDataPtr(parseTime(key.Updated)),
				"etag":                llx.StringData(key.Etag),
			})
			if err != nil {
				return err
			}
			mqlKey.(*mqlGcpProjectStorageServiceHmacKey).projectId = projectId
			res = append(res, mqlKey)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("project", projectId).Msg("could not list Cloud Storage HMAC keys")
			return nil, nil
		}
		return nil, err
	}

	return res, nil
}

// serviceAccount resolves the account the key authenticates as, so an HMAC key
// finding can be traced to the identity it grants and the roles that identity
// holds.
func (g *mqlGcpProjectStorageServiceHmacKey) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	projectId := g.projectId
	if projectId == "" {
		if g.ProjectId.Error != nil {
			return nil, g.ProjectId.Error
		}
		projectId = g.ProjectId.Data
	}

	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		// A key can name a service account from another project, or one that has
		// since been deleted. Neither is an error in the key listing.
		log.Debug().Err(err).Str("email", email).Msg("could not resolve HMAC key service account")
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

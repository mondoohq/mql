// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

type mqlPortainerWebhookInternal struct {
	cacheEndpointId int64
	cacheRegistryId int64
}

func newMqlPortainerWebhook(runtime *plugin.Runtime, w *models.PortainerWebhook) (*mqlPortainerWebhook, error) {
	// The webhook token is deliberately not mapped: it is the whole of the
	// authentication on the redeploy URL.
	res, err := CreateResource(runtime, "portainer.webhook", map[string]*llx.RawData{
		"__id":       llx.StringData("portainer.webhook/" + strconv.FormatInt(w.ID, 10)),
		"id":         llx.IntData(w.ID),
		"type":       llx.StringData(connection.WebhookType(w.Type)),
		"resourceId": llx.StringData(w.ResourceID),
	})
	if err != nil {
		return nil, err
	}
	mqlWebhook := res.(*mqlPortainerWebhook)
	mqlWebhook.cacheEndpointId = w.EndpointID
	mqlWebhook.cacheRegistryId = w.RegistryID
	return mqlWebhook, nil
}

func (r *mqlPortainer) webhooks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	hooks, err := conn.Webhooks()
	if connection.IsForbidden(err) {
		// Listing webhooks is administrator-only; a refusal is not evidence
		// that the instance has none.
		log.Debug().Msg("not permitted to list Portainer webhooks")
		r.Webhooks.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(hooks))
	for _, w := range hooks {
		mqlWebhook, err := newMqlPortainerWebhook(r.MqlRuntime, w)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWebhook)
	}
	return res, nil
}

// environment resolves the environment the webhook redeploys onto.
func (r *mqlPortainerWebhook) environment() (*mqlPortainerEnvironment, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return resolvePortainerEnvironment(r.MqlRuntime, conn, r.cacheEndpointId, &r.Environment)
}

// registry resolves the registry the redeploy pulls its image from.
func (r *mqlPortainerWebhook) registry() (*mqlPortainerRegistry, error) {
	// Portainer registry ids start at 1; 0 means the webhook pulls without a
	// configured registry.
	if r.cacheRegistryId == 0 {
		r.Registry.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	registries, err := conn.Registries()
	if err != nil {
		return nil, err
	}
	for _, reg := range registries {
		if reg.ID == r.cacheRegistryId {
			return newMqlPortainerRegistry(r.MqlRuntime, reg)
		}
	}
	r.Registry.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

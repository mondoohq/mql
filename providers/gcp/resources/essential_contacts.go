// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"google.golang.org/api/essentialcontacts/v1"
	"google.golang.org/api/option"
)

// essentialContactsForParent lists Essential Contacts for a resource parent of
// the form "projects/{id}", "folders/{id}", or "organizations/{id}" and builds
// the corresponding gcp.essentialContact resources.
func essentialContactsForParent(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := conn.Client(essentialcontacts.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	contactSvc, err := essentialcontacts.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var mqlContacts []any
	process := func(page *essentialcontacts.GoogleCloudEssentialcontactsV1ListContactsResponse) error {
		for _, c := range page.Contacts {
			mqlC, err := CreateResource(runtime, "gcp.essentialContact", map[string]*llx.RawData{
				"resourcePath":           llx.StringData(c.Name),
				"email":                  llx.StringData(c.Email),
				"languageTag":            llx.StringData(c.LanguageTag),
				"notificationCategories": llx.ArrayData(convert.SliceAnyToInterface(c.NotificationCategorySubscriptions), types.String),
				"validated":              llx.TimeDataPtr(parseTime(c.ValidateTime)),
				"validationState":        llx.StringData(c.ValidationState),
			})
			if err != nil {
				return err
			}
			mqlContacts = append(mqlContacts, mqlC)
		}
		return nil
	}

	switch {
	case strings.HasPrefix(parent, "organizations/"):
		err = contactSvc.Organizations.Contacts.List(parent).Pages(ctx, process)
	case strings.HasPrefix(parent, "folders/"):
		err = contactSvc.Folders.Contacts.List(parent).Pages(ctx, process)
	default:
		err = contactSvc.Projects.Contacts.List(parent).Pages(ctx, process)
	}
	if err != nil {
		// Only the project path is gated on isServiceEnabled; the organization
		// and folder paths reach the API directly, and org-level
		// essentialcontacts.contacts.list is a separate grant a project-scoped
		// principal rarely holds. Degrade so one missing grant at the org node
		// does not fail the whole query.
		if isSkippable(err) {
			log.Warn().Err(err).Str("parent", parent).Msg("could not list essential contacts")
			return nil, nil
		}
		return nil, err
	}
	return mqlContacts, nil
}

func (g *mqlGcpProject) essentialContacts() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_essential_contacts)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_essential_contacts).Msg("gcp service is not enabled, skipping")
		return nil, nil
	}

	return essentialContactsForParent(g.MqlRuntime, conn, "projects/"+projectId)
}

func (g *mqlGcpOrganization) essentialContacts() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// Id is normally "organizations/{id}" (set from org.Name); guard against a
	// bare id so the parent path is never double-prefixed.
	parent := g.Id.Data
	if !strings.HasPrefix(parent, "organizations/") {
		parent = "organizations/" + parent
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	return essentialContactsForParent(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpFolder) essentialContacts() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// Folder Id is "folders/{id}" when discovered via listing but bare "{id}"
	// when resolved directly; folderResourceName normalizes both.
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	return essentialContactsForParent(g.MqlRuntime, conn, folderResourceName(g.Id.Data))
}

func (g *mqlGcpEssentialContact) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

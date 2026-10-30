// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	directory "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/calendar/v3"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/groupssettings/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
)

// DefaultWorkspaceClientScopes is the OAuth scope set the provider needs. It
// doubles as the list administrators paste into the domain-wide delegation
// grant in the Google Workspace admin console, so it has to stay in exact sync
// with the scopes the resource code asserts: a scope that is asserted but not
// granted makes the whole token request fail with unauthorized_client, and a
// scope that is granted but never asserted is an unnecessary privilege on a
// directory-wide delegation.
var DefaultWorkspaceClientScopes = []string{
	directory.AdminDirectoryCustomerReadonlyScope,
	directory.AdminDirectoryDeviceChromeosReadonlyScope,
	directory.AdminDirectoryDeviceMobileReadonlyScope,
	directory.AdminDirectoryDomainReadonlyScope,
	directory.AdminDirectoryGroupMemberReadonlyScope,
	directory.AdminDirectoryGroupReadonlyScope,
	directory.AdminDirectoryOrgunitReadonlyScope,
	directory.AdminDirectoryRolemanagementReadonlyScope,
	directory.AdminDirectoryUserReadonlyScope,
	directory.AdminDirectoryUserSecurityScope,
	reports.AdminReportsAuditReadonlyScope,
	reports.AdminReportsUsageReadonlyScope,
	calendar.CalendarReadonlyScope,
	calendar.CalendarSettingsReadonlyScope,
	calendar.CalendarAclsReadonlyScope,
	groupssettings.AppsGroupsSettingsScope,
	cloudidentity.CloudIdentityGroupsReadonlyScope,
	cloudidentity.CloudIdentityDevicesReadonlyScope,
	cloudidentity.CloudIdentityPoliciesReadonlyScope,
}

func (c *GoogleWorkspaceConnection) GetWorkspaceCustomer(customerID string) (*directory.Customer, error) {
	client, err := c.Client(directory.AdminDirectoryCustomerReadonlyScope)
	if err != nil {
		return nil, err
	}

	service, err := directory.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return service.Customers.Get(customerID).Do()
}

func (c *GoogleWorkspaceConnection) Client(scope ...string) (*http.Client, error) {
	ctx := context.Background()

	// use service account from secret if one is provided
	if c.cred != nil {
		data, err := credsServiceAccountData(c.cred)
		if err != nil {
			return nil, err
		}
		return serviceAccountAuth(ctx, c.serviceAccountSubject, data, scope...)
	}

	// otherwise fallback to default google sdk authentication
	log.Debug().Msg("fallback to default google sdk authentication")
	return defaultAuth(ctx, scope...)
}

// FIXME: this is something, also the google plugin uses
// once the google plugin is done, we should refactor this
func credsServiceAccountData(cred *vault.Credential) ([]byte, error) {
	switch cred.Type {
	case vault.CredentialType_json:
		return cred.Secret, nil
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", cred.Type)
	}
}

// FIXME: this is something, also the google plugin uses
// once the google plugin is done, we should refactor this
// defaultAuth implements the
func defaultAuth(ctx context.Context, scope ...string) (*http.Client, error) {
	return googleoauth.DefaultClient(ctx, scope...)
}

// FIXME: this is something, also the google plugin uses
// once the google plugin is done, we should refactor this
// serviceAccountAuth implements
func serviceAccountAuth(ctx context.Context, subject string, serviceAccount []byte, scopes ...string) (*http.Client, error) {
	credParams := googleoauth.CredentialsParams{
		Scopes:  scopes,
		Subject: subject,
	}

	credentials, err := googleoauth.CredentialsFromJSONWithParams(ctx, serviceAccount, credParams)
	if err != nil {
		return nil, err
	}

	cleanCtx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())
	client, _, err := transport.NewHTTPClient(cleanCtx, option.WithTokenSource(credentials.TokenSource))
	if err != nil {
		return nil, err
	}

	return client, nil
}

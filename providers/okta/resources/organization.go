// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc"
)

func (o *mqlOktaOrganization) id() (string, error) {
	return "okta/organization/" + o.Id.Data, o.Id.Error
}

func initOktaOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	settings, err := conn.OrgSettings(ctx)
	if err != nil {
		return nil, nil, err
	}
	if settings == nil {
		return nil, nil, errors.New("failed to read Okta org settings: empty response")
	}

	args["id"] = llx.StringData(oktaStr(settings.Id))
	args["companyName"] = llx.StringData(oktaStr(settings.CompanyName))
	args["status"] = llx.StringData(oktaStr(settings.Status))
	args["subdomain"] = llx.StringData(oktaStr(settings.Subdomain))
	args["address1"] = llx.StringData(oktaStr(settings.Address1))
	args["address2"] = llx.StringData(oktaStr(settings.Address2))
	args["city"] = llx.StringData(oktaStr(settings.City))
	args["state"] = llx.StringData(oktaStr(settings.State))
	args["phoneNumber"] = llx.StringData(oktaStr(settings.PhoneNumber))
	args["postalCode"] = llx.StringData(oktaStr(settings.PostalCode))
	args["country"] = llx.StringData(oktaStr(settings.Country))
	args["supportPhoneNumber"] = llx.StringData(oktaStr(settings.SupportPhoneNumber))
	args["website"] = llx.StringData(oktaStr(settings.Website))
	args["endUserSupportHelpURL"] = llx.StringData(oktaStr(settings.EndUserSupportHelpURL))
	args["created"] = llx.TimeDataPtr(settings.Created)
	args["lastUpdated"] = llx.TimeDataPtr(settings.LastUpdated)
	args["expiresAt"] = llx.TimeDataPtr(settings.ExpiresAt)

	return args, nil, nil
}

func (o *mqlOktaOrganization) optOutCommunicationEmails() (bool, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	settings, _, err := client.OrgSettingCommunicationAPI.GetOktaCommunicationSettings(ctx).Execute()
	if err != nil {
		return false, err
	}

	if settings != nil && settings.OptOutEmailUsers != nil {
		return *settings.OptOutEmailUsers, nil
	}

	return false, nil
}

func (o *mqlOktaOrganization) billingContact() (*mqlOktaUser, error) {
	usr, err := o.contactUser("BILLING")
	if err != nil {
		return nil, err
	}
	if usr == nil {
		o.BillingContact.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return usr, nil
}

func (o *mqlOktaOrganization) technicalContact() (*mqlOktaUser, error) {
	usr, err := o.contactUser("TECHNICAL")
	if err != nil {
		return nil, err
	}
	if usr == nil {
		o.TechnicalContact.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return usr, nil
}

// contactUser resolves the okta.user behind one of the org's contact slots.
// Designating a contact is optional: Okta answers 404 when the slot is empty
// and can answer 200 with no user id at all. Both mean "no contact", reported
// as a null field rather than failing the whole okta.organization query.
func (o *mqlOktaOrganization) contactUser(contactType string) (*mqlOktaUser, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	contact, resp, err := client.OrgSettingContactAPI.GetOrgContactUser(ctx, contactType).Execute()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	if contact == nil {
		return nil, nil
	}

	uid := oktaStr(contact.UserId)
	if uid == "" {
		return nil, nil
	}

	usr, _, err := client.UserAPI.GetUser(ctx, uid).Execute()
	if err != nil {
		return nil, err
	}
	if usr == nil {
		return nil, nil
	}

	return newMqlOktaUser(o.MqlRuntime, usr)
}

func (o *mqlOktaOrganization) securityNotificationEmails() (any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	emails, err := apiSupplement.GetSecurityNotificationEmails(
		ctx,
		conn.OrganizationID(),
		ranger.DefaultHttpClient(),
	)
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(emails)
}

// securityNotificationEmailFlag extracts a boolean flag by key from the
// securityNotificationEmails dict. It returns false when the dict is nil, the
// key is absent, or the stored value is not a bool.
func securityNotificationEmailFlag(emails any, key string) bool {
	m, ok := emails.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m[key].(bool)
	if !ok {
		return false
	}
	return v
}

// securityNotificationFlag reads the memoized securityNotificationEmails dict
// and extracts the given boolean key, so the typed fields always agree with the
// dict.
func (o *mqlOktaOrganization) securityNotificationFlag(key string) (bool, error) {
	emails := o.GetSecurityNotificationEmails()
	if emails.Error != nil {
		return false, emails.Error
	}
	return securityNotificationEmailFlag(emails.Data, key), nil
}

func (o *mqlOktaOrganization) reportSuspiciousActivityEnabled() (bool, error) {
	return o.securityNotificationFlag("reportSuspiciousActivityEnabled")
}

func (o *mqlOktaOrganization) sendEmailForNewDeviceEnabled() (bool, error) {
	return o.securityNotificationFlag("sendEmailForNewDeviceEnabled")
}

func (o *mqlOktaOrganization) sendEmailForFactorEnrollmentEnabled() (bool, error) {
	return o.securityNotificationFlag("sendEmailForFactorEnrollmentEnabled")
}

func (o *mqlOktaOrganization) sendEmailForFactorResetEnabled() (bool, error) {
	return o.securityNotificationFlag("sendEmailForFactorResetEnabled")
}

func (o *mqlOktaOrganization) sendEmailForPasswordChangedEnabled() (bool, error) {
	return o.securityNotificationFlag("sendEmailForPasswordChangedEnabled")
}

// threatInsightSettings returns the Threat Insight settings for the organization
func (o *mqlOktaOrganization) threatInsightSettings() (*mqlOktaThreatsConfiguration, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	config, _, err := client.ThreatInsightAPI.GetCurrentConfiguration(ctx).Execute()
	if err != nil {
		return nil, err
	}

	apiSupplement := conn.ApiExtension()

	excludesZones := []any{}
	for i := range config.ExcludeZones {
		zone, err := apiSupplement.GetNetworkZone(ctx, config.ExcludeZones[i])
		if err != nil {
			return nil, err
		}
		mqlZone, err := newMqlOktaNetworkZone(o.MqlRuntime, zone)
		if err != nil {
			return nil, err
		}
		excludesZones = append(excludesZones, mqlZone)
	}

	r, err := CreateResource(o.MqlRuntime, "okta.threatsConfiguration", map[string]*llx.RawData{
		"action":       llx.StringData(config.Action),
		"excludeZones": llx.ArrayData(excludesZones, types.Resource("okta.network")),
		"created":      llx.TimeDataPtr(config.Created),
		"lastUpdated":  llx.TimeDataPtr(config.LastUpdated),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaThreatsConfiguration), nil
}

func (o *mqlOktaThreatsConfiguration) id() (string, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	return "okta.threatsConfiguration/" + conn.OrganizationID(), nil
}

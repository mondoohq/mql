// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// userSecurity reads the project's external authentication configuration. A
// database user with an ldapAuthType is authenticated by whatever host this
// names, so the host and the port it is reached on decide whether those
// credentials cross the network protected.
func (r *mqlMongodbatlas) userSecurity() (*mqlMongodbatlasUserSecurityConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	sec, httpResp, err := atlasClient(r.MqlRuntime).LDAPConfigurationAPI.
		GetUserSecurity(context.Background(), pid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.UserSecurity.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	res, err := newMqlMongodbatlasUserSecurityConfig(r.MqlRuntime, pid, sec)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func newMqlMongodbatlasUserSecurityConfig(runtime *plugin.Runtime, pid string, sec *admin.UserSecurity) (*mqlMongodbatlasUserSecurityConfig, error) {
	args := map[string]*llx.RawData{
		"__id": llx.StringData("mongodbatlas.userSecurityConfig/" + pid),
		// A project with no LDAP block has no LDAP configuration at all, which
		// is not the same claim as "LDAP authentication is switched off", so
		// every LDAP field stays null rather than reporting a default.
		"ldapAuthenticationEnabled":   llx.NilData,
		"ldapAuthorizationEnabled":    llx.NilData,
		"ldapHostname":                llx.NilData,
		"ldapPort":                    llx.NilData,
		"ldapBindUsername":            llx.NilData,
		"ldapAuthzQueryTemplate":      llx.NilData,
		"ldapCaCertificateConfigured": llx.NilData,
		"ldapUserToDnMappings":        llx.NilData,
		// The customer X.509 block is absent when no customer certificate
		// authority has ever been uploaded, which is exactly "not configured".
		"customerX509CasConfigured": llx.BoolData(false),
	}

	if ldap, ok := sec.GetLdapOk(); ok {
		mappings := []any{}
		for _, m := range ldap.GetUserToDNMapping() {
			mappings = append(mappings, map[string]any{
				"match":        m.GetMatch(),
				"ldapQuery":    m.GetLdapQuery(),
				"substitution": m.GetSubstitution(),
			})
		}
		args["ldapAuthenticationEnabled"] = llx.BoolDataPtr(ldap.AuthenticationEnabled)
		args["ldapAuthorizationEnabled"] = llx.BoolDataPtr(ldap.AuthorizationEnabled)
		args["ldapHostname"] = llx.StringDataPtr(ldap.Hostname)
		args["ldapPort"] = llx.IntDataPtr(ldap.Port)
		args["ldapBindUsername"] = llx.StringDataPtr(ldap.BindUsername)
		args["ldapAuthzQueryTemplate"] = llx.StringDataPtr(ldap.AuthzQueryTemplate)
		// The certificate authority is material, not a setting: only whether
		// one is configured is reported.
		args["ldapCaCertificateConfigured"] = llx.BoolData(isSet(ldap.CaCertificate))
		args["ldapUserToDnMappings"] = llx.ArrayData(mappings, types.Dict)
	}

	if x509, ok := sec.GetCustomerX509Ok(); ok {
		args["customerX509CasConfigured"] = llx.BoolData(isSet(x509.Cas))
	}

	res, err := CreateResource(runtime, "mongodbatlas.userSecurityConfig", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasUserSecurityConfig), nil
}

// certificates lists the managed X.509 certificates issued to the database
// user. x509Type reports that a user authenticates by certificate; only this
// listing reports whether the certificate behind that is still valid.
func (r *mqlMongodbatlasDatabaseUser) certificates() ([]any, error) {
	// Atlas issues managed certificates only to users in the external
	// authentication database, and only when the user is set up for X.509. A
	// SCRAM or IAM user genuinely holds none, which is an empty list rather
	// than an unread one.
	if r.DatabaseName.Data != "$external" || r.X509Type.Data == "" || r.X509Type.Data == "NONE" {
		return []any{}, nil
	}

	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()
	username := r.Username.Data

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.X509AuthenticationAPI.
			ListDatabaseUserCerts(ctx, pid, username).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// A denied read leaves the certificate state unknown. Reporting no
			// certificates would read as "this user cannot authenticate", which
			// is a different and unverified claim.
			if isAccessDenied(httpResp) {
				r.Certificates.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			c := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.databaseUserCertificate", map[string]*llx.RawData{
				// The certificate id is a per-project sequence, so the project
				// and the user it was issued to both belong in the key.
				"__id":      llx.StringData("mongodbatlas.databaseUserCertificate/" + pid + "/" + username + "/" + int64ToString(c.GetId())),
				"id":        llx.IntData(c.GetId()),
				"subject":   llx.StringDataPtr(c.Subject),
				"createdAt": llx.TimeDataPtr(c.CreatedAt),
				"notAfter":  llx.TimeDataPtr(c.NotAfter),
			})
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// maintenanceWindow reads the project's maintenance window. numberOfDeferrals
// counts how many times the currently scheduled maintenance has been pushed
// back, which is how a cluster stays on an unpatched build without any setting
// looking wrong.
func (r *mqlMongodbatlas) maintenanceWindow() (*mqlMongodbatlasMaintenanceWindowConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	w, httpResp, err := atlasClient(r.MqlRuntime).MaintenanceWindowsAPI.
		GetMaintenanceWindow(context.Background(), pid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.MaintenanceWindow.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var protectedStart, protectedEnd *int
	if ph, ok := w.GetProtectedHoursOk(); ok {
		protectedStart = ph.StartHourOfDay
		protectedEnd = ph.EndHourOfDay
	}

	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.maintenanceWindowConfig", map[string]*llx.RawData{
		"__id":                         llx.StringData("mongodbatlas.maintenanceWindowConfig/" + pid),
		"dayOfWeek":                    llx.IntDataPtr(w.DayOfWeek),
		"hourOfDay":                    llx.IntDataPtr(w.HourOfDay),
		"numberOfDeferrals":            llx.IntDataPtr(w.NumberOfDeferrals),
		"autoDeferOnceEnabled":         llx.BoolDataPtr(w.AutoDeferOnceEnabled),
		"startAsap":                    llx.BoolDataPtr(w.StartASAP),
		"timeZoneId":                   llx.StringDataPtr(w.TimeZoneId),
		"protectedHoursStartHourOfDay": llx.IntDataPtr(protectedStart),
		"protectedHoursEndHourOfDay":   llx.IntDataPtr(protectedEnd),
		"waveAssignment":               llx.IntDataPtr(w.WaveAssignment),
		"effectiveWaveAssignment":      llx.IntDataPtr(w.EffectiveWaveAssignment),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasMaintenanceWindowConfig), nil
}

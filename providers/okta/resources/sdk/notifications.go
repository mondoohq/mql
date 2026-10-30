// Copyright (c) Okta, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// This code was derived from https://github.com/okta/terraform-provider-okta/blob/master/sdk/security_notification_emails.go
package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type SecurityNotificationEmails struct {
	// New sign-on notification email
	SendEmailForNewDeviceEnabled bool `json:"sendEmailForNewDeviceEnabled"`
	// Password changed notification email
	SendEmailForPasswordChangedEnabled bool `json:"sendEmailForPasswordChangedEnabled"`
	// MFA enrolled notification email
	SendEmailForFactorEnrollmentEnabled bool `json:"sendEmailForFactorEnrollmentEnabled"`
	// MFA reset notification email
	SendEmailForFactorResetEnabled bool `json:"sendEmailForFactorResetEnabled"`
	// Report suspicious activity via email
	ReportSuspiciousActivityEnabled bool `json:"reportSuspiciousActivityEnabled"`
}

// GetSecurityNotificationEmails retrieves the security configuration
func (m *ApiExtension) GetSecurityNotificationEmails(ctx context.Context, orgId string, client *http.Client) (*SecurityNotificationEmails, error) {

	// we need to split the orgId into orgName and domain because this API uses a different domain
	orgName, domain, found := strings.Cut(orgId, ".")
	if !found {
		return nil, errors.New("cound not determine orgName and domain from orgId " + orgId)
	}
	url := fmt.Sprintf("https://%s-admin.%s/api/internal/org/settings/security-notification-settings", orgName, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Authorize through the connection rather than assuming an API token, so
	// this carries whichever credential the org authenticated with.
	if m.Authorize != nil {
		if err := m.Authorize(req); err != nil {
			return nil, err
		}
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode > http.StatusNoContent {
		return nil, errors.New("failed to get security notification emails: " + string(respBody))
	}

	var securityNotificationEmails SecurityNotificationEmails
	err = json.Unmarshal(respBody, &securityNotificationEmails)
	if err != nil {
		return nil, err
	}
	return &securityNotificationEmails, nil
}

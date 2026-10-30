// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// gatewayConfiguration reads the account-wide Gateway settings every Gateway
// rule runs on top of.
//
// The whole resource reports null when the settings cannot be read, rather than
// a resource whose every toggle reads false: a fabricated false on TLS
// decryption or the activity log would report an unreadable account as one with
// its inspection and its audit trail switched off, and pass a policy that says
// "these must not be disabled" for the wrong reason.
func (c *mqlCloudflareOne) gatewayConfiguration() (*mqlCloudflareOneGatewayConfiguration, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	if c.AccountID == "" {
		return nil, errNoAccountBound
	}

	resp, err := conn.Cf.ZeroTrust.Gateway.Configurations.Get(context.TODO(), zero_trust.GatewayConfigurationGetParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	if err != nil {
		if isUnavailable(err) {
			c.GatewayConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	s := resp.Settings

	// A nil UUID means the Cloudflare Root CA handles interception, so there is
	// no customer certificate to name.
	interceptionCertID := s.Certificate.ID
	if interceptionCertID == nilUUID {
		interceptionCertID = ""
	}

	// The API omits max_ttl_secs when no cap is configured, which decodes to 0.
	// Zero is not a meaningful TTL cap, so report it as "no cap set".
	maxTTL := llx.NilData
	if s.MaxTTLSecs > 0 {
		maxTTL = llx.IntData(s.MaxTTLSecs)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.one.gatewayConfiguration", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.one.gatewayConfiguration@" + c.AccountID),

		"tlsDecryptEnabled":  llx.BoolData(s.TLSDecrypt.Enabled),
		"activityLogEnabled": llx.BoolData(s.ActivityLog.Enabled),

		"antivirusDownloadEnabled": llx.BoolData(s.Antivirus.EnabledDownloadPhase),
		"antivirusUploadEnabled":   llx.BoolData(s.Antivirus.EnabledUploadPhase),
		"antivirusFailClosed":      llx.BoolData(s.Antivirus.FailClosed),

		"bodyScanningInspectionMode": llx.StringData(string(s.BodyScanning.InspectionMode)),

		"urlBrowserIsolationEnabled":         llx.BoolData(s.BrowserIsolation.URLBrowserIsolationEnabled),
		"nonIdentityBrowserIsolationEnabled": llx.BoolData(s.BrowserIsolation.NonIdentityEnabled),

		"protocolDetectionEnabled": llx.BoolData(s.ProtocolDetection.Enabled),

		"sandboxEnabled":        llx.BoolData(s.Sandbox.Enabled),
		"sandboxFallbackAction": llx.StringData(string(s.Sandbox.FallbackAction)),

		"fipsTls":        llx.BoolData(s.Fips.TLS),
		"inspectionMode": llx.StringData(string(s.Inspection.Mode)),

		"hostSelectorEnabled":          llx.BoolData(s.HostSelector.Enabled),
		"extendedEmailMatchingEnabled": llx.BoolData(s.ExtendedEmailMatching.Enabled),

		"maxTtlSeconds":             maxTTL,
		"interceptionCertificateId": llx.StringData(interceptionCertID),

		"createdAt": timeOrNil(resp.CreatedAt),
		"updatedAt": timeOrNil(resp.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflareOneGatewayConfiguration), nil
}

// nilUUID is the all-zero UUID Cloudflare returns for a Gateway interception
// certificate when the Cloudflare Root CA is in use rather than a customer
// certificate.
const nilUUID = "00000000-0000-0000-0000-000000000000"

func (c *mqlCloudflareOneGatewayRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) gatewayRules() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Gateway.Rules.ListAutoPaging(context.TODO(), zero_trust.GatewayRuleListParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	for iter.Next() {
		rec := iter.Current()

		filters := make([]any, len(rec.Filters))
		for j, f := range rec.Filters {
			filters[j] = string(f)
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.gatewayRule", map[string]*llx.RawData{
			"id":            llx.StringData(rec.ID),
			"name":          llx.StringData(rec.Name),
			"description":   llx.StringData(rec.Description),
			"action":        llx.StringData(string(rec.Action)),
			"enabled":       llx.BoolData(rec.Enabled),
			"precedence":    llx.IntData(rec.Precedence),
			"traffic":       llx.StringData(rec.Traffic),
			"identity":      llx.StringData(rec.Identity),
			"devicePosture": llx.StringData(rec.DevicePosture),
			"filters":       llx.ArrayData(filters, types.String),
			"version":       llx.IntData(rec.Version),
			"createdAt":     timeOrNil(rec.CreatedAt),
			"updatedAt":     timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

func (c *mqlCloudflareOneList) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) lists() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Gateway.Lists.ListAutoPaging(context.TODO(), zero_trust.GatewayListListParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.list", map[string]*llx.RawData{
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"type":        llx.StringData(string(rec.Type)),
			"description": llx.StringData(rec.Description),
			"count":       llx.IntData(int64(rec.Count)),
			"createdAt":   timeOrNil(rec.CreatedAt),
			"updatedAt":   timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

func (c *mqlCloudflareOneLocation) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// gatewayLocation is the response shape of the gateway-locations endpoint. The
// cloudflare-go typed Location no longer exposes anonymized_logs_enabled, so
// we read the endpoint via the client's generic Get to preserve that field.
type gatewayLocation struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	DOHSubdomain          string    `json:"doh_subdomain"`
	IP                    string    `json:"ip"`
	AnonymizedLogsEnabled bool      `json:"anonymized_logs_enabled"`
	ClientDefault         bool      `json:"client_default"`
	ECSSupport            bool      `json:"ecs_support"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func (c *mqlCloudflareOne) locations() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := cfGetPaged[gatewayLocation](conn, fmt.Sprintf("accounts/%s/gateway/locations", c.AccountID))
	if err != nil {
		return degradedList(err)
	}

	var result []any
	for i := range records {
		rec := records[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.location", map[string]*llx.RawData{
			"id":                    llx.StringData(rec.ID),
			"name":                  llx.StringData(rec.Name),
			"dohSubdomain":          llx.StringData(rec.DOHSubdomain),
			"ip":                    llx.StringData(rec.IP),
			"anonymizedLogsEnabled": llx.BoolData(rec.AnonymizedLogsEnabled),
			"clientDefault":         llx.BoolData(rec.ClientDefault),
			"ecsSupport":            llx.BoolData(rec.ECSSupport),
			"createdAt":             timeOrNil(rec.CreatedAt),
			"updatedAt":             timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}

func (c *mqlCloudflareOneDlpProfile) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOne) dlpProfiles() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.DLP.Profiles.ListAutoPaging(context.TODO(), zero_trust.DLPProfileListParams{
		AccountID: cloudflare.F(c.AccountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.one.dlpProfile", map[string]*llx.RawData{
			"id":                llx.StringData(rec.ID),
			"name":              llx.StringData(rec.Name),
			"type":              llx.StringData(string(rec.Type)),
			"description":       llx.StringData(rec.Description),
			"allowedMatchCount": llx.IntData(rec.AllowedMatchCount),
			"ocrEnabled":        llx.BoolData(rec.OCREnabled),
			"createdAt":         timeOrNil(rec.CreatedAt),
			"updatedAt":         timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

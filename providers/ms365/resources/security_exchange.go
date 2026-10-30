// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// Note: outlookScope is already defined in ms365_exchange.go

var hostedConnectionFilterPolicyScript = `
$appId = '%s'
$organization = '%s'
$tenantId = '%s'
$outlookToken = '%s'

Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AccessToken $outlookToken -AppID $appId -Organization $organization -ShowBanner:$false -ShowProgress:$false

$HostedConnectionFilterPolicy = (Get-HostedConnectionFilterPolicy -Identity Default)

$result = New-Object PSObject
Add-Member -InputObject $result -MemberType NoteProperty -Name HostedConnectionFilterPolicy -Value $HostedConnectionFilterPolicy

Disconnect-ExchangeOnline -Confirm:$false

ConvertTo-Json -Depth 4 $result
`

type HostedConnectionFilterPolicyReport struct {
	HostedConnectionFilterPolicy *HostedConnectionFilterPolicyData `json:"HostedConnectionFilterPolicy"`
}

type HostedConnectionFilterPolicyData struct {
	Identity         string   `json:"Identity"`
	AdminDisplayName string   `json:"AdminDisplayName"`
	IPAllowList      []string `json:"IPAllowList"`
	IPBlockList      []string `json:"IPBlockList"`
	EnableSafeList   bool     `json:"EnableSafeList"`
}

type mqlMicrosoftSecurityExchangeInternal struct {
	reportLock sync.Mutex
	fetched    bool
	fetchErr   error
	report     *HostedConnectionFilterPolicyReport
}

type mqlMicrosoftSecurityExchangeAntispamInternal struct {
	// Inherits from parent
}

type mqlMicrosoftSecurityExchangeAntispamHostedConnectionFilterPolicyInternal struct {
	// Inherits from parent
}

func (r *mqlMicrosoftSecurity) exchange() (*mqlMicrosoftSecurityExchange, error) {
	resource, err := CreateResource(r.MqlRuntime, ResourceMicrosoftSecurityExchange, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftSecurityExchange), nil
}

func (r *mqlMicrosoftSecurityExchange) antispam() (*mqlMicrosoftSecurityExchangeAntispam, error) {
	resource, err := CreateResource(r.MqlRuntime, ResourceMicrosoftSecurityExchangeAntispam, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftSecurityExchangeAntispam), nil
}

func (r *mqlMicrosoftSecurityExchangeAntispam) hostedConnectionFilterPolicy() (*mqlMicrosoftSecurityExchangeAntispamHostedConnectionFilterPolicy, error) {
	// Create a new exchange resource to get the report
	exchangeResource, err := CreateResource(r.MqlRuntime, ResourceMicrosoftSecurityExchange, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	report, err := exchangeResource.(*mqlMicrosoftSecurityExchange).getHostedConnectionFilterPolicyReport()
	if err != nil {
		return nil, err
	}

	if report.HostedConnectionFilterPolicy == nil {
		return nil, errors.New("no hosted connection filter policy found")
	}

	policy := report.HostedConnectionFilterPolicy

	resource, err := CreateResource(r.MqlRuntime, ResourceMicrosoftSecurityExchangeAntispamHostedConnectionFilterPolicy,
		map[string]*llx.RawData{
			// Singular resource: always fetched with -Identity Default, so the
			// index fallback can never fire and 0 is a constant.
			"__id":             llx.StringData(exchangeEntryID("hostedConnectionFilterPolicy", policy.Identity, 0)),
			"identity":         llx.StringData(policy.Identity),
			"adminDisplayName": llx.StringData(policy.AdminDisplayName),
			"ipAllowList":      llx.ArrayData(convert.SliceAnyToInterface(policy.IPAllowList), types.String),
			"ipBlockList":      llx.ArrayData(convert.SliceAnyToInterface(policy.IPBlockList), types.String),
			"enableSafeList":   llx.BoolData(policy.EnableSafeList),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftSecurityExchangeAntispamHostedConnectionFilterPolicy), nil
}

func initMicrosoftSecurityExchangeAntispamHostedConnectionFilterPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Create the parent antispam resource and call its method
	antispamResource, err := CreateResource(runtime, ResourceMicrosoftSecurityExchangeAntispam, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	policy, err := antispamResource.(*mqlMicrosoftSecurityExchangeAntispam).hostedConnectionFilterPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

func (r *mqlMicrosoftSecurityExchange) getHostedConnectionFilterPolicyReport() (*HostedConnectionFilterPolicyReport, error) {
	r.reportLock.Lock()
	defer r.reportLock.Unlock()

	if r.fetched {
		return r.report, r.fetchErr
	}

	errHandler := func(err error) (*HostedConnectionFilterPolicyReport, error) {
		r.fetchErr = err
		r.fetched = true
		return nil, err
	}

	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)

	// Get organization info
	microsoft, err := CreateResource(r.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return errHandler(err)
	}

	tenantDomainName := microsoft.(*mqlMicrosoft).GetTenantDomainName()
	if tenantDomainName.Error != nil {
		return errHandler(tenantDomainName.Error)
	}

	organization := tenantDomainName.Data
	if organization == "" {
		return errHandler(errors.New("no organization provided, unable to fetch hosted connection filter policy"))
	}

	ctx := context.Background()
	token := conn.Token()
	outlookToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{outlookScope},
	})
	if err != nil {
		return errHandler(err)
	}

	client := newExchangeRestClient(exchangeAdminApiHost, conn.TenantId(), organization, outlookToken.Token)
	report, err := fetchHostedConnectionFilterPolicyViaRest(ctx, client)
	if err != nil {
		// PowerShell is a client for this same endpoint, so a throttle or an
		// outage would only repeat itself over a slower transport and be
		// reported as a PowerShell failure. Surface the real cause instead.
		if exchangeErrorIsTransient(err) {
			return errHandler(err)
		}
		log.Warn().Err(err).Msg("exchange online admin endpoint unavailable, falling back to powershell")
		report, err = fetchHostedConnectionFilterPolicyViaPowershell(conn, organization, outlookToken.Token)
		if err != nil {
			return errHandler(err)
		}
	}

	r.report = report
	r.fetched = true
	return report, nil
}

func fetchHostedConnectionFilterPolicyViaPowershell(conn *connection.Ms365Connection, organization string, token string) (*HostedConnectionFilterPolicyReport, error) {
	fmtScript := fmt.Sprintf(hostedConnectionFilterPolicyScript, conn.ClientId(), organization, conn.TenantId(), token)
	res, err := conn.CheckAndRunPowershellScript(fmtScript)
	if err != nil {
		return nil, err
	}

	if res.ExitStatus != 0 {
		data, err := io.ReadAll(res.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to generate hosted connection filter policy report (exit code %d): %s", res.ExitStatus, string(data))
	}

	data, err := io.ReadAll(res.Stdout)
	if err != nil {
		return nil, err
	}
	logger.DebugDumpJSON("hosted-connection-filter-policy-report", data)

	report := &HostedConnectionFilterPolicyReport{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, err
	}
	return report, nil
}

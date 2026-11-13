// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

type mqlCloudflareOneOrganizationInternal struct {
	accountID string

	trustLock    sync.Mutex
	trustFetched bool
	trust        *zero_trust.OrganizationTrustSettingGetResponse
	trustErr     error
}

// trustSettings fetches the organization's cross-account trust settings once
// and shares the result between the fields that read it. A nil result with a
// nil error means the settings could not be read and the fields report null.
func (o *mqlCloudflareOneOrganization) trustSettings() (*zero_trust.OrganizationTrustSettingGetResponse, error) {
	o.trustLock.Lock()
	defer o.trustLock.Unlock()
	if o.trustFetched {
		return o.trust, o.trustErr
	}

	conn := o.MqlRuntime.Connection.(*connection.CloudflareConnection)
	res, err := conn.Cf.ZeroTrust.Organizations.TrustSettings.Get(context.TODO(), zero_trust.OrganizationTrustSettingGetParams{
		AccountID: cloudflare.F(o.accountID),
	})
	switch {
	case err == nil:
		o.trust = res
	case !plugin.StructuredErrors() && isUnavailable(err):
		// v13 behaviour: a refused or missing endpoint reads as null (ADR 046 §9).
	default:
		o.trustErr = err
	}
	o.trustFetched = true
	return o.trust, o.trustErr
}

func (o *mqlCloudflareOneOrganization) grantTrustToAllAccountsInOrg() (bool, error) {
	ts, err := o.trustSettings()
	if err != nil {
		return false, err
	}
	if ts == nil {
		o.GrantTrustToAllAccountsInOrg.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return ts.GrantTrustToAllAccountsInOrg, nil
}

func (o *mqlCloudflareOneOrganization) trustedAccounts() ([]any, error) {
	ts, err := o.trustSettings()
	if err != nil {
		return nil, err
	}
	if ts == nil || len(ts.TrustingAccounts) == 0 {
		return []any{}, nil
	}

	root, err := CreateResource(o.MqlRuntime, "cloudflare", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	known := root.(*mqlCloudflare).GetAccounts()
	if known.Error != nil {
		return nil, known.Error
	}
	byID := make(map[string]any, len(known.Data))
	for _, a := range known.Data {
		byID[a.(*mqlCloudflareAccount).Id.Data] = a
	}

	result := make([]any, 0, len(ts.TrustingAccounts))
	for _, id := range dedupeStrings(ts.TrustingAccounts) {
		if acc, ok := byID[id]; ok {
			result = append(result, acc)
			continue
		}
		// An account outside the token's reach: keep its id, and null every
		// field the accounts list would have supplied.
		acc, err := CreateResource(o.MqlRuntime, "cloudflare.account", map[string]*llx.RawData{
			"id":        llx.StringData(id),
			"name":      llx.NilData,
			"type":      llx.NilData,
			"settings":  llx.NilData,
			"createdOn": llx.NilData,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, acc)
	}
	return result, nil
}

// dedupeStrings drops empty and repeated values, keeping first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

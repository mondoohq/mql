// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"sync"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/r2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareR2) id() (string, error) {
	return "cloudflare.r2", nil
}

type mqlCloudflareR2Internal struct {
	AccountID string
}

func newR2(runtime *plugin.Runtime, accountID string) (*mqlCloudflareR2, error) {
	res, err := CreateResource(runtime, "cloudflare.r2", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.r2@" + accountID),
	})
	if err != nil {
		return nil, err
	}

	r2 := res.(*mqlCloudflareR2)
	r2.AccountID = accountID

	return r2, nil
}

// initCloudflareR2 binds the connection's account when `cloudflare.r2` is
// reached bare, i.e. not through cloudflare.account.r2. R2 is account-scoped, so
// without this the resource is built with an empty AccountID and every request
// goes to /accounts//r2/buckets.
func initCloudflareR2(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	accountID, err := connectionAccountID(runtime)
	if err != nil {
		return nil, nil, err
	}

	res, err := newR2(runtime, accountID)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (c *mqlCloudflareAccount) r2() (*mqlCloudflareR2, error) {
	return newR2(c.MqlRuntime, c.Id.Data)
}

type mqlCloudflareR2BucketInternal struct {
	accountID string

	publicAccessLock        sync.Mutex
	publicAccessFetched     bool
	publicAccessAvailable   bool
	cachePublicAccessOn     bool
	cachePublicAccessDomain string

	customDomainsLock      sync.Mutex
	customDomainsFetched   bool
	customDomainsAvailable bool
	cacheCustomDomains     []r2.BucketDomainCustomListResponseDomain
}

func (c *mqlCloudflareR2Bucket) id() (string, error) {
	if c.accountID == "" {
		return c.GetName().Data, nil
	}
	return c.accountID + "/" + c.GetName().Data, nil
}

// buckets enumerates R2 buckets across the account. The cloudflare-go typed
// bucket list response doesn't surface the pagination cursor, so we call the
// endpoint directly via the client's generic Get and follow
// `result_info.cursor` to walk every page.
func (c *mqlCloudflareR2) buckets() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	accountID := c.mqlCloudflareR2Internal.AccountID
	if accountID == "" {
		return nil, errNoAccountBound
	}

	var (
		result  []any
		cursor  string
		perPage = 100
	)

	for {
		uri := fmt.Sprintf("accounts/%s/r2/buckets?per_page=%d", accountID, perPage)
		if cursor != "" {
			uri += "&cursor=" + cursor
		}

		var env struct {
			Result struct {
				Buckets []r2.Bucket `json:"buckets"`
			} `json:"result"`
			ResultInfo struct {
				Cursor  string `json:"cursor"`
				Cursors struct {
					After string `json:"after"`
				} `json:"cursors"`
			} `json:"result_info"`
		}
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			// R2 is a gated add-on; an account without it returns 403
			// ("Please enable R2 through the Cloudflare Dashboard"). Degrade
			// to empty like the other add-on-gated list accessors.
			return degradedList(err)
		}

		for i := range env.Result.Buckets {
			bucket := env.Result.Buckets[i]
			res, err := CreateResource(c.MqlRuntime, "cloudflare.r2.bucket", map[string]*llx.RawData{
				"__id":      llx.StringData(accountID + "/" + bucket.Name),
				"name":      llx.StringData(bucket.Name),
				"location":  llx.StringData(string(bucket.Location)),
				"createdOn": timeOrNil(parseRFC3339(bucket.CreationDate)),
			})
			if err != nil {
				return nil, err
			}

			mqlBucket := res.(*mqlCloudflareR2Bucket)
			mqlBucket.accountID = accountID

			result = append(result, res)
		}

		next := env.ResultInfo.Cursor
		if next == "" {
			next = env.ResultInfo.Cursors.After
		}
		if next == "" || next == cursor {
			break
		}
		cursor = next
	}

	return result, nil
}

// fetchPublicAccess fetches the bucket's managed-domain (r2.dev) public-access
// configuration. The `available` return is false when the bucket has no managed
// domain or the caller lacks access to read it; in that case the calling
// computed method should mark its field null.
func (c *mqlCloudflareR2Bucket) fetchPublicAccess() (available, enabled bool, domain string, err error) {
	if c.publicAccessFetched {
		return c.publicAccessAvailable, c.cachePublicAccessOn, c.cachePublicAccessDomain, nil
	}
	c.publicAccessLock.Lock()
	defer c.publicAccessLock.Unlock()
	if c.publicAccessFetched {
		return c.publicAccessAvailable, c.cachePublicAccessOn, c.cachePublicAccessDomain, nil
	}

	if c.accountID == "" {
		c.publicAccessFetched = true
		return false, false, "", nil
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	resp, rerr := conn.Cf.R2.Buckets.Domains.Managed.List(context.TODO(), c.GetName().Data, r2.BucketDomainManagedListParams{
		AccountID: cloudflare.F(c.accountID),
	})
	if rerr != nil {
		if isUnavailable(rerr) {
			c.publicAccessFetched = true
			return false, false, "", nil
		}
		return false, false, "", rerr
	}

	c.publicAccessAvailable = true
	c.cachePublicAccessOn = resp.Enabled
	c.cachePublicAccessDomain = resp.Domain
	c.publicAccessFetched = true
	return c.publicAccessAvailable, c.cachePublicAccessOn, c.cachePublicAccessDomain, nil
}

func (c *mqlCloudflareR2Bucket) publicAccessEnabled() (bool, error) {
	available, enabled, _, err := c.fetchPublicAccess()
	if err != nil {
		return false, err
	}
	if !available {
		c.PublicAccessEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return enabled, nil
}

func (c *mqlCloudflareR2Bucket) publicAccessDomain() (string, error) {
	available, _, domain, err := c.fetchPublicAccess()
	if err != nil {
		return "", err
	}
	if !available {
		c.PublicAccessDomain.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return domain, nil
}

// fetchCustomDomains lists the bucket's custom domains. A custom domain serves
// the bucket's objects on the internet independently of the managed r2.dev
// subdomain, so this is the second half of the bucket's public-exposure answer.
//
// The endpoint returns the whole set in one `result.domains` array with no
// cursor or page counter in the envelope, so there is nothing to page through.
//
// The `available` return is false when the caller cannot read the domain list;
// callers must not read that as "no custom domains".
func (c *mqlCloudflareR2Bucket) fetchCustomDomains() (available bool, domains []r2.BucketDomainCustomListResponseDomain, err error) {
	if c.customDomainsFetched {
		return c.customDomainsAvailable, c.cacheCustomDomains, nil
	}
	c.customDomainsLock.Lock()
	defer c.customDomainsLock.Unlock()
	if c.customDomainsFetched {
		return c.customDomainsAvailable, c.cacheCustomDomains, nil
	}

	if c.accountID == "" {
		c.customDomainsFetched = true
		return false, nil, nil
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	resp, rerr := conn.Cf.R2.Buckets.Domains.Custom.List(context.TODO(), c.GetName().Data, r2.BucketDomainCustomListParams{
		AccountID: cloudflare.F(c.accountID),
	})
	if rerr != nil {
		if isUnavailable(rerr) {
			c.customDomainsFetched = true
			return false, nil, nil
		}
		return false, nil, rerr
	}

	c.customDomainsAvailable = true
	c.cacheCustomDomains = resp.Domains
	c.customDomainsFetched = true
	return c.customDomainsAvailable, c.cacheCustomDomains, nil
}

func (c *mqlCloudflareR2Bucket) customDomains() ([]any, error) {
	available, domains, err := c.fetchCustomDomains()
	if err != nil {
		return nil, err
	}
	if !available {
		return []any{}, nil
	}

	result := make([]any, 0, len(domains))
	for i := range domains {
		d := domains[i]
		res, err := CreateResource(c.MqlRuntime, "cloudflare.r2.bucket.customDomain", map[string]*llx.RawData{
			"__id":            llx.StringData(c.accountID + "/" + c.GetName().Data + "/domains/custom/" + d.Domain),
			"domain":          llx.StringData(d.Domain),
			"enabled":         llx.BoolData(d.Enabled),
			"ownershipStatus": llx.StringData(string(d.Status.Ownership)),
			"sslStatus":       llx.StringData(string(d.Status.SSL)),
			// A domain only terminates TLS once its certificate is issued;
			// initializing/pending/error all mean there is no usable cert yet.
			"certificateActive": llx.BoolData(d.Status.SSL == r2.BucketDomainCustomListResponseDomainsStatusSSLActive),
			"minTlsVersion":     llx.StringData(string(d.MinTLS)),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}

	return result, nil
}

// isPublic reports whether the bucket is reachable from the internet over
// either of the two independent paths Cloudflare offers: the managed r2.dev
// subdomain, and any custom domain registered against the bucket.
//
// publicAccessEnabled covers only the first, so a bucket published through a
// custom domain reads false there while being world-readable. Use this for the
// exposure question.
//
// When neither path proves the bucket public, the answer is only `false` if
// both were actually read. If either could not be read the field is null, so an
// unreadable bucket is never reported as private.
func (c *mqlCloudflareR2Bucket) isPublic() (bool, error) {
	managedAvailable, managedEnabled, _, err := c.fetchPublicAccess()
	if err != nil {
		return false, err
	}
	if managedAvailable && managedEnabled {
		return true, nil
	}

	customAvailable, domains, err := c.fetchCustomDomains()
	if err != nil {
		return false, err
	}
	for i := range domains {
		if domains[i].Enabled {
			return true, nil
		}
	}

	if !managedAvailable || !customAvailable {
		c.IsPublic.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return false, nil
}

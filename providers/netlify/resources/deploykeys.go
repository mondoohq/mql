// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newNetlifyDeployKey(runtime *plugin.Runtime, rec *deployKeyRecord) (*mqlNetlifyDeployKey, error) {
	res, err := CreateResource(runtime, "netlify.deployKey", map[string]*llx.RawData{
		"id":        llx.StringData(rec.ID),
		"publicKey": llx.StringData(rec.PublicKey),
		"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNetlifyDeployKey), nil
}

// initNetlifyDeployKey resolves a deploy key by its identifier.
func initNetlifyDeployKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	keyID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			keyID = s
		}
	}
	if keyID == "" {
		return nil, nil, errors.New("netlify.deployKey requires an id")
	}

	c := netlifyConn(runtime)

	var rec deployKeyRecord
	if err := c.Get(context.Background(), "/deploy_keys/"+url.PathEscape(keyID), nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = keyID
	}

	key, err := newNetlifyDeployKey(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, key, nil
}

func (k *mqlNetlifyDeployKey) id() (string, error) {
	return k.Id.Data, k.Id.Error
}

// sites reports which sites clone with this key, so a key that no site
// references stands out as one still granting repository access.
func (k *mqlNetlifyDeployKey) sites() ([]any, error) {
	root, err := getNetlify(k.MqlRuntime)
	if err != nil {
		return nil, err
	}

	sites := root.GetSites()
	if sites.Error != nil {
		return nil, sites.Error
	}

	var res []any
	for _, it := range sites.Data {
		site, ok := it.(*mqlNetlifySite)
		if !ok {
			continue
		}
		if site.cacheDeployKeyID == k.Id.Data {
			res = append(res, site)
		}
	}
	return res, nil
}

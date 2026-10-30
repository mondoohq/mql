// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// secrets enumerates the account's stored secrets. Only metadata is
// surfaced; the stored secret values are never exposed.
func (r *mqlDigitalocean) secrets() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	var all []any
	opt := &godo.ListOptions{PerPage: 200}
	for {
		list, resp, err := client.Secrets.List(ctx, opt)
		if err != nil {
			return nil, err
		}
		if list != nil {
			for _, s := range list.Secrets {
				if s == nil {
					continue
				}

				var createdAt, updatedAt, deleteRequestedAt *time.Time
				if t, perr := time.Parse(time.RFC3339, s.CreatedAt); perr == nil {
					createdAt = &t
				}
				if t, perr := time.Parse(time.RFC3339, s.UpdatedAt); perr == nil {
					updatedAt = &t
				}
				if s.DeleteRequestedAt != nil {
					if t, perr := time.Parse(time.RFC3339, *s.DeleteRequestedAt); perr == nil {
						deleteRequestedAt = &t
					}
				}

				res, err := CreateResource(r.MqlRuntime, "digitalocean.secret", map[string]*llx.RawData{
					"__id":              llx.StringData(s.Region + "/" + s.Name),
					"name":              llx.StringData(s.Name),
					"region":            llx.StringData(s.Region),
					"version":           llx.IntData(int64(s.Version)),
					"createdAt":         llx.TimeDataPtr(createdAt),
					"updatedAt":         llx.TimeDataPtr(updatedAt),
					"deleteRequestedAt": llx.TimeDataPtr(deleteRequestedAt),
				})
				if err != nil {
					return nil, err
				}
				all = append(all, res)
			}
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

// versions lists the version history of the secret. The version API is
// per-secret, so it requires a separate call.
func (r *mqlDigitaloceanSecret) versions() ([]any, error) {
	name := r.Name.Data
	region := r.Region.Data
	if name == "" || region == "" {
		return []any{}, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	versions, _, err := client.Secrets.ListVersions(ctx, name, region)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(versions))
	for _, v := range versions {
		if v == nil {
			continue
		}
		out = append(out, secretVersionDict(v))
	}
	return out, nil
}

// secretVersionDict builds the dict for one secret version. dict values
// must be JSON-native (dict2primitive rejects *time.Time), so the API's
// RFC3339 timestamps are kept as strings.
func secretVersionDict(v *godo.SecretVersion) map[string]any {
	return map[string]any{
		"version":   int64(v.Version),
		"createdAt": v.CreatedAt,
		"updatedAt": v.UpdatedAt,
	}
}

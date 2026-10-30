// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/databricks/databricks-sdk-go/service/sharing"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) deltaSharingRecipients() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	recipients, err := ws.Recipients.ListAll(context.Background(), sharing.ListRecipientsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range recipients {
		rec := recipients[i]

		// Only the non-secret allowed IP ranges are exposed. The token
		// activation URLs and secret values are never modeled.
		var allowedIPs []any
		if rec.IpAccessList != nil {
			allowedIPs = strSlice(rec.IpAccessList.AllowedIpAddresses)
		} else {
			allowedIPs = []any{}
		}

		// Per-token metadata excludes ActivationUrl and any secret material.
		tokens := []any{}
		for j := range rec.Tokens {
			t := rec.Tokens[j]
			tokens = append(tokens, map[string]any{
				"id":             t.Id,
				"expirationTime": epochMsRFC3339(t.ExpirationTime),
				"createdAt":      epochMsRFC3339(t.CreatedAt),
			})
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.deltaSharingRecipient", map[string]*llx.RawData{
			"__id":                           llx.StringData("databricks.deltaSharingRecipient/" + rec.Name),
			"name":                           llx.StringData(rec.Name),
			"owner":                          llx.StringData(rec.Owner),
			"comment":                        llx.StringData(rec.Comment),
			"authenticationType":             llx.StringData(string(rec.AuthenticationType)),
			"activated":                      llx.BoolData(rec.Activated),
			"dataRecipientGlobalMetastoreId": llx.StringData(rec.DataRecipientGlobalMetastoreId),
			"ipAccessList":                   llx.ArrayData(allowedIPs, types.String),
			"tokens":                         llx.ArrayData(tokens, types.Dict),
			"createdAt":                      llx.TimeDataPtr(epochMsTime(rec.CreatedAt)),
			"createdBy":                      llx.StringData(rec.CreatedBy),
			"updatedAt":                      llx.TimeDataPtr(epochMsTime(rec.UpdatedAt)),
			"updatedBy":                      llx.StringData(rec.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricks) deltaSharingShares() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	shares, err := ws.Shares.ListAll(context.Background(), sharing.ListSharesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range shares {
		s := shares[i]

		objects := []any{}
		for j := range s.Objects {
			o := s.Objects[j]
			objects = append(objects, map[string]any{
				"name":           o.Name,
				"dataObjectType": string(o.DataObjectType),
				"sharedAs":       o.SharedAs,
				"cdfEnabled":     o.CdfEnabled,
				"comment":        o.Comment,
				"addedAt":        epochMsRFC3339(o.AddedAt),
				"addedBy":        o.AddedBy,
			})
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.deltaSharingShare", map[string]*llx.RawData{
			"__id":          llx.StringData("databricks.deltaSharingShare/" + s.Name),
			"name":          llx.StringData(s.Name),
			"owner":         llx.StringData(s.Owner),
			"comment":       llx.StringData(s.Comment),
			"sharedObjects": llx.ArrayData(objects, types.Dict),
			"createdAt":     llx.TimeDataPtr(epochMsTime(s.CreatedAt)),
			"createdBy":     llx.StringData(s.CreatedBy),
			"updatedAt":     llx.TimeDataPtr(epochMsTime(s.UpdatedAt)),
			"updatedBy":     llx.StringData(s.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// epochMsRFC3339 renders a Databricks epoch-millisecond timestamp as an RFC3339
// string for embedding in a dict, returning an empty string for the
// zero/negative sentinels the API uses for "unset".
func epochMsRFC3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

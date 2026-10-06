// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
)

func (r *mqlExoscale) kmsKeys() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-kms-keys", func(c *v3.Client) ([]v3.ListKmsKeysResponseEntry, error) {
		res, err := c.ListKmsKeys(ctx())
		if err != nil {
			return nil, err
		}
		return res.KmsKeys, nil
	})
	if err != nil {
		return nil, err
	}
	keys := dedupeKmsKeys(items)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		args := map[string]*llx.RawData{
			"__id":                llx.StringData("exoscale.kms.key/" + string(k.ID)),
			"id":                  llx.StringData(string(k.ID)),
			"name":                llx.StringData(k.Name),
			"description":         llx.StringData(k.Description),
			"originZone":          llx.StringData(k.OriginZone),
			"multiZone":           boolData(k.MultiZone),
			"replicas":            stringArrayData(k.Replicas),
			"keySpec":             llx.StringData(k.KeySpec),
			"usage":               llx.StringData(k.Usage),
			"source":              llx.StringData(string(k.Source)),
			"status":              llx.StringData(string(k.Status)),
			"statusSince":         timeData(k.StatusSince),
			"created":             timeData(k.CreatedAT),
			"deleteAt":            timeData(k.DeleteAT),
			"rotationEnabled":     llx.NilData,
			"rotationPeriod":      llx.NilData,
			"nextRotation":        llx.NilData,
			"manualRotationCount": llx.NilData,
		}
		if rot := k.Rotation; rot != nil {
			args["rotationEnabled"] = boolData(rot.Automatic)
			args["rotationPeriod"] = llx.IntData(rot.RotationPeriod)
			args["manualRotationCount"] = llx.IntData(rot.ManualCount)
			if rot.Automatic != nil && *rot.Automatic {
				args["nextRotation"] = timeData(rot.NextAT)
			}
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.kms.key", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// dedupeKmsKeys collapses a multi-zone key, which every replica zone lists
// under the same id, into one entry. The origin zone's record is preferred:
// only it carries the creation time and the replica list.
func dedupeKmsKeys(items []zoned[v3.ListKmsKeysResponseEntry]) []v3.ListKmsKeysResponseEntry {
	var order []v3.UUID
	byID := map[v3.UUID]zoned[v3.ListKmsKeysResponseEntry]{}
	for _, it := range items {
		prev, seen := byID[it.item.ID]
		if !seen {
			order = append(order, it.item.ID)
			byID[it.item.ID] = it
			continue
		}
		if prev.zone != prev.item.OriginZone && it.zone == it.item.OriginZone {
			byID[it.item.ID] = it
		}
	}
	out := make([]v3.ListKmsKeysResponseEntry, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id].item)
	}
	return out
}

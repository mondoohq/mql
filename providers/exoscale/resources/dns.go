// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
)

func (r *mqlExoscale) dnsDomains() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListDNSDomains(ctx())
	if err != nil {
		return nil, classifyError(err, "list-dns-domains")
	}
	out := make([]any, 0, len(res.DNSDomains))
	for _, d := range res.DNSDomains {
		m, err := CreateResource(r.MqlRuntime, "exoscale.dns.domain", map[string]*llx.RawData{
			"__id":    llx.StringData("exoscale.dns.domain/" + string(d.ID)),
			"id":      llx.StringData(string(d.ID)),
			"name":    llx.StringData(d.UnicodeName),
			"created": timeData(d.CreatedAT),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleDnsDomain) records() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListDNSDomainRecords(ctx(), v3.UUID(r.Id.Data))
	if err != nil {
		return nil, classifyError(err, "list-dns-domain-records")
	}
	out := make([]any, 0, len(res.DNSDomainRecords))
	for _, rec := range res.DNSDomainRecords {
		m, err := CreateResource(r.MqlRuntime, "exoscale.dns.domain.record", map[string]*llx.RawData{
			"__id":         llx.StringData("exoscale.dns.domain.record/" + string(rec.ID)),
			"id":           llx.StringData(string(rec.ID)),
			"name":         llx.StringData(rec.Name),
			"type":         llx.StringData(string(rec.Type)),
			"content":      llx.StringData(rec.Content),
			"ttl":          llx.IntData(rec.Ttl),
			"priority":     llx.IntData(rec.Priority),
			"systemRecord": boolData(rec.SystemRecord),
			"created":      timeData(rec.CreatedAT),
			"updated":      timeData(rec.UpdatedAT),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

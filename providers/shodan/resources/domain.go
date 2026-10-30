// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/shadowscatcher/shodan/models"
	"github.com/shadowscatcher/shodan/search"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/shodan/connection"
)

func initShodanDomain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["name"]; !ok {
		// try to get the ip from the connection
		conn := runtime.Connection.(*connection.ShodanConnection)
		if conn.Conf.Options != nil && conn.Conf.Options["search"] == "domain" {
			args["name"] = llx.StringData(conn.Conf.Host)
		}
	}

	if _, ok := args["name"]; !ok {
		return nil, nil, errors.New("missing required argument 'name'")
	}

	return args, nil, nil
}

func (r *mqlShodanDomain) id() (string, error) {
	return "shodan.domain/" + r.Name.Data, nil
}

func (r *mqlShodanDomain) fetchBaseInformation() error {
	conn := r.MqlRuntime.Connection.(*connection.ShodanConnection)
	client := conn.Client()
	if client == nil {
		return errors.New("cannot retrieve new data while using a mock connection")
	}

	// set default information
	r.Tags = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Subdomains = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Nsrecords = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	ctx := context.Background()
	domain := r.Name.Data
	domainSearch := search.DomainQuery{
		Domain: domain,
		Page:   1,
	}

	var tags []string
	subdomains := make([]string, 0)
	nsrecords := make([]models.NsRecord, 0)
	for {
		results, err := client.DnsDomain(ctx, domainSearch)
		if err != nil {
			return err
		}

		tags = results.Tags
		subdomains = append(subdomains, results.Subdomains...)
		nsrecords = append(nsrecords, results.Data...)

		if results.More == false {
			break
		}
		domainSearch.Page++
	}

	r.Tags = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(tags), Error: nil, State: plugin.StateIsSet}
	r.Subdomains = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(subdomains), Error: nil, State: plugin.StateIsSet}

	var mqlNsRecords []any
	for _, nsrecord := range nsrecords {
		// Shodan emits DNS last_seen without a timezone (e.g.
		// "2021-03-15T00:00:00.000000"), so use the shared parser rather than a
		// strict RFC3339 parse that would silently null the field.
		recordResource, err := CreateResource(r.MqlRuntime, "shodan.nsrecord", map[string]*llx.RawData{
			"domain":    llx.StringData(domain),
			"subdomain": llx.StringData(nsrecord.Subdomain),
			"type":      llx.StringData(nsrecord.Type),
			"value":     llx.StringData(nsrecord.Value),
			"lastSeen":  optionalShodanTime(nsrecord.LastSeen),
		})
		if err != nil {
			return err
		}
		mqlNsRecords = append(mqlNsRecords, recordResource)
	}
	r.Nsrecords = plugin.TValue[[]any]{Data: mqlNsRecords, Error: nil, State: plugin.StateIsSet}

	return nil
}

func (r *mqlShodanDomain) tags() ([]any, error) {
	return nil, r.fetchBaseInformation()
}

func (r *mqlShodanDomain) subdomains() ([]any, error) {
	return nil, r.fetchBaseInformation()
}

func (r *mqlShodanDomain) nsrecords() ([]any, error) {
	return nil, r.fetchBaseInformation()
}

func (r *mqlShodanDomain) hosts() ([]any, error) {
	nsrecords := r.GetNsrecords()
	if nsrecords.Error != nil {
		return nil, nsrecords.Error
	}

	// A and AAAA records carry the IP addresses the domain and its subdomains
	// resolve to. Map each unique address to a Shodan host so callers can
	// traverse from a domain to host-level data (ports, vulnerabilities, ...).
	hosts := []any{}
	seen := map[string]struct{}{}
	for _, raw := range nsrecords.Data {
		record, ok := raw.(*mqlShodanNsrecord)
		if !ok {
			continue
		}

		switch record.Type.Data {
		case "A", "AAAA":
		default:
			continue
		}

		ip := record.Value.Data
		if ip == "" {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}

		host, err := NewResource(r.MqlRuntime, "shodan.host", map[string]*llx.RawData{
			"ip": llx.StringData(ip),
		})
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (r *mqlShodanNsrecord) id() (string, error) {
	id := "shodan.nsrecord/" + r.Domain.Data
	if r.Subdomain.Data != "" {
		id += "/" + r.Subdomain.Data
	}
	if r.Type.Data != "" {
		id += "/" + r.Type.Data
	}
	if r.Value.Data != "" {
		id += "/" + r.Value.Data
	}
	return id, nil
}

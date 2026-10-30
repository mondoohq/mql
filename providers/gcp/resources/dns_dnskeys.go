// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// weakDnssecAlgorithms are the DNSSEC signing algorithms that no longer offer
// meaningful collision resistance. RFC 8624 marks RSASHA1 and its NSEC3 variant
// as NOT RECOMMENDED for signing.
//
// Keys are upper-cased for lookup: the Cloud DNS API returns the mnemonic in
// lower case ("rsasha1") while the zone-level key specs and the DNSSEC
// registries spell it in upper case, and both reach this predicate.
var weakDnssecAlgorithms = map[string]struct{}{
	"RSASHA1":            {},
	"RSASHA1-NSEC3-SHA1": {},
}

func isWeakDnssecAlgorithm(algorithm string) bool {
	_, ok := weakDnssecAlgorithms[strings.ToUpper(strings.TrimSpace(algorithm))]
	return ok
}

// dnsKeysHaveWeakAlgorithm reports whether any key published for a zone uses a
// weak signing algorithm.
//
// Inactive keys are included deliberately. Cloud DNS keeps them in the DNSKEY
// record set so resolvers can validate signatures already made with them, so a
// deactivated RSASHA1 key is still a key resolvers trust. Skipping them would
// report a zone mid-rollover as clean while the weak key is still published.
func dnsKeysHaveWeakAlgorithm(keys []*dns.DnsKey) bool {
	for _, key := range keys {
		if key == nil {
			continue
		}
		if isWeakDnssecAlgorithm(key.Algorithm) {
			return true
		}
	}
	return false
}

// loadDnsKeys fetches the zone's live signing keys once and memoizes them for
// every field that reads them.
//
// The second return value reports whether the keys were readable at all. A
// permission gap or a missing zone yields (nil, false, nil) so the caller can
// render the field as null: reporting "no weak keys" for a zone whose keys we
// were never allowed to read would let an audit pass on data that was never
// fetched.
func (g *mqlGcpProjectDnsServiceManagedzone) loadDnsKeys() ([]*dns.DnsKey, bool, error) {
	if g.dnsKeysLoaded.Load() {
		return g.dnsKeysData, g.dnsKeysReadable, g.dnsKeysErr
	}
	g.dnsKeysLock.Lock()
	defer g.dnsKeysLock.Unlock()
	if g.dnsKeysLoaded.Load() {
		return g.dnsKeysData, g.dnsKeysReadable, g.dnsKeysErr
	}
	defer g.dnsKeysLoaded.Store(true)

	g.dnsKeysData, g.dnsKeysReadable, g.dnsKeysErr = g.fetchDnsKeys()
	return g.dnsKeysData, g.dnsKeysReadable, g.dnsKeysErr
}

func (g *mqlGcpProjectDnsServiceManagedzone) fetchDnsKeys() ([]*dns.DnsKey, bool, error) {
	if g.ProjectId.Error != nil {
		return nil, false, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, false, g.Name.Error
	}
	projectId := g.ProjectId.Data
	zoneName := g.Name.Data

	// An unsigned zone has no signing keys, and the API says so with an empty
	// list. Reading dnssecEnabled first turns that into zero API calls for every
	// unsigned zone in the project, and it costs nothing: the value comes from
	// the same ManagedZones.List response that created this resource.
	enabled := g.GetDnssecEnabled()
	if enabled.Error != nil {
		return nil, false, enabled.Error
	}
	if !enabled.Data {
		return nil, true, nil
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, false, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, false, err
	}

	ctx := context.Background()
	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, false, err
	}

	keys := []*dns.DnsKey{}
	req := dnsSvc.DnsKeys.List(projectId, zoneName)
	if err := req.Pages(ctx, func(page *dns.DnsKeysListResponse) error {
		keys = append(keys, page.DnsKeys...)
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("project", projectId).Str("zone", zoneName).
				Msg("cannot read DNSSEC signing keys for managed zone; reporting them as null")
			return nil, false, nil
		}
		return nil, false, err
	}
	return keys, true, nil
}

func (g *mqlGcpProjectDnsServiceManagedzone) dnsKeys() ([]any, error) {
	keys, readable, err := g.loadDnsKeys()
	if err != nil {
		return nil, err
	}
	if !readable {
		// A nil slice still renders as an empty list, which reads as "this zone
		// has no signing keys". Mark the field null so the difference survives.
		g.DnsKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	projectId := g.ProjectId.Data
	zoneName := g.Name.Data

	res := make([]any, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			continue
		}

		digests := make([]any, 0, len(key.Digests))
		for _, d := range key.Digests {
			if d == nil {
				continue
			}
			digests = append(digests, map[string]any{
				"type":   d.Type,
				"digest": d.Digest,
			})
		}

		// The key id is server-defined and only documented as unique within its
		// zone, so the cache key carries the project and the zone as well.
		mqlKey, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.managedzone.dnsKey", map[string]*llx.RawData{
			"__id":         llx.StringData("gcp.project.dnsService.managedzone.dnsKey/" + projectId + "/" + zoneName + "/" + dnsKeyIdentity(key)),
			"id":           llx.StringData(key.Id),
			"keyTag":       llx.IntData(key.KeyTag),
			"algorithm":    llx.StringData(key.Algorithm),
			"keyLength":    llx.IntData(key.KeyLength),
			"type":         llx.StringData(key.Type),
			"isActive":     llx.BoolData(key.IsActive),
			"creationTime": llx.TimeDataPtr(parseTime(key.CreationTime)),
			"description":  llx.StringData(key.Description),
			"publicKey":    llx.StringData(key.PublicKey),
			"digests":      llx.ArrayData(digests, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// dnsKeyIdentity picks the most stable identifier the key carries. Id is
// output-only and always set in practice, but a key that came back without one
// must not collapse onto the same cache entry as every other such key in the
// zone, so fall back to the key tag and role.
func dnsKeyIdentity(key *dns.DnsKey) string {
	if key.Id != "" {
		return key.Id
	}
	return strconv.FormatInt(key.KeyTag, 10) + "/" + key.Type
}

// dnsSecAlgorithmWeak reports whether the zone is signed with a weak algorithm.
//
// This reads the keys the zone is signed with today, not DnssecConfig's default
// key specs: those specify how new keys are generated, so a zone rolled from
// RSASHA1 onto a modern algorithm (or onto RSASHA1 from a modern one) is
// audited against the wrong data if the specs are trusted.
func (g *mqlGcpProjectDnsServiceManagedzone) dnsSecAlgorithmWeak() (bool, error) {
	enabled := g.GetDnssecEnabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	// An unsigned zone has no signing algorithm to be weak. dnssecEnabled is the
	// finding for that zone.
	if !enabled.Data {
		return false, nil
	}

	keys, readable, err := g.loadDnsKeys()
	if err != nil {
		return false, err
	}
	if !readable {
		// Never report "not weak" for keys we could not read: a false here is
		// indistinguishable from a verified-safe zone and the audit passes on
		// data that was never fetched.
		g.DnsSecAlgorithmWeak.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return dnsKeysHaveWeakAlgorithm(keys), nil
}

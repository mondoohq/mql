// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/util/filteropts"
)

// DiscoveryFilters narrows what a scan looks at.
//
// Two of the four dimensions are applied where the fan-out is built rather than
// where a resource is read. Almost every OCI list API answers for one
// compartment in one region, so ociCollect multiplies its lister across
// regions x compartments; narrowing that product is the only place a filter can
// avoid the request rather than discard its result. Region and compartment
// filters therefore also narrow plain MQL queries, not just discovery - asking
// for one compartment and paying to enumerate forty is not a defensible default.
//
// Tag filters cannot work that way. A tag is a property of the resource, so it
// is not known until the request that the filter would have avoided has already
// been made. They are applied per-lister instead, which is also what keeps them
// consistent between discovery and a direct query: discovery reaches assets
// through the same accessor an MQL query uses.
type DiscoveryFilters struct {
	// Regions and Compartments accept the values a user can see in the console:
	// a region key for regions, and either an OCID or a compartment name for
	// compartments. Empty means "no restriction", never "nothing".
	Regions        []string
	ExcludeRegions []string

	Compartments        []string
	ExcludeCompartments []string

	// Tags and ExcludeTags are keyed by the filter key the user typed. A key
	// containing a dot selects a defined tag ("Operations.CostCenter"); a key
	// without one selects a freeform tag ("env"). Values may be a CSV list, in
	// which case any one of them matching is a match.
	Tags        map[string]string
	ExcludeTags map[string]string
}

// DiscoveryFiltersFromOpts reads the filters out of the raw --filters key/value
// options collected by ParseCLI.
func DiscoveryFiltersFromOpts(opts map[string]string) DiscoveryFilters {
	return DiscoveryFilters{
		Regions:             filteropts.ParseCsvSliceOpt(opts, "regions"),
		ExcludeRegions:      filteropts.ParseCsvSliceOpt(opts, "exclude:regions"),
		Compartments:        filteropts.ParseCsvSliceOpt(opts, "compartments"),
		ExcludeCompartments: filteropts.ParseCsvSliceOpt(opts, "exclude:compartments"),
		Tags:                parseMapOpt(opts, "tag:"),
		ExcludeTags:         parseMapOpt(opts, "exclude:tag:"),
	}
}

// parseMapOpt collects the options whose key carries the given prefix, keyed by
// the remainder. "exclude:tag:env" does not carry the "tag:" prefix, so the two
// tag maps do not collide.
func parseMapOpt(opts map[string]string, keyPrefix string) map[string]string {
	res := map[string]string{}
	for k, v := range opts {
		if k == "" || v == "" {
			continue
		}
		if !strings.HasPrefix(k, keyPrefix) {
			continue
		}
		res[strings.TrimPrefix(k, keyPrefix)] = v
	}
	return res
}

// HasRegions reports whether any region filter is set, so a caller can skip the
// selection entirely when there is nothing to apply.
func (f DiscoveryFilters) HasRegions() bool {
	return len(f.Regions) > 0 || len(f.ExcludeRegions) > 0
}

// HasCompartments reports whether any compartment filter is set.
func (f DiscoveryFilters) HasCompartments() bool {
	return len(f.Compartments) > 0 || len(f.ExcludeCompartments) > 0
}

// HasTags reports whether any tag filter is set. Listers gate their tag lookup
// on this so an unfiltered scan does not pay for tags it will not read.
func (f DiscoveryFilters) HasTags() bool {
	return len(f.Tags) > 0 || len(f.ExcludeTags) > 0
}

// AdmitsRegion reports whether a region passes the filters. An exclusion beats
// an inclusion, so naming a region in both leaves it out.
//
// Both identifiers are matched because OCI gives a region two of them and the
// console shows both: the region key is a three-letter code ("IAD") and the
// region name is the identifier that appears in every endpoint and document
// ("us-ashburn-1"). A user writing a filter reaches for the latter, while the
// provider carries the former as the region resource's id, so matching only one
// would silently select nothing.
func (f DiscoveryFilters) AdmitsRegion(key, name string) bool {
	if !f.HasRegions() {
		return true
	}
	if matchesAny(f.ExcludeRegions, key) || matchesAny(f.ExcludeRegions, name) {
		return false
	}
	if len(f.Regions) == 0 {
		return true
	}
	return matchesAny(f.Regions, key) || matchesAny(f.Regions, name)
}

// SelectCompartments returns the OCIDs of the compartments the filters admit.
// A filter value matches either the compartment's OCID or its name, because
// both are things a user reads off the console and neither is more canonical
// from the outside.
//
// The tenancy root is a compartment like any other, so a compartment filter
// applies to root-scoped listers too. That is deliberate: a scan told to look
// at one compartment should not quietly report the root's contents instead.
func (f DiscoveryFilters) SelectCompartments(compartments []identity.Compartment) []string {
	res := make([]string, 0, len(compartments))
	for i := range compartments {
		id := derefString(compartments[i].Id)
		if id == "" {
			continue
		}
		if !f.AdmitsCompartment(id, derefString(compartments[i].Name)) {
			continue
		}
		res = append(res, id)
	}
	return res
}

// AdmitsCompartment reports whether a compartment passes the filters, matched
// by OCID or by name.
func (f DiscoveryFilters) AdmitsCompartment(id, name string) bool {
	if !f.HasCompartments() {
		return true
	}
	if matchesAny(f.ExcludeCompartments, id) || matchesAny(f.ExcludeCompartments, name) {
		return false
	}
	if len(f.Compartments) == 0 {
		return true
	}
	return matchesAny(f.Compartments, id) || matchesAny(f.Compartments, name)
}

// SelectTenancyRoot returns the tenancy root compartment as a one-element slice
// when the compartment filters admit it, and an empty slice when they do not.
//
// Root-scoped listers ask for the tenancy OCID directly and never touch the
// compartment tree, so the root's name is not otherwise in hand. It is only
// needed to let a filter written as a name match, so the lookup is gated on a
// compartment filter actually being set - an unfiltered scan still costs
// nothing. A lookup failure falls back to matching on the OCID alone rather
// than dropping the root, because failing to resolve a name is not evidence
// that the root was excluded.
func (c *OciConnection) SelectTenancyRoot(ctx context.Context) []string {
	root := c.TenantID()
	if !c.Filters.HasCompartments() {
		return []string{root}
	}

	name := ""
	if compartment, err := c.CompartmentByID(ctx, root); err == nil && compartment != nil {
		name = derefString(compartment.Name)
	} else if err != nil {
		log.Debug().Err(err).Msg("oci: could not resolve the tenancy root's name for compartment filtering")
	}

	if !c.Filters.AdmitsCompartment(root, name) {
		return []string{}
	}
	return []string{root}
}

// IsFilteredOutByTags reports whether a resource should be skipped given its
// tags. Both OCI tag kinds are consulted together; see ociTagLookup for how a
// filter key selects between them.
func (f DiscoveryFilters) IsFilteredOutByTags(freeform map[string]string, defined map[string]map[string]any) bool {
	if !f.HasTags() {
		return false
	}
	lookup := ociTagLookup(freeform, defined)
	return !matchesIncludeTags(f.Tags, lookup) || matchesExcludeTags(f.ExcludeTags, lookup)
}

// ociTagLookup flattens a resource's two tag namespaces into the one key space
// the filter syntax addresses: a freeform tag by its bare key, a defined tag by
// "namespace.key".
//
// A freeform key may itself contain a dot, which would collide with a defined
// tag's flattened form. Freeform wins that collision - it is the literal key the
// user typed, so resolving to it is the less surprising of the two readings.
func ociTagLookup(freeform map[string]string, defined map[string]map[string]any) map[string]string {
	lookup := make(map[string]string, len(freeform)+len(defined))
	for namespace, entries := range defined {
		for key, value := range entries {
			lookup[namespace+"."+key] = tagValueString(value)
		}
	}
	// Applied second so a freeform key overwrites a colliding defined tag.
	maps.Copy(lookup, freeform)
	return lookup
}

// tagValueString renders a defined tag's value for comparison. Defined tag
// values arrive as interface{} because the API allows strings and numbers;
// formatting rather than asserting keeps a numeric value comparable to the
// string a user typed on the command line.
func tagValueString(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

// matchesIncludeTags reports whether the resource carries at least one of the
// requested tags. No include filters means everything is included.
func matchesIncludeTags(filters map[string]string, lookup map[string]string) bool {
	if len(filters) == 0 {
		return true
	}
	for key, csv := range filters {
		value, ok := lookup[key]
		if !ok {
			continue
		}
		if matchesAny(strings.Split(csv, ","), value) {
			return true
		}
	}
	return false
}

// matchesExcludeTags reports whether the resource carries any excluded tag, in
// which case it should be skipped.
func matchesExcludeTags(filters map[string]string, lookup map[string]string) bool {
	for key, csv := range filters {
		value, ok := lookup[key]
		if !ok {
			continue
		}
		if matchesAny(strings.Split(csv, ","), value) {
			return true
		}
	}
	return false
}

// matchesAny reports whether want equals any candidate, ignoring surrounding
// whitespace so a CSV list written with spaces still matches. Comparison is
// case-insensitive: OCI region keys and compartment names are both routinely
// written in either case.
func matchesAny(candidates []string, want string) bool {
	if want == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

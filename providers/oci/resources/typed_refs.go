// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

// A resource that points at another one - an instance at its image, a key at
// its vault - stores the target's OCID and resolves it on read. Every such
// accessor is the same six steps, and there were thirteen copies of them: five
// named helpers and eight written out inline.
//
// Two of those steps are easy to get wrong in a way nothing catches:
//
//   - The null marking. A singular resource accessor that returns (nil, nil)
//     without first setting StateIsNull leaves the runtime unable to tell the
//     field was resolved, so it re-fetches or panics on read rather than
//     reporting null. It has to happen on every empty-id path, in every copy.
//   - The type assertion. All thirteen ended in a bare res.(*mqlOciX), which
//     panics if the resource name and the target type ever disagree - and a
//     panic inside an accessor takes down the whole scan, not one field.
//
// resolveRef does both once.

// ociCompartmentRef carries a resource's raw compartment OCID. The OCID is not
// part of the schema, so it rides on the internal struct and feeds only the
// compartment() accessor and asset discovery. Every resource exposing
// compartment() embeds this through its mqlOci<Resource>Internal struct.
type ociCompartmentRef struct {
	cacheCompartmentID string
}

func (c *ociCompartmentRef) setCompartmentID(id string) {
	c.cacheCompartmentID = id
}

func (c *ociCompartmentRef) compartmentIDValue() string {
	return c.cacheCompartmentID
}

// ociCompartmentGetter reads the compartment a resource was listed from.
type ociCompartmentGetter interface {
	compartmentIDValue() string
}

// ociCompartmentSetter is satisfied by every resource embedding
// ociCompartmentRef, which lets createOciResourceInCompartment stash the OCID
// without knowing the concrete resource type.
type ociCompartmentSetter interface {
	setCompartmentID(string)
}

// createOciResourceInCompartment creates a resource and records the compartment
// OCID it was listed from, so compartment() resolves without the OCID being a
// field on the resource. A resource that reaches here without embedding
// ociCompartmentRef would silently lose its compartment(), so the mismatch is
// reported rather than ignored.
func createOciResourceInCompartment(runtime *plugin.Runtime, name string, compartmentID string, args map[string]*llx.RawData) (plugin.Resource, error) {
	res, err := CreateResource(runtime, name, args)
	if err != nil {
		return nil, err
	}
	setter, ok := res.(ociCompartmentSetter)
	if !ok {
		return nil, errors.New(name + " does not embed ociCompartmentRef")
	}
	setter.setCompartmentID(compartmentID)
	return res, nil
}

// resolveRef resolves a typed resource from an OCID, marking the field null
// when there is no id to resolve.
//
// A null here is a real answer rather than a missing one: a service using
// Oracle-managed encryption has no customer key to point at, and an instance
// not launched from a boot volume has no source. Null is how the absence is
// reported.
func resolveRef[T plugin.Resource](runtime *plugin.Runtime, resourceName, id string, field *plugin.TValue[T]) (T, error) {
	var zero T
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return zero, nil
	}

	res, err := NewResource(runtime, resourceName, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return zero, err
	}

	// Reported rather than asserted. This can only fail if resourceName and T
	// disagree, which is a bug in the caller - but a failed bare assertion is a
	// panic, and the executor runs accessors in goroutines where a panic ends
	// the scan instead of the query.
	typed, ok := any(res).(T)
	if !ok {
		return zero, errors.New("oci: " + resourceName + " resolved to an unexpected resource type")
	}
	return typed, nil
}

// ocidOrEmpty reports id, or "" when it is not an OCID.
//
// OCI returns placeholder values where an OCID would go - ORACLE_MANAGED_KEY
// for a service-managed encryption key is the common one. Passing that to
// resolveRef would send it to an init that cannot find it and surface a
// not-found error on a field whose honest answer is "nothing is referenced
// here". Callers whose upstream field carries such placeholders wrap the id in
// this; the rest pass the id straight through, which is the behaviour those
// accessors already had.
func ocidOrEmpty(id string) string {
	if !isOcid(id) {
		return ""
	}
	return id
}

// resolveOciImage resolves a typed image resource from an image OCID.
func resolveOciImage(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciComputeImage]) (*mqlOciComputeImage, error) {
	return resolveRef(runtime, "oci.compute.image", id, field)
}

// resolveOciVault resolves a typed vault resource from a vault OCID.
func resolveOciVault(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciKmsVault]) (*mqlOciKmsVault, error) {
	return resolveRef(runtime, "oci.kms.vault", id, field)
}

// resolveOciKmsKey resolves a typed KMS key resource from a key OCID.
func resolveOciKmsKey(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciKmsKey]) (*mqlOciKmsKey, error) {
	return resolveRef(runtime, "oci.kms.key", id, field)
}

// resolveOciRegionByName resolves a region from its full name, for example
// us-phoenix-1.
//
// oci.region is keyed by the short region key - iad, phx - and not by the
// name, so handing a name to the region init matches nothing and reports no
// region rather than an error. The subscribed region listing carries both, so
// the name is matched against that instead.
//
// A name the listing does not carry is a region the tenancy is not subscribed
// to. That is a null region rather than a failure: the caller's own name field
// stays populated, which keeps the destination on the record even when the
// region resource cannot be built for it.
func resolveOciRegionByName(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlOciRegion]) (*mqlOciRegion, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	items, err := ociServiceCollection(runtime, "oci", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOci).GetRegions()
	})
	if err != nil {
		return nil, err
	}

	if region := ociRegionByName(items, name); region != nil {
		return region, nil
	}

	log.Debug().Str("region", name).Msg("oci region not among the tenancy's subscriptions")
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ociRegionByName picks the region carrying a full region name out of a listed
// oci.regions collection, or nil when none does.
func ociRegionByName(items []any, name string) *mqlOciRegion {
	for _, raw := range items {
		region, ok := raw.(*mqlOciRegion)
		if !ok {
			continue
		}
		if strings.EqualFold(region.Name.Data, name) {
			return region
		}
	}
	return nil
}

// resolveOciSubnet resolves a typed subnet resource from a subnet OCID.
func resolveOciSubnet(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciNetworkSubnet]) (*mqlOciNetworkSubnet, error) {
	return resolveRef(runtime, "oci.network.subnet", id, field)
}

// compartmentLookup reports the compartment record for an OCID, or nil when the
// tenancy tree the connection already holds does not contain it.
type compartmentLookup func(id string) (*identity.Compartment, error)

// ociCompartmentLookup returns a lookup backed by the connection's memoized
// compartment tree, or nil when the runtime has no OCI connection to ask.
func ociCompartmentLookup(runtime *plugin.Runtime) compartmentLookup {
	if runtime == nil {
		return nil
	}
	conn, ok := runtime.Connection.(*connection.OciConnection)
	if !ok {
		return nil
	}
	return func(id string) (*identity.Compartment, error) {
		return conn.CompartmentByID(context.Background(), id)
	}
}

// resolveOciCompartment resolves the compartment a resource lives in. It is by
// far the most used of these, since almost every resource reports its owner.
func resolveOciCompartment(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciCompartment]) (*mqlOciCompartment, error) {
	return resolveCompartment(runtime, ociCompartmentLookup(runtime), id, field)
}

// resolveCompartment resolves a compartment from the tenancy tree the
// connection already holds, and only asks the Identity API for an OCID that
// tree does not cover.
//
// The difference is not marginal. Going through NewResource runs
// initOciCompartment before the runtime cache is consulted, so a GetCompartment
// call is issued for every resource that reports an owner - five hundred
// instances across five compartments cost five hundred calls for five distinct
// answers. The tree is fetched once per connection and already walks the whole
// subtree, so those five answers are in hand before the first instance is read.
//
// The fallback stays for the OCIDs the tree cannot cover: a compartment in
// another tenancy, or one deleted between the listing and the read. Those keep
// the direct read, including its behaviour of reporting an unreadable
// compartment by id with the rest of its fields null.
func resolveCompartment(runtime *plugin.Runtime, lookup compartmentLookup, id string, field *plugin.TValue[*mqlOciCompartment]) (*mqlOciCompartment, error) {
	// resolveRef owns the null marking for an absent reference, and the empty
	// id is exactly that case; it has no business reaching a lookup.
	if id == "" {
		return resolveRef(runtime, "oci.compartment", id, field)
	}

	cached, err := cachedCompartment(runtime, lookup, id)
	if err != nil {
		return nil, err
	}
	if cached == nil {
		return resolveRef(runtime, "oci.compartment", id, field)
	}
	return cached, nil
}

// cachedCompartment builds the compartment for an OCID out of the tenancy tree
// the connection already holds, or reports nil when the tree cannot answer for
// it - an unknown OCID, an unreadable tree, or a runtime with no connection to
// ask. A nil result means "ask the API", not "no compartment"; only a real
// failure to build the resource is an error.
func cachedCompartment(runtime *plugin.Runtime, lookup compartmentLookup, id string) (*mqlOciCompartment, error) {
	if lookup == nil || id == "" {
		return nil, nil
	}

	compartment, err := lookup(id)
	if err != nil {
		// The tree could not be read at all - a throttled or denied
		// ListCompartments. That is not an answer about this compartment, so
		// let the direct read speak for it.
		log.Debug().Err(err).Str("compartment", id).
			Msg("oci compartment tree unavailable, resolving compartment directly")
		return nil, nil
	}
	if compartment == nil {
		return nil, nil
	}

	// Built from the same args as the oci.compartments lister, so the __id
	// matches and CreateResource hands back the instance the runtime already
	// holds rather than a second copy of it.
	res, err := CreateResource(runtime, "oci.compartment", ociCompartmentArgs(*compartment))
	if err != nil {
		return nil, err
	}
	typed, ok := res.(*mqlOciCompartment)
	if !ok {
		return nil, errors.New("oci: oci.compartment resolved to an unexpected resource type")
	}
	return typed, nil
}

// ociCompartmentResource resolves the compartment a lister embeds in the resource it
// is building, rather than one read later through an accessor.
//
// These are the costliest copies of the same call: the compartment is resolved
// while the list is built, so the GetCompartment per resource is paid whether
// or not anything asks for the field. The tree answers them for free, and an
// OCID it does not cover keeps the direct read - which is what fills in a
// compartment outside the listing.
func ociCompartmentResource(runtime *plugin.Runtime, id *string) (plugin.Resource, error) {
	return compartmentRef(runtime, ociCompartmentLookup(runtime), id)
}

func compartmentRef(runtime *plugin.Runtime, lookup compartmentLookup, id *string) (plugin.Resource, error) {
	if id != nil {
		cached, err := cachedCompartment(runtime, lookup, *id)
		if err != nil {
			return nil, err
		}
		if cached != nil {
			return cached, nil
		}
	}

	return NewResource(runtime, "oci.compartment", map[string]*llx.RawData{
		"id": llx.StringDataPtr(id),
	})
}

// resolveOciSecurityGroups resolves a list of typed network security group
// resources from a list of NSG OCIDs. Empty list returns ([], nil).
func resolveOciSecurityGroups(runtime *plugin.Runtime, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(runtime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A group that cannot be resolved - deleted between the list and
			// this call, or outside the compartments we enumerate - must not
			// take the rest of the list with it.
			log.Debug().Err(err).Str("nsg", id).Msg("skipping unresolvable oci network security group")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveOciSubnets resolves a list of typed subnet resources from a list of
// subnet OCIDs. Empty list returns ([], nil).
func resolveOciSubnets(runtime *plugin.Runtime, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(runtime, "oci.network.subnet", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A subnet that cannot be resolved must not take the rest of the
			// list with it.
			log.Debug().Err(err).Str("subnet", id).Msg("skipping unresolvable oci subnet")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveOciKmsKeys resolves a list of typed KMS key resources from a list of
// key OCIDs. Empty list returns ([], nil).
func resolveOciKmsKeys(runtime *plugin.Runtime, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(runtime, "oci.kms.key", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A key that cannot be resolved must not take the rest of the list
			// with it.
			log.Debug().Err(err).Str("key", id).Msg("skipping unresolvable oci kms key")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveOciCertificates resolves a list of typed OCI Certificates service
// certificate resources from a list of certificate OCIDs. Empty entries are
// skipped. Empty list returns ([], nil).
func resolveOciCertificates(runtime *plugin.Runtime, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(runtime, "oci.certificates.certificate", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			log.Debug().Err(err).Str("certificate", id).Msg("skipping unresolvable oci certificate")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// resolveOciCertRefsByType resolves typed resources of a single kind from a
// mixed list of OCIDs, keeping only the OCIDs whose type segment matches
// ocidType (e.g. "cabundle" or "certificateauthority"). OCIDs of other types
// are skipped, so callers can split one heterogeneous ID list across several
// typed accessors.
func resolveOciCertRefsByType(runtime *plugin.Runtime, ids []any, ocidType, resourceName string) ([]any, error) {
	prefix := "ocid1." + ocidType + "."
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || !strings.HasPrefix(id, prefix) {
			continue
		}
		res, err := NewResource(runtime, resourceName, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			log.Debug().Err(err).Str("id", id).Str("resource", resourceName).
				Msg("skipping unresolvable oci reference")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// ociResolveRefs resolves a list of OCIDs to resources of one kind, skipping
// the ones that cannot be resolved rather than failing the collection.
func ociResolveRefs(runtime *plugin.Runtime, resourceName, kind string, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(runtime, resourceName, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			ociLogSkippedRef(kind, id, err)
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// ociLogSkippedRef reports a reference that could not be resolved without
// failing the collection it was found in.
func ociLogSkippedRef(kind, id string, err error) {
	log.Debug().Err(err).Str("id", id).Msgf("skipping unresolvable oci %s", kind)
}

// resolveOciTopics resolves a list of typed ONS topic resources from a list of
// destination OCIDs. Monitoring alarms accept both ONS topics and Streaming
// streams, so non-topic OCIDs are filtered out by prefix. Without that filter a
// stream destination reached initOciOnsTopic, which reports a not-found error,
// and because the loop aborted on the first error the alarm's valid topics were
// lost along with it.
func resolveOciTopics(runtime *plugin.Runtime, ids []any) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || !strings.HasPrefix(id, "ocid1.onstopic.") {
			continue
		}
		res, err := NewResource(runtime, "oci.ons.topic", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A topic that cannot be resolved (deleted, or in a compartment the
			// token cannot read) must not take the alarm's other topics with it.
			log.Debug().Err(err).Str("topic", id).Msg("skipping unresolvable oci ons topic")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// ----- compute -----

func (o *mqlOciComputeInstance) image() (*mqlOciComputeImage, error) {
	return resolveOciImage(o.MqlRuntime, o.cacheImageID, &o.Image)
}

func (o *mqlOciComputeBootVolume) image() (*mqlOciComputeImage, error) {
	return resolveOciImage(o.MqlRuntime, o.cacheImageID, &o.Image)
}

func (o *mqlOciComputeBootVolume) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeBlockVolume) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeVnic) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeVnic) securityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, o.cacheNsgIDs)
}

func (o *mqlOciLoadBalancerLoadBalancer) securityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, o.cacheNsgIDs)
}

// ----- kms -----

func (o *mqlOciKmsVault) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciKmsKey) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciKmsKey) vault() (*mqlOciKmsVault, error) {
	return resolveOciVault(o.MqlRuntime, o.cacheVaultID, &o.Vault)
}

func (o *mqlOciKmsKeyVersion) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciKmsKeyVersion) vault() (*mqlOciKmsVault, error) {
	return resolveOciVault(o.MqlRuntime, o.cacheVaultID, &o.Vault)
}

// ----- events / ons / monitoring -----

func (o *mqlOciEventsRule) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciOnsTopic) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciMonitoringAlarm) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// metricCompartment resolves the compartment whose metrics the alarm watches,
// which is not necessarily the compartment the alarm itself lives in.
func (o *mqlOciMonitoringAlarm) metricCompartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.MetricCompartmentId.Data, &o.MetricCompartment)
}

func (o *mqlOciMonitoringAlarm) topics() ([]any, error) {
	return resolveOciTopics(o.MqlRuntime, o.cacheDestinations)
}

// ----- bastion / vault.secret -----

func (o *mqlOciBastionInstance) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciVaultSecret) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ----- database -----

func (o *mqlOciDatabaseDbSystem) securityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, o.cacheNsgIDs)
}

func (o *mqlOciDatabaseDbSystem) backupSecurityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, o.cacheBackupNetworkNsgIDs)
}

func (o *mqlOciDatabaseAutonomousDatabase) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseAutonomousDatabase) securityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, o.cacheNsgIDs)
}

// ----- compartment accessors (ownership) -----

func (o *mqlOciIdentityUser) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityOauth2ClientCredential) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityDynamicGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityIdentityProvider) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityNetworkSource) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkPublicIp) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkVcn) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkSubnet) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkInternetGateway) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkNatGateway) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkRouteTable) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciLoggingLogGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciObjectStorageBucket) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciFileStorageFileSystem) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardTarget) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardSecurityZone) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardSecurityZoneRecipe) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardSecurityPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciLoadBalancerLoadBalancer) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkFirewallFirewall) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkFirewallPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciOkeCluster) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciOkeNodePool) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciWafFirewall) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciWafPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciFunctionsApplication) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciFunctionsFunction) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciContainerInstancesInstance) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciContainerInstancesContainer) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseBackup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseAutonomousDatabaseBackup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDatabaseDbSystem) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciApigatewayGateway) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciApigatewayDeployment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciApigatewayCertificate) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCertificatesCertificate) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCertificatesCertificateAuthority) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCertificatesCaBundle) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciRedisCluster) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeConfiguration) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeTargetDatabase) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeSecurityAssessment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeUserAssessment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeSensitiveDataModel) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeSensitiveType) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDataSafeMaskingPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardDetectorRecipe) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ----- source / lineage accessors -----

func (o *mqlOciComputeImage) baseImage() (*mqlOciComputeImage, error) {
	return resolveOciImage(o.MqlRuntime, o.cacheBaseImageID, &o.BaseImage)
}

func (o *mqlOciComputeInstance) bootVolume() (*mqlOciComputeBootVolume, error) {
	return resolveRef(o.MqlRuntime, "oci.compute.bootVolume", ocidOrEmpty(o.cacheBootVolumeID), &o.BootVolume)
}

func (o *mqlOciComputeBlockVolume) sourceVolume() (*mqlOciComputeBlockVolume, error) {
	return resolveRef(o.MqlRuntime, "oci.compute.blockVolume", ocidOrEmpty(o.cacheSourceVolumeID), &o.SourceVolume)
}

func (o *mqlOciComputeBootVolume) sourceBootVolume() (*mqlOciComputeBootVolume, error) {
	return resolveRef(o.MqlRuntime, "oci.compute.bootVolume", ocidOrEmpty(o.cacheSourceBootVolumeID), &o.SourceBootVolume)
}

func (o *mqlOciIdentityUser) identityProvider() (*mqlOciIdentityIdentityProvider, error) {
	return resolveRef(o.MqlRuntime, "oci.identity.identityProvider", ocidOrEmpty(o.cacheIdentityProviderID), &o.IdentityProvider)
}

func (o *mqlOciOkeNodePool) cluster() (*mqlOciOkeCluster, error) {
	return resolveRef(o.MqlRuntime, "oci.oke.cluster", ocidOrEmpty(o.cacheClusterID), &o.Cluster)
}

func (o *mqlOciLoadBalancerLoadBalancer) subnets() ([]any, error) {
	out := make([]any, 0, len(o.cacheSubnetIDs))
	for _, id := range o.cacheSubnetIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (o *mqlOciNetworkSubnet) securityLists() ([]any, error) {
	out := make([]any, 0, len(o.cacheSecurityListIDs))
	for _, id := range o.cacheSecurityListIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(o.MqlRuntime, "oci.network.securityList", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (o *mqlOciFileStorageFileSystem) parentFileSystem() (*mqlOciFileStorageFileSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.fileSystem", ocidOrEmpty(o.cacheParentFileSystemID), &o.ParentFileSystem)
}

func (o *mqlOciDatabaseDbSystem) sourceDbSystem() (*mqlOciDatabaseDbSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.database.dbSystem", ocidOrEmpty(o.cacheSourceDbSystemID), &o.SourceDbSystem)
}

func (o *mqlOciDatabaseAutonomousDatabase) sourceDatabase() (*mqlOciDatabaseAutonomousDatabase, error) {
	return resolveRef(o.MqlRuntime, "oci.database.autonomousDatabase", ocidOrEmpty(o.cacheSourceID), &o.SourceDatabase)
}

type mqlOciKmsKeyVersionInternal struct {
	ociCompartmentRef
	cacheVaultID string
}

type mqlOciMonitoringAlarmInternal struct {
	ociCompartmentRef
	cacheDestinations []any
}

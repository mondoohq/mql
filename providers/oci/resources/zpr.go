// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/securityattribute"
	"github.com/oracle/oci-go-sdk/v65/zpr"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// Zero Trust Packet Routing and the security attributes its policies are
// written against.
//
// ZPR is the layer above security lists and network security groups: it
// authorizes traffic by the security attributes a resource carries rather than
// by its address. That makes it load-bearing for `oci.network.exposure` - an
// opening the address-based layers admit can still be denied here - which is
// why the enforcement facts are computed in this file and read from there.

// zprEnforceMode is the namespace mode that makes a security attribute
// actually block traffic. The other documented mode is `audit`, under which
// ZPR evaluates a policy and reports the decision without acting on it.
//
// The comparison is case-insensitive because the API documents these as
// lowercase but the field is a free-form string slice rather than an enum.
const zprEnforceMode = "enforce"

// zprStatusEnabled is the tenancy-level onboarding status under which policies
// take effect. Anything else means ZPR is present in the API but inert.
const zprStatusEnabled = "ENABLED"

func (o *mqlOciZpr) id() (string, error) {
	return "oci.zpr", nil
}

func (o *mqlOciSecurityAttributes) id() (string, error) {
	return "oci.securityAttributes", nil
}

func (o *mqlOciZprPolicy) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciZprConfiguration) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciSecurityAttributesNamespace) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciSecurityAttributesAttribute) id() (string, error) {
	return o.Id.Data, nil
}

// The compartment each of these lives in arrives with the listing but is only
// wanted as a resource, so it is held here and resolved on demand rather than
// shipped as a second, redundant OCID field.
type mqlOciZprPolicyInternal struct {
	cacheCompartmentID string
}

type mqlOciZprConfigurationInternal struct {
	cacheCompartmentID string
}

type mqlOciSecurityAttributesNamespaceInternal struct {
	cacheCompartmentID string
}

// An attribute additionally remembers the namespace that defines it, because
// the namespace carries the enforce-versus-audit mode that decides whether the
// attribute means anything.
//
// The namespace is held as the resource rather than as its OCID: attributes
// are listed per namespace, so the one that owns each attribute is already in
// hand. Re-resolving it through NewResource would run an init before the cache
// is consulted, turning one listing into a lookup per attribute.
type mqlOciSecurityAttributesAttributeInternal struct {
	cacheCompartmentID string
	cacheNamespace     *mqlOciSecurityAttributesNamespace
	detail             ociRetryLazy[*securityattribute.SecurityAttribute]
}

// fetchDetail reads the attribute definition, which the listing does not carry.
//
// Four fields share this call rather than making one each: the validator, the
// retirement flag, the lifecycle state and the creation time all live only on
// the full definition.
func (o *mqlOciSecurityAttributesAttribute) fetchDetail() (*securityattribute.SecurityAttribute, error) {
	return o.detail.get(func() (*securityattribute.SecurityAttribute, error) {
		if o.cacheNamespace == nil {
			return nil, errors.New("oci.securityAttributes.attribute: the defining namespace is not known")
		}

		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		region, err := conn.ConfiguredRegion()
		if err != nil {
			return nil, err
		}
		svc, err := conn.SecurityAttributeClient(region)
		if err != nil {
			return nil, err
		}

		resp, err := svc.GetSecurityAttribute(context.Background(), securityattribute.GetSecurityAttributeRequest{
			SecurityAttributeNamespaceId: new(o.cacheNamespace.Id.Data),
			SecurityAttributeName:        new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.SecurityAttribute, nil
	})
}

func (o *mqlOciSecurityAttributesAttribute) isRetired() (bool, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return false, err
	}
	return boolValue(detail.IsRetired), nil
}

func (o *mqlOciSecurityAttributesAttribute) validator() (any, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.Validator == nil {
		// No validator means the attribute accepts any value. That is a real
		// answer rather than an absent one, but it is the API's absence too, so
		// it is reported as null instead of being invented as a DEFAULT record.
		return nil, nil
	}
	return convert.JsonToDict(detail.Validator)
}

func (o *mqlOciSecurityAttributesAttribute) state() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.LifecycleState), nil
}

func (o *mqlOciSecurityAttributesAttribute) created() (*time.Time, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.TimeCreated == nil {
		// Left null rather than becoming the zero time, which would report
		// 1 January year 1 as the attribute's creation date.
		o.Created.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &detail.TimeCreated.Time, nil
}

func (o *mqlOciZprPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciZprConfiguration) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciSecurityAttributesNamespace) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciSecurityAttributesAttribute) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// namespace returns the namespace that defines this attribute.
func (o *mqlOciSecurityAttributesAttribute) namespace() (*mqlOciSecurityAttributesNamespace, error) {
	if o.cacheNamespace == nil {
		o.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return o.cacheNamespace, nil
}

// ----- ZPR policies -----

func (o *mqlOciZpr) policies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// ZPR policies are tenancy-scoped: ListZprPolicies takes the tenancy OCID
	// as its compartment and does not accept a child compartment, so unlike
	// most listers here this one is correctly root-scoped rather than pending
	// a compartment migration.
	return ociCollect(o.MqlRuntime, ociScopeTenancyRoot,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ZprClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]zpr.ZprPolicySummary, *string, error) {
				resp, err := svc.ListZprPolicies(ctx, zpr.ListZprPoliciesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				p := items[i]

				if conn.Filters.IsFilteredOutByTags(p.FreeformTags, p.DefinedTags) {
					continue
				}

				var created, updated *time.Time
				if p.TimeCreated != nil {
					created = &p.TimeCreated.Time
				}
				if p.TimeUpdated != nil {
					updated = &p.TimeUpdated.Time
				}

				mqlPolicy, err := CreateResource(o.MqlRuntime, "oci.zpr.policy", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(p.Id),
					"name":             llx.StringDataPtr(p.Name),
					"description":      llx.StringDataPtr(p.Description),
					"statements":       llx.ArrayData(stringsToAny(p.Statements), types.String),
					"state":            llx.StringData(string(p.LifecycleState)),
					"lifecycleDetails": llx.StringDataPtr(p.LifecycleDetails),
					"created":          llx.TimeDataPtr(created),
					"timeUpdated":      llx.TimeDataPtr(updated),
					"freeformTags":     llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
					"systemTags":       llx.MapData(definedTagsToAny(p.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlPolicy.(*mqlOciZprPolicy)
				typed.cacheCompartmentID = stringValue(p.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

// ----- ZPR tenancy configuration -----

func (o *mqlOciZpr) configuration() (*mqlOciZprConfiguration, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	cfg, err := ociZprConfiguration(conn)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		// A tenancy that never onboarded ZPR has no configuration to report.
		// Null is the honest answer; an invented DISABLED record would look
		// like a deliberate setting rather than an absent service.
		o.Configuration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	var created, updated *time.Time
	if cfg.TimeCreated != nil {
		created = &cfg.TimeCreated.Time
	}
	if cfg.TimeUpdated != nil {
		updated = &cfg.TimeUpdated.Time
	}

	res, err := CreateResource(o.MqlRuntime, "oci.zpr.configuration", map[string]*llx.RawData{
		"id":               llx.StringDataPtr(cfg.Id),
		"zprStatus":        llx.StringData(string(cfg.ZprStatus)),
		"state":            llx.StringData(string(cfg.LifecycleState)),
		"lifecycleDetails": llx.StringDataPtr(cfg.LifecycleDetails),
		"created":          llx.TimeDataPtr(created),
		"timeUpdated":      llx.TimeDataPtr(updated),
	})
	if err != nil {
		return nil, err
	}
	typed := res.(*mqlOciZprConfiguration)
	typed.cacheCompartmentID = stringValue(cfg.CompartmentId)
	return typed, nil
}

// initOciZprConfiguration makes the dotted spelling of this resource behave
// like the accessor.
//
// `oci.zpr.configuration` is both a field path on oci.zpr and a resource name.
// Asked for by its dotted path, the compiler instantiates the resource directly
// and never runs the accessor that populates it, so every field would come back
// unset - which surfaces client-side as "primitive with no type information"
// rather than as anything pointing here. Delegating to the parent gives both
// spellings the same answer.
func initOciZprConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// The lister builds this resource with its fields already in hand.
	if len(args) > 0 {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "oci.zpr", nil)
	if err != nil {
		return nil, nil, err
	}

	cfg := obj.(*mqlOciZpr).GetConfiguration()
	if cfg.Error != nil {
		return nil, nil, cfg.Error
	}
	if cfg.Data == nil {
		return nil, nil, errors.New("Zero Trust Packet Routing is not onboarded to this tenancy")
	}
	return args, cfg.Data, nil
}

// ----- security attribute namespaces and attributes -----

func (o *mqlOciSecurityAttributes) namespaces() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.SecurityAttributeClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]securityattribute.SecurityAttributeNamespaceSummary, *string, error) {
				resp, err := svc.ListSecurityAttributeNamespaces(ctx, securityattribute.ListSecurityAttributeNamespacesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				ns := items[i]

				if conn.Filters.IsFilteredOutByTags(ns.FreeformTags, ns.DefinedTags) {
					continue
				}

				var created *time.Time
				if ns.TimeCreated != nil {
					created = &ns.TimeCreated.Time
				}

				mqlNs, err := CreateResource(o.MqlRuntime, "oci.securityAttributes.namespace", map[string]*llx.RawData{
					"id":           llx.StringDataPtr(ns.Id),
					"name":         llx.StringDataPtr(ns.Name),
					"description":  llx.StringDataPtr(ns.Description),
					"mode":         llx.ArrayData(stringsToAny(ns.Mode), types.String),
					"isRetired":    llx.BoolDataPtr(ns.IsRetired),
					"state":        llx.StringData(string(ns.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(ns.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(ns.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(ns.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlNs.(*mqlOciSecurityAttributesNamespace)
				typed.cacheCompartmentID = stringValue(ns.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciSecurityAttributes) attributes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Attribute definitions are listed per namespace, so this walks the
	// namespaces already resolved above rather than fanning out again.
	namespaces := o.GetNamespaces()
	if namespaces.Error != nil {
		return nil, namespaces.Error
	}

	res := []any{}
	for _, raw := range namespaces.Data {
		ns, ok := raw.(*mqlOciSecurityAttributesNamespace)
		if !ok {
			continue
		}

		items, err := ociSecurityAttributesFor(conn, ns.Id.Data)
		if err != nil {
			// A namespace the caller cannot read is a per-namespace IAM gap,
			// not a reason to report the tenancy as having no attributes.
			log.Debug().Err(err).Str("namespace", ns.Id.Data).
				Msg("oci: skipping security attribute namespace that could not be listed")
			continue
		}

		for i := range items {
			a := items[i]

			// The listing carries only identity and type. Retirement, the
			// validator, the lifecycle state and the creation time all come
			// from a per-attribute Get, so they are computed rather than
			// filled in with zero values that would read as real answers.
			mqlAttr, err := CreateResource(o.MqlRuntime, "oci.securityAttributes.attribute", map[string]*llx.RawData{
				"id":          llx.StringDataPtr(a.Id),
				"name":        llx.StringDataPtr(a.Name),
				"description": llx.StringDataPtr(a.Description),
				"type":        llx.StringDataPtr(a.Type),
			})
			if err != nil {
				return nil, err
			}
			typed := mqlAttr.(*mqlOciSecurityAttributesAttribute)
			typed.cacheCompartmentID = stringValue(a.CompartmentId)
			typed.cacheNamespace = ns
			res = append(res, typed)
		}
	}
	return res, nil
}

// ociSecurityAttributesFor lists the attribute definitions in one namespace.
func ociSecurityAttributesFor(conn *connection.OciConnection, namespaceID string) ([]securityattribute.SecurityAttributeSummary, error) {
	ctx := context.Background()

	region, err := conn.ConfiguredRegion()
	if err != nil {
		return nil, err
	}
	svc, err := conn.SecurityAttributeClient(region)
	if err != nil {
		return nil, err
	}

	return ociPaginate(ctx, func(ctx context.Context, page *string) ([]securityattribute.SecurityAttributeSummary, *string, error) {
		resp, err := svc.ListSecurityAttributes(ctx, securityattribute.ListSecurityAttributesRequest{
			SecurityAttributeNamespaceId: new(namespaceID),
			Page:                         page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
}

// ----- enforcement facts, shared by every exposure computation -----

// ociZprState is the pair of tenancy-wide facts that decide whether a security
// attribute on a resource actually blocks anything: whether ZPR is onboarded,
// and which namespaces enforce rather than audit.
type ociZprState struct {
	enabled bool
	// enforcing holds the lowercased names of namespaces whose mode includes
	// `enforce`. Names rather than OCIDs, because that is what a resource's
	// securityAttributes map is keyed by.
	enforcing map[string]bool
}

// ociZprStateCache memoizes that pair for the lifetime of a scan.
//
// Every instance and load balancer computing an exposure needs the same two
// answers, and both cost an API call, so without this a hundred instances mean
// a hundred repeats of one tenancy-wide read. Keyed by connection id so
// separate connections in one process do not share a tenancy's state.
var (
	ociZprStateCache   = map[uint32]*ociZprState{}
	ociZprStateCacheMu sync.Mutex
)

// ociZprStateFor returns the tenancy's ZPR enforcement state, fetching it once.
//
// A failure is not cached: it returns a zero state, under which zprEnforced
// reads false. That direction is deliberate - reporting "not enforced" when the
// lookup failed leaves `internetReachable` reading as exposed, which is the
// safe way to be wrong. Caching the failure would instead fix that answer for
// the whole scan.
func ociZprStateFor(conn *connection.OciConnection) *ociZprState {
	ociZprStateCacheMu.Lock()
	defer ociZprStateCacheMu.Unlock()

	if cached, ok := ociZprStateCache[conn.ID()]; ok {
		return cached
	}

	state := &ociZprState{enforcing: map[string]bool{}}

	cfg, err := ociZprConfiguration(conn)
	if err != nil {
		log.Debug().Err(err).Msg("oci: could not read the Zero Trust Packet Routing configuration")
		return state
	}
	state.enabled = cfg != nil && strings.EqualFold(string(cfg.ZprStatus), zprStatusEnabled)

	// The namespace modes are read whether or not ZPR is switched on. They are
	// two independent facts, and `oci.securityAttributes.applied.isEnforcing`
	// reports the namespace one on its own: a namespace configured to enforce
	// is still configured to enforce in a tenancy that has not onboarded ZPR,
	// and saying otherwise would hide what switching ZPR on would then do.
	namespaces, err := ociSecurityAttributeNamespacesFor(conn)
	if err != nil {
		log.Debug().Err(err).Msg("oci: could not list security attribute namespaces")
		return state
	}
	for i := range namespaces {
		name := stringValue(namespaces[i].Name)
		if name == "" {
			continue
		}
		for _, mode := range namespaces[i].Mode {
			if strings.EqualFold(strings.TrimSpace(mode), zprEnforceMode) {
				state.enforcing[strings.ToLower(name)] = true
				break
			}
		}
	}

	ociZprStateCache[conn.ID()] = state
	return state
}

// ociZprConfiguration reads the tenancy's ZPR onboarding record, returning nil
// when the tenancy has never onboarded ZPR.
func ociZprConfiguration(conn *connection.OciConnection) (*zpr.Configuration, error) {
	ctx := context.Background()

	region, err := conn.ConfiguredRegion()
	if err != nil {
		return nil, err
	}
	svc, err := conn.ZprClient(region)
	if err != nil {
		return nil, err
	}

	resp, err := svc.GetConfiguration(ctx, zpr.GetConfigurationRequest{
		CompartmentId: new(conn.TenantID()),
	})
	if err != nil {
		if ociZprAbsent(err) {
			return nil, nil
		}
		return nil, err
	}
	return &resp.Configuration, nil
}

// ociZprAbsent reports whether the error means the tenancy has no Zero Trust
// Packet Routing configuration to read.
//
// OCI answers both "never onboarded" and "you may not look" with a 404 and
// NotAuthorizedOrNotFound, deliberately, so that a caller cannot probe for the
// existence of a resource it has no access to. The two are therefore not
// distinguishable here - but they do not need to be, because both land on the
// same conservative reading: no configuration means zprEnforced is false, which
// leaves internetReachable reporting an opening rather than hiding one.
func ociZprAbsent(err error) bool {
	svcErr, ok := common.IsServiceError(err)
	return ok && svcErr.GetHTTPStatusCode() == 404
}

// ociSecurityAttributeNamespacesFor lists the tenancy's security attribute
// namespaces, which is where the enforce-versus-audit mode lives.
func ociSecurityAttributeNamespacesFor(conn *connection.OciConnection) ([]securityattribute.SecurityAttributeNamespaceSummary, error) {
	ctx := context.Background()

	region, err := conn.ConfiguredRegion()
	if err != nil {
		return nil, err
	}
	svc, err := conn.SecurityAttributeClient(region)
	if err != nil {
		return nil, err
	}

	return ociPaginate(ctx, func(ctx context.Context, page *string) ([]securityattribute.SecurityAttributeNamespaceSummary, *string, error) {
		resp, err := svc.ListSecurityAttributeNamespaces(ctx, securityattribute.ListSecurityAttributeNamespacesRequest{
			CompartmentId: new(conn.TenantID()),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
}

// ociZprEnforced reports whether ZPR actually governs a resource carrying these
// security attributes.
//
// Both halves are required. A tenancy with ZPR switched off enforces nothing
// however its resources are labelled, and an attribute from an audit-mode
// namespace is evaluated and then ignored. Only a resource carrying at least
// one attribute from an enforcing namespace, in an onboarded tenancy, is
// subject to a ZPR verdict.
// The attribute map arrives in the shape the resource field carries it -
// namespace to a map of attribute names - rather than as the SDK's nested
// map type, because every caller reads it off a resolved resource.
func ociZprEnforced(state *ociZprState, attributes map[string]any) bool {
	if state == nil || !state.enabled || len(attributes) == 0 {
		return false
	}
	for namespace, raw := range attributes {
		entries, ok := raw.(map[string]any)
		if !ok || len(entries) == 0 {
			// A namespace key with no attributes under it labels nothing.
			continue
		}
		if state.enforcing[strings.ToLower(namespace)] {
			return true
		}
	}
	return false
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

// The resolved form of a resource's security attributes.
//
// Every resource that can be labelled reports the labelling twice: once as the
// raw `securityAttributes` map, which is cheap and matches how definedTags is
// modelled everywhere else in this provider, and once through this accessor,
// which joins each labelling to the namespace and definition behind it.
//
// The join is what makes the labelling answerable. A map tells you an instance
// carries `zpr-prod.tier = db`; it cannot tell you whether the `zpr-prod`
// namespace enforces that or merely audits it, and those two are the difference
// between a control and a report. That fact lives on the namespace, so reaching
// it requires the resource the map does not carry.

// ociAppliedSecurityAttributes builds the resolved attribute rows for one
// resource from its raw securityAttributes map.
//
// parentID is the labelled resource's own id, used only to key the rows in the
// runtime cache. It is not exposed: a row is identified by which resource it
// sits on plus its namespace and name, which is a composite with no meaning
// outside this provider.
func ociAppliedSecurityAttributes(
	runtime *plugin.Runtime,
	parentID string,
	attributes map[string]any,
) ([]any, error) {
	if len(attributes) == 0 {
		return []any{}, nil
	}

	conn := runtime.Connection.(*connection.OciConnection)
	state := ociZprStateFor(conn)

	// Namespaces are iterated in sorted order so a resource's rows keep a
	// stable order between scans. Go map iteration is randomised, and an
	// unstable order shows up as spurious diffs in scan output.
	namespaces := make([]string, 0, len(attributes))
	for namespace := range attributes {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	res := []any{}
	for _, namespace := range namespaces {
		entries, ok := attributes[namespace].(map[string]any)
		if !ok {
			// A namespace key whose value is not a map labels nothing. Skipping
			// keeps a shape change in the API from becoming a panic here.
			continue
		}

		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)

		isEnforcing := state.enforcing[strings.ToLower(namespace)]

		for _, name := range names {
			mqlApplied, err := CreateResource(runtime, "oci.securityAttributes.applied", map[string]*llx.RawData{
				"__id":          llx.StringData(parentID + "/securityAttribute/" + namespace + "/" + name),
				"namespaceName": llx.StringData(namespace),
				"name":          llx.StringData(name),
				"value":         llx.StringData(tagValueString(entries[name])),
				"isEnforcing":   llx.BoolData(isEnforcing),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlApplied)
		}
	}
	return res, nil
}

// tagValueString renders an attribute value for comparison. Values arrive as
// any because the API allows strings and numbers; formatting rather than
// asserting keeps a numeric value comparable to the string a policy names.
func tagValueString(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

// namespace resolves the namespace this labelling belongs to.
//
// Resolved by scanning the tenancy's namespace collection rather than through
// NewResource: a NewResource call runs the target's init before the runtime
// cache is consulted, so a resource carrying five attributes would cost five
// lookups of a list that was already fetched once.
func (o *mqlOciSecurityAttributesApplied) namespace() (*mqlOciSecurityAttributesNamespace, error) {
	namespaces, err := ociSecurityAttributeNamespaceResources(o.MqlRuntime)
	if err != nil {
		return nil, err
	}

	want := strings.ToLower(o.NamespaceName.Data)
	for _, raw := range namespaces {
		ns, ok := raw.(*mqlOciSecurityAttributesNamespace)
		if !ok {
			continue
		}
		if strings.EqualFold(ns.Name.Data, want) {
			return ns, nil
		}
	}

	// A namespace the caller cannot list, or one deleted since the resource was
	// labelled, leaves the labelling in place with nothing behind it. Null is
	// the honest answer.
	o.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// attribute resolves the definition behind this labelling, which carries the
// validator that decides which values are accepted.
func (o *mqlOciSecurityAttributesApplied) attribute() (*mqlOciSecurityAttributesAttribute, error) {
	obj, err := CreateResource(o.MqlRuntime, "oci.securityAttributes", nil)
	if err != nil {
		return nil, err
	}

	attributes := obj.(*mqlOciSecurityAttributes).GetAttributes()
	if attributes.Error != nil {
		return nil, attributes.Error
	}

	for _, raw := range attributes.Data {
		attr, ok := raw.(*mqlOciSecurityAttributesAttribute)
		if !ok {
			continue
		}
		if !strings.EqualFold(attr.Name.Data, o.Name.Data) {
			continue
		}
		// Attribute names are unique only within a namespace, so the namespace
		// has to match too - without it a `tier` attribute in one namespace
		// would resolve to a `tier` in another.
		ns := attr.cacheNamespace
		if ns == nil || !strings.EqualFold(ns.Name.Data, o.NamespaceName.Data) {
			continue
		}
		return attr, nil
	}

	o.Attribute.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ociSecurityAttributeNamespaceResources returns the tenancy's namespace
// resources, fetched once and shared through the runtime cache.
func ociSecurityAttributeNamespaceResources(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "oci.securityAttributes", nil)
	if err != nil {
		return nil, err
	}
	namespaces := obj.(*mqlOciSecurityAttributes).GetNamespaces()
	if namespaces.Error != nil {
		return nil, namespaces.Error
	}
	return namespaces.Data, nil
}

// The accessors below are one line each because the work is identical: hand the
// resource's own id and its raw attribute map to the shared resolver. They
// differ only in which resource they hang off.

func (o *mqlOciComputeInstance) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciComputeVnic) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciNetworkVcn) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciLoadBalancerLoadBalancer) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciNetworkLoadBalancerLoadBalancer) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciOkeCluster) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciNetworkFirewallFirewall) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciDatabaseDbSystem) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciStreamingStreamPool) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciOpensearchCluster) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

func (o *mqlOciGoldenGateDeployment) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/resources/eos"
)

// resolveAcl builds the arista.eos.acl named by a reference elsewhere in the
// configuration, returning (nil, nil) when no list by that name is defined.
//
// family selects the address family the reference belongs to, since IPv4 and
// IPv6 access-lists are separate namespaces that can share a name. An empty
// family matches the first list of either family with that name, which is
// what a reference that does not itself carry a family means.
//
// A dangling reference is a real and common misconfiguration: an access-group
// naming a list that does not exist permits all traffic. Callers report that
// as a null rather than an error so the surrounding query still returns, and
// they must set StateIsNull on the field before returning nil.
//
// The fields set here match the ones arista.eos.acls sets, so both paths
// produce the same __id and therefore share one cached resource.
func resolveAcl(runtime *plugin.Runtime, name, family string) (*mqlAristaEosAcl, error) {
	if name == "" {
		return nil, nil
	}

	rc, err := fetchRunningConfig(runtime)
	if err != nil {
		return nil, err
	}
	for _, acl := range eos.ParseAccessLists(rc) {
		if acl.Name != name || (family != "" && acl.Family != family) {
			continue
		}
		mqlAcl, err := CreateResource(runtime, "arista.eos.acl", map[string]*llx.RawData{
			"name":   llx.StringData(acl.Name),
			"family": llx.StringData(acl.Family),
			"type":   llx.StringData(acl.Type),
		})
		if err != nil {
			return nil, err
		}
		return mqlAcl.(*mqlAristaEosAcl), nil
	}

	return nil, nil
}

// =====================================================================
// arista.eos.aclBinding (list)
// =====================================================================

// id keys a binding on everything that makes it distinct: the same list can be
// applied to several targets, and to one target in both directions and both
// address families.
func (a *mqlAristaEosAclBinding) id() (string, error) {
	for _, f := range []struct{ err error }{
		{a.Target.Error}, {a.TargetName.Error}, {a.Family.Error},
		{a.Direction.Error}, {a.AclName.Error}, {a.Vrf.Error},
	} {
		if f.err != nil {
			return "", f.err
		}
	}
	// The same list can be bound to one target per routing instance, so the
	// instance is part of what makes a binding distinct.
	return "arista.eos.aclBinding/" + a.Target.Data + "/" + a.TargetName.Data + "/" +
		a.Family.Data + "/" + a.Direction.Data + "/" + a.AclName.Data + "/" +
		a.Vrf.Data, nil
}

func (a *mqlAristaEos) aclBindings() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	bindings := eos.ParseAclBindings(rc)

	res := make([]any, 0, len(bindings))
	for _, b := range bindings {
		mqlBinding, err := CreateResource(a.MqlRuntime, "arista.eos.aclBinding", map[string]*llx.RawData{
			"target":     llx.StringData(b.Target),
			"targetName": llx.StringData(b.TargetName),
			"direction":  llx.StringData(b.Direction),
			"family":     llx.StringData(b.Family),
			"aclName":    llx.StringData(b.AclName),
			"vrf":        llx.StringData(b.VRF),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (a *mqlAristaEosAclBinding) acl() (*mqlAristaEosAcl, error) {
	if a.AclName.Error != nil {
		return nil, a.AclName.Error
	}
	if a.Family.Error != nil {
		return nil, a.Family.Error
	}
	// The binding knows its own address family, so an IPv6 access-group never
	// resolves to a same-named IPv4 list.
	mqlAcl, err := resolveAcl(a.MqlRuntime, a.AclName.Data, a.Family.Data)
	if err != nil {
		return nil, err
	}
	if mqlAcl == nil {
		a.Acl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlAcl, nil
}

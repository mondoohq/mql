// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlAwsEc2NetworkaclEntryInternal holds a back-reference to the entry's own
// network ACL. Shadowing is a property of an entry relative to its siblings, and
// an entry otherwise has no way to reach them. The parent's entry list is already
// resolved by the time an entry exists, so reading it costs no API call.
type mqlAwsEc2NetworkaclEntryInternal struct {
	parentAcl *mqlAwsEc2Networkacl
}

// Network ACL verdicts on a security group rule's traffic.
const (
	// naclVerdictAllow means the first matching inbound entry permits the whole
	// range the security group rule covers.
	naclVerdictAllow = "allow"
	// naclVerdictDeny means the first matching entry denies the whole range, or
	// nothing matches and the implicit final deny applies.
	naclVerdictDeny = "deny"
	// naclVerdictPartial means the first matching entry covers only part of the
	// range, so the remainder falls through to later entries.
	naclVerdictPartial = "partial"
	// naclVerdictUnknown means the network ACL could not be read.
	naclVerdictUnknown = "unknown"
)

// naclEntrySourceCidr returns the source range of a network ACL entry. An entry
// carries either an IPv4 or an IPv6 block, never both.
func naclEntrySourceCidr(entry *mqlAwsEc2NetworkaclEntry) string {
	if cidr := entry.CidrBlock.Data; cidr != "" {
		return cidr
	}
	return entry.Ipv6CidrBlock.Data
}

// naclEntryRule converts a network ACL entry resource into the rule shape used
// for matching. Reading PortRange here is a cached read: it is populated as a
// creation arg, so this triggers no fetch. Its absence means all ports.
func naclEntryRule(entry *mqlAwsEc2NetworkaclEntry) naclIngressRule {
	rule := naclIngressRule{
		ruleNumber: int(entry.RuleNumber.Data),
		allow:      strings.EqualFold(entry.RuleAction.Data, "allow"),
		public:     cidrEntryIsPublic(entry.CidrBlock.Data, entry.Ipv6CidrBlock.Data),
		protocol:   entry.Protocol.Data,
		cidr:       naclEntrySourceCidr(entry),
		allPorts:   true,
	}
	if pr := entry.PortRange.Data; pr != nil {
		rule.fromPort = pr.From.Data
		rule.toPort = pr.To.Data
		rule.allPorts = false
	}
	return rule
}

// orderedNaclEntries returns a network ACL's entries for one direction, sorted
// by rule number ascending, which is the order AWS evaluates them in.
func orderedNaclEntries(nacl *mqlAwsEc2Networkacl, egress bool) ([]*mqlAwsEc2NetworkaclEntry, error) {
	entries := nacl.GetEntries()
	if entries.Error != nil {
		return nil, entries.Error
	}
	res := make([]*mqlAwsEc2NetworkaclEntry, 0, len(entries.Data))
	for _, e := range entries.Data {
		entry, ok := e.(*mqlAwsEc2NetworkaclEntry)
		if !ok || entry.Egress.Data != egress {
			continue
		}
		res = append(res, entry)
	}
	sort.SliceStable(res, func(i, j int) bool {
		return res[i].RuleNumber.Data < res[j].RuleNumber.Data
	})
	return res, nil
}

// trafficRule describes the packets one security group rule admits, in the same
// shape network ACL entries are matched in.
func trafficRule(protocol, cidr string, ports portRange) naclIngressRule {
	traffic := naclIngressRule{protocol: protocol, cidr: cidr}
	if ports.all {
		traffic.allPorts = true
	} else {
		traffic.fromPort, traffic.toPort = ports.from, ports.to
	}
	return traffic
}

// evaluateNaclIngressRules decides what a network ACL does to the given traffic,
// returning the verdict and the index of the deciding rule (-1 when none
// matched). rules must already be ordered by rule number ascending.
//
// The first rule matching a packet wins. A rule that fully covers the traffic
// settles it. A rule that only overlaps settles part of the traffic and leaves
// the rest to later rules, which is reported as partial rather than guessed at --
// resolving it properly would mean splitting the range and evaluating each piece,
// and reporting either "allow" or "deny" for the whole would be wrong.
//
// When nothing matches, the network ACL's implicit final deny applies.
func evaluateNaclIngressRules(rules []naclIngressRule, traffic naclIngressRule) (string, int) {
	for i, rule := range rules {
		// Skip rules that cannot apply to this traffic at all. A rule applies
		// when it and the traffic share a protocol, a source address, and a port.
		if !protocolCovers(rule.protocol, traffic.protocol) && !protocolCovers(traffic.protocol, rule.protocol) {
			continue
		}
		if !cidrsOverlap(rule.cidr, traffic.cidr) {
			continue
		}
		if !rule.ports().overlaps(traffic.ports()) {
			continue
		}

		if rule.covers(traffic) {
			if rule.allow {
				return naclVerdictAllow, i
			}
			return naclVerdictDeny, i
		}
		return naclVerdictPartial, i
	}
	return naclVerdictDeny, -1
}

// securityGroupRuleSources expands one security group ingress rule into the
// individual source ranges it permits. Security group references and managed
// prefix lists are skipped: neither resolves to a range a network ACL can be
// evaluated against without further lookups.
func securityGroupRuleSources(perm *mqlAwsEc2SecuritygroupIppermission) ([]string, error) {
	ipRanges := perm.GetIpRanges()
	if ipRanges.Error != nil {
		return nil, ipRanges.Error
	}
	ipv6Ranges := perm.GetIpv6Ranges()
	if ipv6Ranges.Error != nil {
		return nil, ipv6Ranges.Error
	}

	sources := []string{}
	for _, list := range [][]any{ipRanges.Data, ipv6Ranges.Data} {
		for _, r := range list {
			cidr, ok := r.(string)
			if !ok || cidr == "" {
				continue
			}
			sources = append(sources, cidr)
		}
	}
	return sources, nil
}

// effectiveIngress pairs every security group ingress rule reaching this
// interface with the subnet network ACL's decision on it.
//
// Security groups are evaluated as a union -- any rule permitting traffic
// permits it -- so each rule is reported on its own rather than being merged.
// The network ACL applies at the subnet boundary, so all rules are evaluated
// against the same entry list.
func (a *mqlAwsEc2Networkinterface) effectiveIngress() ([]any, error) {
	// The interface ID is part of every row's cache key. An empty one would make
	// rows from different interfaces with matching rules collide and silently
	// replace each other, so fail loudly instead.
	if a.Id.Data == "" {
		return nil, errors.New("cannot evaluate effective ingress: network interface has no id")
	}

	sgs := a.GetSecurityGroups()
	if sgs.Error != nil {
		return nil, sgs.Error
	}

	// An unreadable subnet or network ACL yields the unknown verdict rather than
	// failing the query: the security group half of the answer is still useful,
	// and reporting nothing would read as "no exposure".
	var entries []*mqlAwsEc2NetworkaclEntry
	var naclRules []naclIngressRule
	naclReadable := false
	if subnet := a.GetSubnet(); subnet.Error == nil && subnet.Data != nil {
		if nacl := subnet.Data.GetNetworkAcl(); nacl.Error == nil && nacl.Data != nil {
			ordered, err := orderedNaclEntries(nacl.Data, false)
			if err == nil {
				entries = ordered
				naclRules = make([]naclIngressRule, 0, len(entries))
				for _, entry := range entries {
					naclRules = append(naclRules, naclEntryRule(entry))
				}
				naclReadable = true
			}
		}
	}

	res := []any{}
	for _, s := range sgs.Data {
		sg, ok := s.(*mqlAwsEc2Securitygroup)
		if !ok {
			continue
		}
		perms := sg.GetIpPermissions()
		if perms.Error != nil {
			return nil, perms.Error
		}
		for _, p := range perms.Data {
			perm, ok := p.(*mqlAwsEc2SecuritygroupIppermission)
			if !ok {
				continue
			}
			sources, err := securityGroupRuleSources(perm)
			if err != nil {
				return nil, err
			}
			protocol := perm.GetIpProtocol()
			if protocol.Error != nil {
				return nil, protocol.Error
			}
			fromPort := perm.GetFromPort()
			if fromPort.Error != nil {
				return nil, fromPort.Error
			}
			toPort := perm.GetToPort()
			if toPort.Error != nil {
				return nil, toPort.Error
			}
			ports := newPortRange(fromPort.Data, toPort.Data)

			for _, source := range sources {
				verdict := naclVerdictUnknown
				var matched *mqlAwsEc2NetworkaclEntry
				if naclReadable {
					v, idx := evaluateNaclIngressRules(naclRules, trafficRule(protocol.Data, source, ports))
					verdict = v
					if idx >= 0 {
						matched = entries[idx]
					}
				}

				mqlRule, err := a.newEffectiveIngress(sg, perm, source, protocol.Data, fromPort.Data, toPort.Data, verdict, matched)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlRule)
			}
		}
	}
	return res, nil
}

// verdictIsReachable reports whether a network ACL verdict lets traffic through.
//
// Partial counts as reachable because part of the range does get through, and
// unknown counts as reachable so a failed read never reports an interface as
// protected when it may not be.
func verdictIsReachable(verdict string) bool {
	return verdict != naclVerdictDeny
}

func (a *mqlAwsEc2Networkinterface) newEffectiveIngress(
	sg *mqlAwsEc2Securitygroup,
	perm *mqlAwsEc2SecuritygroupIppermission,
	source string,
	protocol string,
	fromPort int64,
	toPort int64,
	verdict string,
	matched *mqlAwsEc2NetworkaclEntry,
) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"__id":              llx.StringData(fmt.Sprintf("%s/%s/%s/%d-%d/%s", a.Id.Data, sg.Id.Data, protocol, fromPort, toPort, source)),
		"source":            llx.StringData(source),
		"protocol":          llx.StringData(protocol),
		"fromPort":          llx.IntData(fromPort),
		"toPort":            llx.IntData(toPort),
		"securityGroup":     llx.ResourceData(sg, sg.MqlName()),
		"securityGroupRule": llx.ResourceData(perm, perm.MqlName()),
		"networkAclVerdict": llx.StringData(verdict),
		"reachable":         llx.BoolData(verdictIsReachable(verdict)),
	}
	if matched != nil {
		args["networkAclEntry"] = llx.ResourceData(matched, matched.MqlName())
	} else {
		args["networkAclEntry"] = llx.NilData
	}
	return CreateResource(a.MqlRuntime, ResourceAwsNetworkEffectiveIngress, args)
}

// isShadowed reports whether an earlier entry in the same direction makes this
// entry unreachable.
func (a *mqlAwsEc2NetworkaclEntry) isShadowed() (bool, error) {
	if a.parentAcl == nil {
		// The entry was built outside its parent's entry list, so there are no
		// siblings to compare against.
		return false, nil
	}
	entries, err := orderedNaclEntries(a.parentAcl, a.Egress.Data)
	if err != nil {
		return false, err
	}

	self := naclEntryRule(a)
	for _, other := range entries {
		candidate := naclEntryRule(other)
		if candidate.ruleNumber >= self.ruleNumber {
			// Entries are ordered, so nothing from here on is earlier.
			break
		}
		if candidate.covers(self) {
			return true, nil
		}
	}
	return false, nil
}

// mqlAwsEc2Internal memoizes which security groups are referenced by other
// security groups' rules.
//
// Answering that for one group means walking every rule in the account, and
// isUnused asks it once per group, so deriving it per group would be quadratic in
// the number of groups. Building the whole reference map once and sharing it
// through the runtime-cached aws.ec2 singleton makes a full
// `aws.ec2.securityGroups { isUnused }` sweep a single pass instead.
type mqlAwsEc2Internal struct {
	securityGroupRefsOnce sync.Once
	// securityGroupRefs maps a referenced group ID to the IDs of the groups whose
	// rules reference it. The referencing IDs are kept rather than collapsed to a
	// boolean so a group that only references itself is not counted as used.
	securityGroupRefs    map[string][]string
	securityGroupRefsErr error

	// lockedSnapshots holds the snapshot locks of each region, read once per
	// region and shared by every snapshot in it.
	lockedSnapshots lockedSnapshotCache
}

// securityGroupReferences returns the map of referenced group ID to referencing
// group IDs, computing it once per runtime.
func (a *mqlAwsEc2) securityGroupReferences() (map[string][]string, error) {
	a.securityGroupRefsOnce.Do(func() {
		refs := map[string][]string{}
		groups := a.GetSecurityGroups()
		if groups.Error != nil {
			a.securityGroupRefsErr = groups.Error
			return
		}
		for _, g := range groups.Data {
			sg, ok := g.(*mqlAwsEc2Securitygroup)
			if !ok {
				continue
			}
			for _, perms := range []*plugin.TValue[[]any]{sg.GetIpPermissions(), sg.GetIpPermissionsEgress()} {
				if perms.Error != nil {
					a.securityGroupRefsErr = perms.Error
					return
				}
				for _, p := range perms.Data {
					perm, ok := p.(*mqlAwsEc2SecuritygroupIppermission)
					if !ok {
						continue
					}
					pairs := perm.GetUserIdGroupPairs()
					if pairs.Error != nil {
						a.securityGroupRefsErr = pairs.Error
						return
					}
					for _, referenced := range userIdGroupPairIds(pairs.Data) {
						refs[referenced] = append(refs[referenced], sg.Id.Data)
					}
				}
			}
		}
		a.securityGroupRefs = refs
	})
	return a.securityGroupRefs, a.securityGroupRefsErr
}

// isUnused reports whether nothing depends on the security group: it is attached
// to no network interface and no other group references it.
func (a *mqlAwsEc2Securitygroup) isUnused() (bool, error) {
	attached := a.GetIsAttachedToNetworkInterface()
	if attached.Error != nil {
		return false, attached.Error
	}
	if attached.Data {
		return false, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return false, err
	}
	refs, err := obj.(*mqlAwsEc2).securityGroupReferences()
	if err != nil {
		return false, err
	}

	return !referencedByOtherGroup(refs, a.Id.Data), nil
}

// referencedByOtherGroup reports whether any group other than groupId itself
// references it. A group referencing only itself is still unused: nothing else
// depends on it, so deleting it changes no other group's meaning.
func referencedByOtherGroup(refs map[string][]string, groupId string) bool {
	for _, referencingId := range refs[groupId] {
		if referencingId != groupId {
			return true
		}
	}
	return false
}

// userIdGroupPairIds returns the security group IDs a rule's references name.
func userIdGroupPairIds(pairs []any) []string {
	ids := []string{}
	for _, raw := range pairs {
		pair, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := pair["GroupId"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

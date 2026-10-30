// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciNetworkFirewall) id() (string, error) {
	return "oci.networkFirewall", nil
}

func (o *mqlOciNetworkFirewall) firewalls() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci network firewall with region %s", region)

			svc, err := conn.NetworkFirewallClient(region)
			if err != nil {
				return nil, err
			}

			firewalls, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.NetworkFirewallSummary, *string, error) {
				response, err := svc.ListNetworkFirewalls(ctx, networkfirewall.ListNetworkFirewallsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range firewalls {
				fw := firewalls[i]

				var created *time.Time
				if fw.TimeCreated != nil {
					created = &fw.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if fw.TimeUpdated != nil {
					timeUpdated = &fw.TimeUpdated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.networkFirewall.firewall", stringValue(fw.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(fw.Id),
					"name":               llx.StringDataPtr(fw.DisplayName),
					"ipv4Address":        llx.StringDataPtr(fw.Ipv4Address),
					"ipv6Address":        llx.StringDataPtr(fw.Ipv6Address),
					"shape":              llx.StringDataPtr(fw.Shape),
					"state":              llx.StringData(string(fw.LifecycleState)),
					"created":            llx.TimeDataPtr(created),
					"timeUpdated":        llx.TimeDataPtr(timeUpdated),
					"securityAttributes": llx.MapData(definedTagsToAny(fw.SecurityAttributes), types.Dict),
					"freeformTags":       llx.MapData(strMapToAny(fw.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(fw.DefinedTags), types.Any),
					"systemTags":         llx.MapData(definedTagsToAny(fw.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlFw := mqlInstance.(*mqlOciNetworkFirewallFirewall)
				mqlFw.cacheSubnetID = stringValue(fw.SubnetId)
				mqlFw.cachePolicyID = stringValue(fw.NetworkFirewallPolicyId)
				mqlFw.cacheRegion = region
				res = append(res, mqlFw)
			}

			return res, nil
		})
}

type mqlOciNetworkFirewallFirewallInternal struct {
	ociCompartmentRef
	cacheSubnetID string
	cachePolicyID string
	cacheRegion   string
}

func (o *mqlOciNetworkFirewallFirewall) id() (string, error) {
	return "oci.networkFirewall.firewall/" + o.Id.Data, nil
}

func (o *mqlOciNetworkFirewallFirewall) healthStatus() (string, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkFirewallClient(o.cacheRegion)
	if err != nil {
		return "", err
	}
	resp, err := svc.GetNetworkFirewallHealthStatus(context.Background(), networkfirewall.GetNetworkFirewallHealthStatusRequest{
		NetworkFirewallId: new(o.Id.Data),
	})
	if err != nil {
		return "", err
	}
	return string(resp.Status), nil
}

func (o *mqlOciNetworkFirewallFirewall) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlOciNetworkSubnet), nil
}

func (o *mqlOciNetworkFirewallFirewall) policy() (*mqlOciNetworkFirewallPolicy, error) {
	if o.cachePolicyID == "" {
		o.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlPolicy, err := NewResource(o.MqlRuntime, "oci.networkFirewall.policy", map[string]*llx.RawData{
		"id": llx.StringData(o.cachePolicyID),
	})
	if err != nil {
		return nil, err
	}
	return mqlPolicy.(*mqlOciNetworkFirewallPolicy), nil
}

func (o *mqlOciNetworkFirewall) policies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci network firewall policies with region %s", region)

			svc, err := conn.NetworkFirewallClient(region)
			if err != nil {
				return nil, err
			}

			policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.NetworkFirewallPolicySummary, *string, error) {
				response, err := svc.ListNetworkFirewallPolicies(ctx, networkfirewall.ListNetworkFirewallPoliciesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range policies {
				p := policies[i]

				var created *time.Time
				if p.TimeCreated != nil {
					created = &p.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.networkFirewall.policy", stringValue(p.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(p.Id),
					"name":         llx.StringDataPtr(p.DisplayName),
					"state":        llx.StringData(string(p.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(p.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlOciNetworkFirewallPolicy).cacheRegion = region
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

type mqlOciNetworkFirewallPolicyInternal struct {
	ociCompartmentRef
	cacheRegion string
	detail      ociRetryLazy[*networkfirewall.NetworkFirewallPolicy]
}

func (o *mqlOciNetworkFirewallPolicy) fetchDetail() (*networkfirewall.NetworkFirewallPolicy, error) {
	return o.detail.get(func() (*networkfirewall.NetworkFirewallPolicy, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.NetworkFirewallClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetNetworkFirewallPolicy(context.Background(), networkfirewall.GetNetworkFirewallPolicyRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.NetworkFirewallPolicy, nil
	})
}

func (o *mqlOciNetworkFirewallPolicy) description() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return stringValue(detail.Description), nil
}

func (o *mqlOciNetworkFirewallPolicy) attachedFirewallCount() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.AttachedNetworkFirewallCount == nil {
		return 0, nil
	}
	return int64(*detail.AttachedNetworkFirewallCount), nil
}

func initOciNetworkFirewallPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.networkFirewall.policy")
	}

	obj, err := CreateResource(runtime, "oci.networkFirewall", nil)
	if err != nil {
		return nil, nil, err
	}
	nf := obj.(*mqlOciNetworkFirewall)

	rawPolicies := nf.GetPolicies()
	if rawPolicies.Error != nil {
		return nil, nil, rawPolicies.Error
	}

	for _, raw := range rawPolicies.Data {
		policy := raw.(*mqlOciNetworkFirewallPolicy)
		if policy.Id.Data == idVal {
			return args, policy, nil
		}
	}

	return nil, nil, errors.New("oci.networkFirewall.policy not found: " + idVal)
}

func (o *mqlOciNetworkFirewallPolicy) id() (string, error) {
	return "oci.networkFirewall.policy/" + o.Id.Data, nil
}

func (o *mqlOciNetworkFirewallPolicy) decryptionProfiles() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkFirewallClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	// The list returns summaries only (name/type); the blocking booleans
	// require a per-profile Get.
	summaries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.DecryptionProfileSummary, *string, error) {
		resp, err := svc.ListDecryptionProfiles(ctx, networkfirewall.ListDecryptionProfilesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(summaries))
	for i := range summaries {
		name := stringValue(summaries[i].Name)

		getResp, err := svc.GetDecryptionProfile(ctx, networkfirewall.GetDecryptionProfileRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			DecryptionProfileName:   new(name),
		})
		if err != nil {
			return nil, err
		}

		fields := decryptionProfileFields(getResp.DecryptionProfile, summaries[i])
		fields["__id"] = llx.StringData(o.Id.Data + "/decryptionProfile/" + name)

		mqlProfile, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.decryptionProfile", fields)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}
	return res, nil
}

// securityRules lists the policy's security rules, which decide what traffic
// the attached firewalls allow, drop, reject or inspect. Without them a policy
// with no rules at all was indistinguishable from a restrictive one.
func (o *mqlOciNetworkFirewallPolicy) securityRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkFirewallClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.SecurityRuleSummary, *string, error) {
		resp, err := svc.ListSecurityRules(ctx, networkfirewall.ListSecurityRulesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range rules {
		r := rules[i]
		name := stringValue(r.Name)
		mqlRule, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.securityRule", map[string]*llx.RawData{
			"__id":          llx.StringData(o.Id.Data + "/securityRule/" + name),
			"name":          llx.StringData(name),
			"action":        llx.StringData(string(r.Action)),
			"inspection":    llx.StringData(string(r.Inspection)),
			"priorityOrder": llx.IntDataPtr(r.PriorityOrder),
			"description":   llx.StringDataPtr(r.Description),
		})
		if err != nil {
			return nil, err
		}
		// The rule's match criteria are not in the listing, and resolving the
		// names they hold needs the policy's own collections; both reach them
		// through this pointer.
		typed := mqlRule.(*mqlOciNetworkFirewallPolicySecurityRule)
		typed.cachePolicy = o
		res = append(res, typed)
	}
	return res, nil
}

// decryptionRules lists the policy's decryption rules, which decide which TLS
// sessions are decrypted for inspection and under which profile.
func (o *mqlOciNetworkFirewallPolicy) decryptionRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkFirewallClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.DecryptionRuleSummary, *string, error) {
		resp, err := svc.ListDecryptionRules(ctx, networkfirewall.ListDecryptionRulesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range rules {
		r := rules[i]
		name := stringValue(r.Name)
		mqlRule, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.decryptionRule", map[string]*llx.RawData{
			"__id":              llx.StringData(o.Id.Data + "/decryptionRule/" + name),
			"name":              llx.StringData(name),
			"action":            llx.StringData(string(r.Action)),
			"decryptionProfile": llx.StringDataPtr(r.DecryptionProfile),
			"secret":            llx.StringDataPtr(r.Secret),
			"priorityOrder":     llx.IntDataPtr(r.PriorityOrder),
			"description":       llx.StringDataPtr(r.Description),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

// decryptionProfileFields maps an OCI decryption profile to its MQL fields.
// Forward-proxy profiles carry all ten blocking controls; inbound-inspection
// profiles carry only the three shared ones, so the certificate-validation
// controls stay null (llx.BoolDataPtr(nil)) for them. The caller adds the
// synthetic __id.
func decryptionProfileFields(dp networkfirewall.DecryptionProfile, summary networkfirewall.DecryptionProfileSummary) map[string]*llx.RawData {
	fields := map[string]*llx.RawData{
		"name": llx.StringData(stringValue(summary.Name)),
		// Forward-proxy-only fields are null on inbound profiles; the
		// forward-proxy case below overwrites them.
		"isExpiredCertificateBlocked":        llx.BoolDataPtr(nil),
		"isUntrustedIssuerBlocked":           llx.BoolDataPtr(nil),
		"isRevocationStatusTimeoutBlocked":   llx.BoolDataPtr(nil),
		"isUnknownRevocationStatusBlocked":   llx.BoolDataPtr(nil),
		"areCertificateExtensionsRestricted": llx.BoolDataPtr(nil),
		"isAutoIncludeAltName":               llx.BoolDataPtr(nil),
	}

	switch p := dp.(type) {
	case networkfirewall.SslForwardProxyProfile:
		fields["type"] = llx.StringData(string(networkfirewall.InspectionTypeSslForwardProxy))
		fields["description"] = llx.StringDataPtr(p.Description)
		fields["isUnsupportedVersionBlocked"] = llx.BoolDataPtr(p.IsUnsupportedVersionBlocked)
		fields["isUnsupportedCipherBlocked"] = llx.BoolDataPtr(p.IsUnsupportedCipherBlocked)
		fields["isOutOfCapacityBlocked"] = llx.BoolDataPtr(p.IsOutOfCapacityBlocked)
		fields["isExpiredCertificateBlocked"] = llx.BoolDataPtr(p.IsExpiredCertificateBlocked)
		fields["isUntrustedIssuerBlocked"] = llx.BoolDataPtr(p.IsUntrustedIssuerBlocked)
		fields["isRevocationStatusTimeoutBlocked"] = llx.BoolDataPtr(p.IsRevocationStatusTimeoutBlocked)
		fields["isUnknownRevocationStatusBlocked"] = llx.BoolDataPtr(p.IsUnknownRevocationStatusBlocked)
		fields["areCertificateExtensionsRestricted"] = llx.BoolDataPtr(p.AreCertificateExtensionsRestricted)
		fields["isAutoIncludeAltName"] = llx.BoolDataPtr(p.IsAutoIncludeAltName)
	case networkfirewall.SslInboundInspectionProfile:
		fields["type"] = llx.StringData(string(networkfirewall.InspectionTypeSslInboundInspection))
		fields["description"] = llx.StringDataPtr(p.Description)
		fields["isUnsupportedVersionBlocked"] = llx.BoolDataPtr(p.IsUnsupportedVersionBlocked)
		fields["isUnsupportedCipherBlocked"] = llx.BoolDataPtr(p.IsUnsupportedCipherBlocked)
		fields["isOutOfCapacityBlocked"] = llx.BoolDataPtr(p.IsOutOfCapacityBlocked)
	default:
		// Unknown profile type (an inspection type newer than the pinned SDK):
		// surface the summary type and report the controls as not blocking.
		// Null would make `isUnsupportedVersionBlocked &&
		// isUnsupportedCipherBlocked` evaluate to true, so a profile we could
		// not decode would pass a TLS-hygiene check it was never measured for.
		// That reasoning applies to every control, so the forward-proxy-only
		// fields seeded null above are overwritten here too - leaving them null
		// let `isExpiredCertificateBlocked && isUntrustedIssuerBlocked` pass for
		// exactly the profile we failed to decode.
		fields["type"] = llx.StringData(string(summary.Type))
		fields["description"] = llx.StringDataPtr(summary.Description)
		fields["isUnsupportedVersionBlocked"] = llx.BoolData(false)
		fields["isUnsupportedCipherBlocked"] = llx.BoolData(false)
		fields["isOutOfCapacityBlocked"] = llx.BoolData(false)
		fields["isExpiredCertificateBlocked"] = llx.BoolData(false)
		fields["isUntrustedIssuerBlocked"] = llx.BoolData(false)
		fields["isRevocationStatusTimeoutBlocked"] = llx.BoolData(false)
		fields["isUnknownRevocationStatusBlocked"] = llx.BoolData(false)
		fields["areCertificateExtensionsRestricted"] = llx.BoolData(false)
		fields["isAutoIncludeAltName"] = llx.BoolData(false)
	}
	return fields
}

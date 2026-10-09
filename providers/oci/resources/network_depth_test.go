// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestDhcpOptionSetArgs(t *testing.T) {
	args := dhcpOptionSetArgs(core.DhcpOptions{
		Id: common.String("d1"),
		Options: []core.DhcpOption{
			core.DhcpDnsOption{ServerType: core.DhcpDnsOptionServerTypeCustomdnsserver, CustomDnsServers: []string{"192.0.2.53"}},
			core.DhcpSearchDomainOption{SearchDomainNames: []string{"corp.example"}},
		},
		DomainNameType: core.DhcpOptionsDomainNameTypeCustomDomain,
	})
	assert.Equal(t, "CustomDnsServer", args["serverType"].Value)
	assert.Equal(t, []any{"192.0.2.53"}, args["customDnsServers"].Value)
	assert.Equal(t, []any{"corp.example"}, args["searchDomains"].Value)
	assert.Equal(t, "CUSTOM_DOMAIN", args["domainNameType"].Value)

	empty := dhcpOptionSetArgs(core.DhcpOptions{Id: common.String("d2")})
	assert.Equal(t, "", empty["serverType"].Value)
	assert.Equal(t, []any{}, empty["customDnsServers"].Value)
}

func TestDrgDistributionStatementArgs(t *testing.T) {
	byType, id := drgDistributionStatementArgs(core.DrgRouteDistributionStatement{
		Priority: common.Int(10),
		Action:   core.DrgRouteDistributionStatementActionAccept,
		MatchCriteria: []core.DrgRouteDistributionMatchCriteria{
			core.DrgAttachmentTypeDrgRouteDistributionMatchCriteria{AttachmentType: core.DrgAttachmentTypeDrgRouteDistributionMatchCriteriaAttachmentTypeIpsecTunnel},
		},
	})
	assert.Equal(t, "DRG_ATTACHMENT_TYPE", byType["matchType"].Value)
	assert.Equal(t, "IPSEC_TUNNEL", byType["matchAttachmentType"].Value)
	assert.Equal(t, int64(10), byType["priority"].Value)
	assert.Empty(t, id)

	byID, id := drgDistributionStatementArgs(core.DrgRouteDistributionStatement{
		MatchCriteria: []core.DrgRouteDistributionMatchCriteria{
			core.DrgAttachmentIdDrgRouteDistributionMatchCriteria{DrgAttachmentId: common.String("ocid1.drgattachment..a")},
		},
	})
	assert.Equal(t, "DRG_ATTACHMENT_ID", byID["matchType"].Value)
	assert.Equal(t, "ocid1.drgattachment..a", id)

	all, _ := drgDistributionStatementArgs(core.DrgRouteDistributionStatement{})
	assert.Equal(t, "MATCH_ALL", all["matchType"].Value, "a statement without criteria matches everything")
}

func TestCaptureFilterRuleArgs(t *testing.T) {
	rules := captureFilterRuleArgs(core.CaptureFilter{
		VtapCaptureFilterRules: []core.VtapCaptureFilterRuleDetails{{
			TrafficDirection: core.VtapCaptureFilterRuleDetailsTrafficDirectionIngress,
			RuleAction:       core.VtapCaptureFilterRuleDetailsRuleActionInclude,
			SourceCidr:       common.String("0.0.0.0/0"),
		}},
		FlowLogCaptureFilterRules: []core.FlowLogCaptureFilterRuleDetails{{
			IsEnabled:    common.Bool(false),
			Priority:     common.Int(1),
			SamplingRate: common.Int(10),
			RuleAction:   core.FlowLogCaptureFilterRuleDetailsRuleActionExclude,
		}},
	})
	require.Len(t, rules, 2)
	assert.Equal(t, "INGRESS", rules[0]["direction"].Value)
	assert.Equal(t, true, rules[0]["isEnabled"].Value, "a VTAP rule is always in force")
	assert.Nil(t, rules[0]["priority"].Value)
	assert.Equal(t, "", rules[1]["direction"].Value)
	assert.Equal(t, false, rules[1]["isEnabled"].Value)
	assert.Equal(t, int64(10), rules[1]["samplingRate"].Value)
}

func TestCrossConnectGroupArgs(t *testing.T) {
	withMacsec := crossConnectGroupArgs(core.CrossConnectGroup{
		Id: common.String("g1"),
		MacsecProperties: &core.MacsecProperties{
			State:                       core.MacsecStateEnabled,
			EncryptionCipher:            core.MacsecEncryptionCipherAes256GcmXpn,
			IsUnprotectedTrafficAllowed: common.Bool(true),
		},
	})
	assert.Equal(t, "ENABLED", withMacsec["macsecState"].Value)
	assert.Equal(t, "AES256_GCM_XPN", withMacsec["macsecEncryptionCipher"].Value)
	assert.Equal(t, true, withMacsec["macsecIsUnprotectedTrafficAllowed"].Value)

	none := crossConnectGroupArgs(core.CrossConnectGroup{Id: common.String("g2")})
	assert.Equal(t, "", none["macsecState"].Value, "a group without MACsec reports no state")
	assert.Equal(t, false, none["macsecIsUnprotectedTrafficAllowed"].Value)
}

func TestChildrenOf(t *testing.T) {
	a := &mqlOciNetworkDrgRouteTable{}
	a.cacheDrgID = "drg1"
	b := &mqlOciNetworkDrgRouteTable{}
	b.cacheDrgID = "drg2"
	got, err := childrenOf(&plugin.TValue[[]any]{Data: []any{a, b}}, "drg1", func(t *mqlOciNetworkDrgRouteTable) string { return t.cacheDrgID })
	require.NoError(t, err)
	assert.Equal(t, []any{a}, got)
}

func TestVtapRefID(t *testing.T) {
	assert.Equal(t, "ocid1.subnet.oc1..s", vtapRefID("SUBNET", "SUBNET", "ocid1.subnet.oc1..s"))
	assert.Equal(t, "", vtapRefID("SUBNET", "VNIC", "ocid1.subnet.oc1..s"), "an accessor of another kind reads null")
	assert.Equal(t, "", vtapRefID("VNIC", "VNIC", ""), "no id is no reference")
}

func TestRowKey(t *testing.T) {
	assert.Equal(t, "rule-1", rowKey("rule-1", 3), "an id keeps the key stable across listings")
	assert.Equal(t, "#3", rowKey("", 3))
	assert.NotEqual(t, rowKey("", 0), rowKey("", 1), "rows without an id get distinct keys")
}

func TestVtapArgsTargetIDNull(t *testing.T) {
	args := vtapArgs(core.Vtap{Id: common.String("v"), TargetType: core.VtapTargetTypeIpAddress, TargetIp: common.String("10.0.0.9")})
	assert.Nil(t, args["targetId"].Value, "an IP address target has no OCID")
	assert.Equal(t, "10.0.0.9", args["targetIp"].Value)
}

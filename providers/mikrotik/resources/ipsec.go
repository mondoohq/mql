// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- ip.ipsec.proposal ---

func ipsecProposalArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":           llx.StringData("mikrotik.ip.ipsec.proposal/" + row["name"]),
		"name":           llx.StringData(row["name"]),
		"encAlgorithms":  listField(row, "enc-algorithms"),
		"authAlgorithms": listField(row, "auth-algorithms"),
		"pfsGroup":       llx.StringData(row["pfs-group"]),
		"lifetime":       llx.StringData(row["lifetime"]),
		"default":        boolField(row, "default"),
		"disabled":       boolField(row, "disabled"),
		"comment":        llx.StringData(row["comment"]),
	}
}

func newMikrotikIpsecProposal(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.ipsec.proposal", ipsecProposalArgs(row))
}

func (r *mqlMikrotik) ipsecProposals() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/proposal")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpsecProposal)
}

// --- ip.ipsec.profile ---

func ipsecProfileArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData("mikrotik.ip.ipsec.profile/" + row["name"]),
		"name":               llx.StringData(row["name"]),
		"hashAlgorithm":      llx.StringData(row["hash-algorithm"]),
		"encAlgorithms":      listField(row, "enc-algorithm"),
		"dhGroups":           listField(row, "dh-group"),
		"prfAlgorithm":       llx.StringData(row["prf-algorithm"]),
		"proposalCheck":      llx.StringData(row["proposal-check"]),
		"lifetime":           llx.StringData(row["lifetime"]),
		"natTraversal":       boolField(row, "nat-traversal"),
		"dpdInterval":        llx.StringData(row["dpd-interval"]),
		"dpdMaximumFailures": intField(row, "dpd-maximum-failures"),
	}
}

func newMikrotikIpsecProfile(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.ipsec.profile", ipsecProfileArgs(row))
}

func (r *mqlMikrotik) ipsecProfiles() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/profile")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpsecProfile)
}

// --- ip.ipsec.peer ---

type mqlMikrotikIpIpsecPeerInternal struct {
	cacheProfile string
}

func ipsecPeerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData(rowID("mikrotik.ip.ipsec.peer/", row, row["name"], row["address"])),
		"name":               llx.StringData(row["name"]),
		"address":            llx.StringData(row["address"]),
		"localAddress":       llx.StringData(row["local-address"]),
		"port":               intField(row, "port"),
		"exchangeMode":       llx.StringData(row["exchange-mode"]),
		"passive":            boolField(row, "passive"),
		"sendInitialContact": boolField(row, "send-initial-contact"),
		"disabled":           boolField(row, "disabled"),
		"comment":            llx.StringData(row["comment"]),
	}
}

func newMikrotikIpsecPeer(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.ip.ipsec.peer", ipsecPeerArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpIpsecPeer).cacheProfile = row["profile"]
	return res, nil
}

func (r *mqlMikrotik) ipsecPeers() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/peer")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpsecPeer)
}

// profile resolves the peer's profile against the already-cached profile
// listing, so a fleet of peers costs one read of /ip/ipsec/profile rather than
// one per peer.
func (r *mqlMikrotikIpIpsecPeer) profile() (*mqlMikrotikIpIpsecProfile, error) {
	null := func() (*mqlMikrotikIpIpsecProfile, error) {
		r.Profile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if r.cacheProfile == "" {
		return null()
	}
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/profile")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row["name"] == r.cacheProfile {
			res, err := newMikrotikIpsecProfile(r.MqlRuntime, row)
			if err != nil {
				return nil, err
			}
			return res.(*mqlMikrotikIpIpsecProfile), nil
		}
	}
	return null()
}

// --- ip.ipsec.identity ---

type mqlMikrotikIpIpsecIdentityInternal struct {
	cachePeer              string
	cacheCertificate       string
	cacheRemoteCertificate string
}

// cacheRefs stores the names the identity points at, so peer,
// certificate and remoteCertificate can resolve them without the raw
// names being carried as fields that duplicate what the references already
// report.
func (r *mqlMikrotikIpIpsecIdentity) cacheRefs(row map[string]string) {
	r.cachePeer = row["peer"]
	r.cacheCertificate = certificateRefName(row["certificate"])
	r.cacheRemoteCertificate = certificateRefName(row["remote-certificate"])
}

func ipsecIdentityArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(rowID("mikrotik.ip.ipsec.identity/", row, row["peer"])),
		"authMethod": llx.StringData(row["auth-method"]),
		// the pre-shared key, the EAP password, and the raw key material are
		// never read; only whether a key is configured at all
		"hasSecret":           presenceField(row, "secret"),
		"generatePolicy":      llx.StringData(row["generate-policy"]),
		"policyTemplateGroup": llx.StringData(row["policy-template-group"]),
		"matchBy":             llx.StringData(row["match-by"]),
		"modeConfig":          llx.StringData(row["mode-config"]),
		"myIdType":            llx.StringData(row["my-id-type"]),
		"myId":                llx.StringData(row["my-id"]),
		"remoteIdType":        llx.StringData(row["remote-id-type"]),
		"remoteId":            llx.StringData(row["remote-id"]),
		"notrackChain":        llx.StringData(row["notrack-chain"]),
		"disabled":            boolField(row, "disabled"),
		"comment":             llx.StringData(row["comment"]),
	}
}

func newMikrotikIpsecIdentity(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.ip.ipsec.identity", ipsecIdentityArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpIpsecIdentity).cacheRefs(row)
	return res, nil
}

func (r *mqlMikrotik) ipsecIdentities() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/identity")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpsecIdentity)
}

// peer resolves the identity's peer against the already-cached peer listing.
func (r *mqlMikrotikIpIpsecIdentity) peer() (*mqlMikrotikIpIpsecPeer, error) {
	null := func() (*mqlMikrotikIpIpsecPeer, error) {
		r.Peer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if r.cachePeer == "" {
		return null()
	}
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/ipsec/peer")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row["name"] == r.cachePeer {
			res, err := newMikrotikIpsecPeer(r.MqlRuntime, row)
			if err != nil {
				return nil, err
			}
			return res.(*mqlMikrotikIpIpsecPeer), nil
		}
	}
	return null()
}

// certificate resolves the certificate the identity presents against the
// already-cached /certificate listing.
func (r *mqlMikrotikIpIpsecIdentity) certificate() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}

// remoteCertificate resolves the certificate the identity expects from the
// peer against the already-cached /certificate listing.
func (r *mqlMikrotikIpIpsecIdentity) remoteCertificate() (*mqlMikrotikCertificate, error) {
	if r.cacheRemoteCertificate == "" {
		r.RemoteCertificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheRemoteCertificate)
}

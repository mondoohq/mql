// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// errFlexReachabilityUnknown is returned by a Flex instance's
// internetReachable() when the instance detail (and thus its ACL) could not be
// fetched, typically because the token can list instances but is denied
// GetInstance. Surfacing an error keeps an `internetReachable == false`
// assertion from passing vacuously when exposure was never actually determined.
var errFlexReachabilityUnknown = errors.New("stackit: cannot determine internet reachability, instance ACL unavailable (access denied to GetInstance)")

// nicsHavePublicIp reports whether any network interface dict carries a
// non-empty public IP.
func nicsHavePublicIp(nics []any) bool {
	for _, n := range nics {
		nic, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if ip, ok := nic["publicIp"].(string); ok && ip != "" {
			return true
		}
	}
	return false
}

// securityRuleOpenToInternet reports whether a security group rule is an ingress
// rule whose remote CIDR admits any address (0.0.0.0/0 or ::/0).
func securityRuleOpenToInternet(direction, ipRange string) bool {
	if !strings.EqualFold(direction, "ingress") {
		return false
	}
	return ipRange == "0.0.0.0/0" || ipRange == "::/0"
}

// exposure breaks down whether the server is reachable from the internet: a
// network interface with a public IP combined with a security group ingress
// rule that admits any address.
func (s *mqlStackitServer) exposure() (*mqlStackitNetworkExposure, error) {
	id := s.GetId()
	if id.Error != nil {
		return nil, id.Error
	}

	hasPublicIp := nicsHavePublicIp(s.cacheNics)

	openRules := []any{}
	sgs := s.GetSecurityGroups()
	if sgs.Error != nil {
		return nil, sgs.Error
	}
	for _, g := range sgs.Data {
		sg, ok := g.(*mqlStackitSecurityGroup)
		if !ok {
			continue
		}
		rules := sg.GetRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		for _, r := range rules.Data {
			rule, ok := r.(*mqlStackitSecurityGroupRule)
			if !ok {
				continue
			}
			direction := rule.GetDirection()
			if direction.Error != nil {
				return nil, direction.Error
			}
			ipRange := rule.GetIpRange()
			if ipRange.Error != nil {
				return nil, ipRange.Error
			}
			if securityRuleOpenToInternet(direction.Data, ipRange.Data) {
				openRules = append(openRules, rule)
			}
		}
	}
	sgAllows := len(openRules) > 0
	internetReachable := hasPublicIp && sgAllows

	res, err := CreateResource(s.MqlRuntime, "stackit.network.exposure", map[string]*llx.RawData{
		"__id":                       llx.StringData("stackit.server/" + id.Data + "/exposure"),
		"internetReachable":          llx.BoolData(internetReachable),
		"hasPublicIp":                llx.BoolData(hasPublicIp),
		"securityGroupAllowsIngress": llx.BoolData(sgAllows),
		"openIngressRules":           llx.ArrayData(openRules, types.Resource("stackit.securityGroup.rule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitNetworkExposure), nil
}

// cidrIsAnyAddress reports whether a CIDR string admits any address — the
// IPv4 default route 0.0.0.0/0 or the IPv6 default route ::/0. Surrounding
// whitespace is tolerated.
func cidrIsAnyAddress(cidr string) bool {
	c := strings.TrimSpace(cidr)
	return c == "0.0.0.0/0" || c == "::/0"
}

// aclAllowsAnyAddress reports whether a list of allowed source CIDRs leaves the
// resource open to the internet. An empty (or all-blank) allow-list means "no
// restriction" — every address is admitted — and a list that explicitly
// contains a default route (0.0.0.0/0 or ::/0) is equally open.
func aclAllowsAnyAddress(ranges []string) bool {
	hasEntry := false
	for _, r := range ranges {
		if strings.TrimSpace(r) == "" {
			continue
		}
		hasEntry = true
		if cidrIsAnyAddress(r) {
			return true
		}
	}
	return !hasEntry
}

// dictStrSlice coerces a dict value that should be a list of strings into a
// []string. It accepts a JSON array of strings ([]any) as well as a single
// comma-separated string (the form some DBaaS parameter blobs use for ACLs).
func dictStrSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			out = append(out, strings.TrimSpace(p))
		}
		return out
	default:
		return nil
	}
}

// dictStr reads a single string value out of a dict, returning "" when the
// value is missing or not a string.
func dictStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// dictInt reads a whole number out of a dict value. Values that arrived
// through a JSON round-trip are float64; native ints and numeric strings are
// accepted too. The second result is false when the value is absent, not
// numeric, or not a whole number.
func dictInt(v any) (int64, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case float64:
		if n < math.MinInt64 || n > math.MaxInt64 || n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

// dictBool reads a bool-ish value out of a dict. STACKIT parameter blobs encode
// booleans as actual bools or as the strings "true"/"false".
func dictBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

// lbAccessControlRanges pulls the allowed-source-range allow-list out of a load
// balancer's `options` dict (options.accessControl.allowedSourceRanges). Both
// the legacy and ALB load balancers serialize options with the same shape.
func lbAccessControlRanges(options any) []string {
	opts, ok := options.(map[string]any)
	if !ok {
		return nil
	}
	ac, ok := opts["accessControl"].(map[string]any)
	if !ok {
		return nil
	}
	return dictStrSlice(ac["allowedSourceRanges"])
}

// lbPrivateNetworkOnly reads the privateNetworkOnly flag out of a load
// balancer's `options` dict, the canonical "no public address" signal that
// applies to both load balancer products.
func lbPrivateNetworkOnly(options any) bool {
	opts, ok := options.(map[string]any)
	if !ok {
		return false
	}
	return dictBool(opts["privateNetworkOnly"])
}

// lbExposure computes the three exposure booleans for a load balancer from its
// public address, its privateNetworkOnly flag, and the access-control
// allow-list. The load balancer is internet-reachable when it carries a public
// address and the allow-list admits any source address.
func lbExposure(externalAddress string, privateNetworkOnly bool, options any) (internetReachable, hasPublicIp, allowsIngress bool) {
	hasPublicIp = !privateNetworkOnly && strings.TrimSpace(externalAddress) != ""
	allowsIngress = aclAllowsAnyAddress(lbAccessControlRanges(options))
	internetReachable = hasPublicIp && allowsIngress
	return
}

// dbaasInstanceReachable reports whether a DBaaS-style managed instance
// (OpenSearch, MariaDB, Redis, RabbitMQ, LogMe) is reachable from the internet.
// These instances surface their networking through the free-form `parameters`
// blob, and the SDK's InstanceParameters model documents exactly one network
// key on it: `sgw_acl`, the comma-separated CIDR allow-list ("IP networks
// which are allowed to access this instance"). The instance is reachable when
// that list admits any address, or is absent.
//
// An `enable_public_access` key is honored only when the API actually sends
// it: an explicit false short-circuits to "not reachable". No engine's
// InstanceParameters model declares the key, so it is usually absent, and an
// absent key must not be read as false. Doing so reported every CF-broker
// instance as unreachable regardless of its allow-list, which is the
// reassuring answer and the wrong one.
func dbaasInstanceReachable(parameters any) bool {
	params, ok := parameters.(map[string]any)
	if !ok {
		return false
	}
	if v, present := params["enable_public_access"]; present && !dictBool(v) {
		return false
	}
	return aclAllowsAnyAddress(dictStrSlice(params["sgw_acl"]))
}

// flexInstanceReachable reports whether a Flex managed database (Postgres,
// MongoDB, SQLServer) is reachable from the internet. These services expose
// their connection allow-list directly as an ACL CIDR list, and the instance is
// internet-reachable only when that list explicitly admits a default route
// (0.0.0.0/0 or ::/0).
//
// Unlike the DBaaS and load-balancer paths — which gate on an explicit
// enable_public_access / public-IP signal before consulting the allow-list —
// the Flex SDK exposes no public-endpoint flag (see postgresflex.Instance,
// which carries only an ACL). An *empty* ACL is therefore deliberately NOT
// treated as internet-open here: doing so would report a false positive for a
// VPC-only instance, or one whose ACL simply has not been populated, that is not
// actually reachable from the public internet.
func flexInstanceReachable(acl []any) bool {
	for _, a := range acl {
		if s, ok := a.(string); ok && cidrIsAnyAddress(s) {
			return true
		}
	}
	return false
}

// loadBalancerExposure builds the network-exposure breakdown for a legacy
// load balancer. The access-control allow-list takes the place of a security
// group; openIngressRules is empty because the legacy LB has no per-rule model.
func (c *mqlStackitLoadBalancer) exposure() (*mqlStackitNetworkExposure, error) {
	name := c.GetName()
	if name.Error != nil {
		return nil, name.Error
	}
	ext := c.GetExternalAddress()
	if ext.Error != nil {
		return nil, ext.Error
	}
	pno := c.GetPrivateNetworkOnly()
	if pno.Error != nil {
		return nil, pno.Error
	}
	opts := c.GetOptions()
	if opts.Error != nil {
		return nil, opts.Error
	}

	reachable, hasPublicIp, allows := lbExposure(ext.Data, pno.Data, opts.Data)
	return newNetworkExposure(c.MqlRuntime,
		"stackit.loadBalancer/"+name.Data+"/exposure",
		reachable, hasPublicIp, allows)
}

// exposure builds the network-exposure breakdown for an Application Load
// Balancer, mirroring the legacy load balancer's access-control model.
//
// Note: unlike the legacy load balancer (which surfaces privateNetworkOnly as a
// top-level field), the ALB carries the flag inside its `options` blob, so it is
// read via lbPrivateNetworkOnly(opts.Data). If the ALB API ever promotes the
// flag to a top-level field, switch to that accessor here.
func (c *mqlStackitAlbLoadBalancer) exposure() (*mqlStackitNetworkExposure, error) {
	name := c.GetName()
	if name.Error != nil {
		return nil, name.Error
	}
	ext := c.GetExternalAddress()
	if ext.Error != nil {
		return nil, ext.Error
	}
	opts := c.GetOptions()
	if opts.Error != nil {
		return nil, opts.Error
	}

	reachable, hasPublicIp, allows := lbExposure(ext.Data, lbPrivateNetworkOnly(opts.Data), opts.Data)
	return newNetworkExposure(c.MqlRuntime,
		"stackit.alb.loadBalancer/"+name.Data+"/exposure",
		reachable, hasPublicIp, allows)
}

// newNetworkExposure creates a stackit.network.exposure resource with no
// security-group rule list — used by load balancers, whose internet gate is an
// access-control allow-list rather than discrete security-group rules.
func newNetworkExposure(runtime *plugin.Runtime, id string, internetReachable, hasPublicIp, allowsIngress bool) (*mqlStackitNetworkExposure, error) {
	res, err := CreateResource(runtime, "stackit.network.exposure", map[string]*llx.RawData{
		"__id":                       llx.StringData(id),
		"internetReachable":          llx.BoolData(internetReachable),
		"hasPublicIp":                llx.BoolData(hasPublicIp),
		"securityGroupAllowsIngress": llx.BoolData(allowsIngress),
		"openIngressRules":           llx.ArrayData([]any{}, types.Resource("stackit.securityGroup.rule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitNetworkExposure), nil
}

// ---- Flex managed databases (ACL-based) ----

func (c *mqlStackitPostgresFlexInstance) internetReachable() (bool, error) {
	d, err := c.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, errFlexReachabilityUnknown
	}
	acl := c.GetAcl()
	if acl.Error != nil {
		return false, acl.Error
	}
	return flexInstanceReachable(acl.Data), nil
}

func (c *mqlStackitMongoDbFlexInstance) internetReachable() (bool, error) {
	d, err := c.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, errFlexReachabilityUnknown
	}
	acl := c.GetAcl()
	if acl.Error != nil {
		return false, acl.Error
	}
	return flexInstanceReachable(acl.Data), nil
}

func (c *mqlStackitSqlServerFlexInstance) internetReachable() (bool, error) {
	d, err := c.fetchDetail()
	if err != nil {
		return false, err
	}
	if d == nil {
		return false, errFlexReachabilityUnknown
	}
	acl := c.GetAcl()
	if acl.Error != nil {
		return false, acl.Error
	}
	return flexInstanceReachable(acl.Data), nil
}

// ---- DBaaS managed instances (parameters-based) ----

func (c *mqlStackitOpenSearchInstance) internetReachable() (bool, error) {
	params := c.GetParameters()
	if params.Error != nil {
		return false, params.Error
	}
	return dbaasInstanceReachable(params.Data), nil
}

func (c *mqlStackitMariaDbInstance) internetReachable() (bool, error) {
	params := c.GetParameters()
	if params.Error != nil {
		return false, params.Error
	}
	return dbaasInstanceReachable(params.Data), nil
}

func (c *mqlStackitRedisInstance) internetReachable() (bool, error) {
	params := c.GetParameters()
	if params.Error != nil {
		return false, params.Error
	}
	return dbaasInstanceReachable(params.Data), nil
}

func (c *mqlStackitRabbitMqInstance) internetReachable() (bool, error) {
	params := c.GetParameters()
	if params.Error != nil {
		return false, params.Error
	}
	return dbaasInstanceReachable(params.Data), nil
}

func (c *mqlStackitLogMeInstance) internetReachable() (bool, error) {
	params := c.GetParameters()
	if params.Error != nil {
		return false, params.Error
	}
	return dbaasInstanceReachable(params.Data), nil
}

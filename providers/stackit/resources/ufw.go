// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	ufw "github.com/stackitcloud/stackit-sdk-go/services/ufw/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlStackit) ufw() (*mqlStackitUfw, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.ufw")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitUfw), nil
}

// ufwPageSize is the page size asked of ListRules. The service caps a larger
// request at its own maximum, so the walk below does not rely on a short page
// to detect the end.
const ufwPageSize int32 = 1000

// ufwNextCursor decides whether another ListRules page follows the given one
// and which cursor asks for it. The rule list carries no cursor of its own;
// each rule reports its position as offset, and a cursor names the position
// the next page starts after. The walk ends on an empty page, on a page whose
// last rule reports no position, and on a page that does not move past the
// previous one, so a service that ignores the cursor cannot loop forever.
func ufwNextCursor(prevLast *int32, page []ufw.RuleResponse) (string, *int32, bool) {
	if len(page) == 0 {
		return "", prevLast, false
	}
	last, ok := page[len(page)-1].GetOffsetOk()
	if !ok || last == nil {
		return "", prevLast, false
	}
	if prevLast != nil && *last <= *prevLast {
		return "", prevLast, false
	}
	return strconv.FormatInt(int64(*last), 10), last, true
}

// ufwPageAdvances reports whether a page returned for a cursor holds rules
// past the previous page, rather than repeating it.
func ufwPageAdvances(prevLast *int32, page []ufw.RuleResponse) bool {
	if prevLast == nil || len(page) == 0 {
		return true
	}
	first, ok := page[0].GetOffsetOk()
	if !ok || first == nil {
		return true
	}
	return *first > *prevLast
}

func (r *mqlStackitUfw) rules() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Ufw()
	if err != nil {
		return nil, err
	}
	out := []any{}
	seen := map[string]struct{}{}
	var cursor string
	var prevLast *int32
	for {
		req := client.DefaultAPI.ListRules(bgctx(), c.ProjectID(), c.Region()).Limit(ufwPageSize)
		if cursor != "" {
			req = req.Cursor(cursor)
		}
		resp, err := req.Execute()
		if err != nil {
			if isNotFound(err) {
				return out, nil
			}
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		for _, msg := range resp.GetErrors() {
			log.Debug().Str("error", msg).Msg("stackit> unified firewall reported a partial rule list")
		}
		page := resp.GetRules()
		if !ufwPageAdvances(prevLast, page) {
			break
		}
		for i := range page {
			key := ufwRuleKey(c.ProjectID(), c.Region(), &page[i])
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			res, err := buildUfwRule(r.MqlRuntime, key, &page[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		next, last, more := ufwNextCursor(prevLast, page)
		if !more {
			break
		}
		cursor, prevLast = next, last
	}
	return out, nil
}

// ufwRuleKey builds the cache key of a firewall rule. A rule carries the ID
// it has in its product as refId; where that is missing, the key is derived
// from every field that tells two rules of one product instance apart.
func ufwRuleKey(projectID, region string, rule *ufw.RuleResponse) string {
	base := "stackit.ufw.rule/" + projectID + "/" + region + "/" + rule.GetProduct() + "/" + rule.GetInstanceId()
	if ref := rule.GetRefId(); ref != "" {
		return base + "/" + ref
	}
	offset := ""
	if o, ok := rule.GetOffsetOk(); ok && o != nil {
		offset = strconv.FormatInt(int64(*o), 10)
	}
	parts := []string{
		string(rule.GetType()), rule.GetDirection(), rule.GetSourceIP(), rule.GetIpRange(),
		rule.GetDestination(), rule.GetPortRange(), rule.GetProtocol(), rule.GetEtherType(),
		rule.GetSecurityGroupId(), rule.GetRemoteSecurityGroupId(), offset,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return base + "/" + hex.EncodeToString(sum[:8])
}

// mqlStackitUfwRuleInternal keeps the two security group IDs the rule names,
// which the typed accessors resolve.
type mqlStackitUfwRuleInternal struct {
	cacheSecurityGroupID       string
	cacheRemoteSecurityGroupID string
}

func ufwRuleArgs(key string, rule *ufw.RuleResponse) map[string]*llx.RawData {
	var offset *int64
	if o, ok := rule.GetOffsetOk(); ok && o != nil {
		v := int64(*o)
		offset = &v
	}
	return map[string]*llx.RawData{
		"__id":         llx.StringData(key),
		"refId":        llx.StringData(rule.GetRefId()),
		"product":      llx.StringData(rule.GetProduct()),
		"instanceId":   llx.StringData(rule.GetInstanceId()),
		"instanceName": llx.StringData(rule.GetInstanceName()),
		"type":         llx.StringData(string(rule.GetType())),
		"direction":    llx.StringData(rule.GetDirection()),
		"sourceIp":     llx.StringData(rule.GetSourceIP()),
		"ipRange":      llx.StringData(rule.GetIpRange()),
		"destination":  llx.StringData(rule.GetDestination()),
		"portRange":    llx.StringData(rule.GetPortRange()),
		"protocol":     llx.StringData(rule.GetProtocol()),
		"etherType":    llx.StringData(rule.GetEtherType()),
		"stateful":     llx.BoolDataPtr(optBool(rule.GetStatefulOk())),
		"status":       llx.StringData(string(rule.GetStatus())),
		"errorMessage": llx.StringData(rule.GetErrorMessage()),
		"description":  llx.StringData(rule.GetDescription()),
		"offset":       llx.IntDataPtr(offset),
		"region":       llx.StringData(rule.GetRegion()),
	}
}

func buildUfwRule(runtime *plugin.Runtime, key string, rule *ufw.RuleResponse) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "stackit.ufw.rule", ufwRuleArgs(key, rule))
	if err != nil {
		return nil, err
	}
	r := res.(*mqlStackitUfwRule)
	r.cacheSecurityGroupID = rule.GetSecurityGroupId()
	r.cacheRemoteSecurityGroupID = rule.GetRemoteSecurityGroupId()
	return res, nil
}

func (r *mqlStackitUfwRule) securityGroup() (*mqlStackitSecurityGroup, error) {
	return projectSecurityGroup(r.MqlRuntime, r.cacheSecurityGroupID, &r.SecurityGroup)
}

func (r *mqlStackitUfwRule) remoteSecurityGroup() (*mqlStackitSecurityGroup, error) {
	return projectSecurityGroup(r.MqlRuntime, r.cacheRemoteSecurityGroupID, &r.RemoteSecurityGroup)
}

// projectSecurityGroup resolves a security group from the project's cached
// group list. The field is null for an empty ID and for a group the project
// does not hold: a firewall rule may name a group of another product's
// project, and that is an absence here rather than an error.
func projectSecurityGroup(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitSecurityGroup]) (*mqlStackitSecurityGroup, error) {
	if id == "" {
		return markNull(field)
	}
	groups, err := conn(runtime).SecurityGroups(bgctx())
	if err != nil {
		if isAccessDenied(err) {
			return nil, refusal(err)
		}
		return nil, err
	}
	sg, ok := groups[id]
	if !ok {
		return markNull(field)
	}
	res, err := buildSecurityGroup(runtime, &sg)
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecurityGroup), nil
}

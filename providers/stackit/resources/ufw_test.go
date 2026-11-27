// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	ufw "github.com/stackitcloud/stackit-sdk-go/services/ufw/v1api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func ufwRuleAt(offset *int32) ufw.RuleResponse {
	return ufw.RuleResponse{Product: "iaas", InstanceId: "i", Offset: offset}
}

func i32(v int32) *int32 { return &v }

func TestUfwNextCursor(t *testing.T) {
	// Synthetic: page shapes for the offset-cursor walk; no live account was checked.
	t.Run("empty page ends the walk", func(t *testing.T) {
		_, _, more := ufwNextCursor(nil, nil)
		assert.False(t, more)
	})
	t.Run("last rule without offset ends the walk", func(t *testing.T) {
		_, _, more := ufwNextCursor(nil, []ufw.RuleResponse{ufwRuleAt(i32(0)), ufwRuleAt(nil)})
		assert.False(t, more)
	})
	t.Run("advancing page continues after its last offset", func(t *testing.T) {
		cursor, last, more := ufwNextCursor(i32(3), []ufw.RuleResponse{ufwRuleAt(i32(4)), ufwRuleAt(i32(7))})
		assert.True(t, more)
		assert.Equal(t, "7", cursor)
		assert.Equal(t, int32(7), *last)
	})
	t.Run("page that does not move ends the walk", func(t *testing.T) {
		_, _, more := ufwNextCursor(i32(7), []ufw.RuleResponse{ufwRuleAt(i32(0)), ufwRuleAt(i32(7))})
		assert.False(t, more)
	})
}

func TestUfwPageAdvances(t *testing.T) {
	// Synthetic: a service that ignores the cursor repeats the first page; no live account was checked.
	assert.True(t, ufwPageAdvances(nil, []ufw.RuleResponse{ufwRuleAt(i32(0))}), "first page")
	assert.False(t, ufwPageAdvances(i32(1), []ufw.RuleResponse{ufwRuleAt(i32(0)), ufwRuleAt(i32(1))}), "repeated page")
	assert.True(t, ufwPageAdvances(i32(1), []ufw.RuleResponse{ufwRuleAt(i32(2))}), "next page")
}

func TestUfwRuleKey(t *testing.T) {
	// Synthetic: rule identities; no live account was checked.
	ref := "sg-rule-1"
	withRef := ufw.RuleResponse{Product: "iaas", InstanceId: "sg-1", RefId: &ref, SourceIP: "0.0.0.0/0"}
	assert.Equal(t, "stackit.ufw.rule/p/eu01/iaas/sg-1/sg-rule-1", ufwRuleKey("p", "eu01", &withRef))

	a := ufw.RuleResponse{Product: "postgresflex", InstanceId: "db-1", SourceIP: "10.0.0.0/8"}
	b := ufw.RuleResponse{Product: "postgresflex", InstanceId: "db-1", SourceIP: "0.0.0.0/0"}
	assert.NotEqual(t, ufwRuleKey("p", "eu01", &a), ufwRuleKey("p", "eu01", &b), "rules differing only in source collide")
	assert.NotEqual(t, ufwRuleKey("p", "eu01", &a), ufwRuleKey("p", "eu02", &a), "same rule in two regions collides")
	assert.Equal(t, ufwRuleKey("p", "eu01", &a), ufwRuleKey("p", "eu01", &a), "key is not stable")
}

const ufwRulesPath = "GET /v1/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/rules"

func TestUfwRules(t *testing.T) {
	sgPath := "GET /v2/projects/" + fakeProjectID + "/regions/" + fakeRegion + "/security-groups"
	// Synthetic: a database ACL entry open to the internet and a security
	// group rule, shaped after the SDK's RuleResponse model; no live account
	// was checked. The fake ignores the cursor, so it also stands in for a
	// service that repeats its first page.
	body := `{"rules":[` +
		`{"product":"postgresflex","instanceId":"db-1","instanceName":"orders","type":"ACL","sourceIP":"0.0.0.0/0",` +
		`"destination":"db-1","status":"Active","offset":0},` +
		`{"product":"iaas","instanceId":"sg-1","type":"SecurityRule","sourceIP":"10.0.0.0/8","destination":"sg-1",` +
		`"status":"Active","offset":1,"refId":"r-2","stateful":true,"securityGroupId":"sg-1","remoteSecurityGroupId":"sg-gone"}]}`

	runtime, api := fakeRuntime(t, map[string]fakeAnswer{
		ufwRulesPath: json200(body),
		sgPath:       json200(`{"items":[{"id":"sg-1","name":"web"}]}`),
	})
	ns, err := CreateResource(runtime, "stackit.ufw", map[string]*llx.RawData{})
	require.NoError(t, err)
	rules := ns.(*mqlStackitUfw).GetRules()
	require.NoError(t, rules.Error)
	require.Len(t, rules.Data, 2)
	assert.Equal(t, 2, api.count(ufwRulesPath), "the walk asks once more after a page, then stops on the repeat")

	acl := rules.Data[0].(*mqlStackitUfwRule)
	assert.Equal(t, "0.0.0.0/0", acl.SourceIp.Data)
	assert.Equal(t, "ACL", acl.Type.Data)
	assert.True(t, acl.GetStateful().IsNull(), "stateful must be null when not reported")
	sg := acl.GetSecurityGroup()
	require.NoError(t, sg.Error)
	assert.Nil(t, sg.Data)

	rule := rules.Data[1].(*mqlStackitUfwRule)
	assert.True(t, rule.GetStateful().Data)
	sg = rule.GetSecurityGroup()
	require.NoError(t, sg.Error)
	require.NotNil(t, sg.Data)
	assert.Equal(t, "sg-1", sg.Data.Id.Data)
	remote := rule.GetRemoteSecurityGroup()
	require.NoError(t, remote.Error)
	assert.Nil(t, remote.Data, "a group the project does not hold reads as null")
}

func TestUfwRulesNotOnboarded(t *testing.T) {
	// Synthetic: the service answers 404 for a project it does not know; no live account was checked.
	runtime, _ := fakeRuntime(t, map[string]fakeAnswer{ufwRulesPath: jsonStatus(http.StatusNotFound)})
	ns, err := CreateResource(runtime, "stackit.ufw", map[string]*llx.RawData{})
	require.NoError(t, err)
	rules := ns.(*mqlStackitUfw).GetRules()
	require.NoError(t, rules.Error)
	assert.Empty(t, rules.Data)
}

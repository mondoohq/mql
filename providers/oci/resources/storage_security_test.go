// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/bastion"
	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/stretchr/testify/assert"
)

func TestLifecycleRuleArgs(t *testing.T) {
	args := lifecycleRuleArgs(objectstorage.ObjectLifecycleRule{
		Name:             common.String("expire-logs"),
		Action:           common.String("DELETE"),
		Target:           common.String("previous-object-versions"),
		TimeAmount:       common.Int64(30),
		TimeUnit:         objectstorage.ObjectLifecycleRuleTimeUnitDays,
		IsEnabled:        common.Bool(true),
		ObjectNameFilter: &objectstorage.ObjectNameFilter{InclusionPrefixes: []string{"logs/"}},
	})
	assert.Equal(t, "DELETE", args["action"].Value)
	assert.Equal(t, int64(30), args["timeAmount"].Value)
	assert.Equal(t, "DAYS", args["timeUnit"].Value)
	assert.Equal(t, []any{"logs/"}, args["inclusionPrefixes"].Value)

	bare := lifecycleRuleArgs(objectstorage.ObjectLifecycleRule{Name: common.String("r")})
	assert.Equal(t, false, bare["isEnabled"].Value)
	assert.Equal(t, []any{}, bare["inclusionPrefixes"].Value, "no filter applies the rule to every object")
}

func TestBastionSessionArgs(t *testing.T) {
	ssh, inst := bastionSessionArgs(bastion.SessionSummary{
		Id: common.String("s1"),
		TargetResourceDetails: bastion.ManagedSshSessionTargetResourceDetails{
			TargetResourceId:                      common.String("ocid1.instance..i"),
			TargetResourcePrivateIpAddress:        common.String("10.0.0.5"),
			TargetResourcePort:                    common.Int(22),
			TargetResourceOperatingSystemUserName: common.String("opc"),
		},
	})
	assert.Equal(t, "MANAGED_SSH", ssh["sessionType"].Value)
	assert.Equal(t, "opc", ssh["targetUser"].Value)
	assert.Equal(t, int64(22), ssh["targetPort"].Value)
	assert.Equal(t, "ocid1.instance..i", inst)

	pf, inst := bastionSessionArgs(bastion.SessionSummary{
		Id: common.String("s2"),
		TargetResourceDetails: bastion.PortForwardingSessionTargetResourceDetails{
			TargetResourcePrivateIpAddress: common.String("10.0.0.9"),
			TargetResourcePort:             common.Int(5432),
		},
	})
	assert.Equal(t, "PORT_FORWARDING", pf["sessionType"].Value)
	assert.Equal(t, "", pf["targetUser"].Value)
	assert.Empty(t, inst, "a port forwarding session to an IP address has no instance")

	dyn, _ := bastionSessionArgs(bastion.SessionSummary{Id: common.String("s3"), TargetResourceDetails: bastion.DynamicPortForwardingSessionTargetResourceDetails{}})
	assert.Equal(t, "DYNAMIC_PORT_FORWARDING", dyn["sessionType"].Value)
	assert.Nil(t, dyn["targetPort"].Value)
}

func TestTargetRecipeIDs(t *testing.T) {
	detector, responder := targetRecipeIDs(&cloudguard.Target{
		TargetDetectorRecipes: []cloudguard.TargetDetectorRecipe{
			{Id: common.String("copy1"), DetectorRecipeId: common.String("recipe1")},
			{Id: common.String("copy2")},
		},
		TargetResponderRecipes: []cloudguard.TargetResponderRecipe{{Id: common.String("copy3"), ResponderRecipeId: common.String("recipe3")}},
	})
	assert.Equal(t, []string{"recipe1"}, detector, "the source recipe, not the target's copy")
	assert.Equal(t, []string{"recipe3"}, responder)
}

func TestOciServiceStatus(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, ociServiceStatus(fakeServiceError{status: http.StatusNotFound, code: "NotFound"}))
	assert.Equal(t, 0, ociServiceStatus(errors.New("timeout")), "a transport failure has no status")
	assert.Equal(t, 0, ociServiceStatus(nil))
}

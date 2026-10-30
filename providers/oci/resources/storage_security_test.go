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
		Name:             new("expire-logs"),
		Action:           new("DELETE"),
		Target:           new("previous-object-versions"),
		TimeAmount:       common.Int64(30),
		TimeUnit:         objectstorage.ObjectLifecycleRuleTimeUnitDays,
		IsEnabled:        new(true),
		ObjectNameFilter: &objectstorage.ObjectNameFilter{InclusionPrefixes: []string{"logs/"}},
	})
	assert.Equal(t, "DELETE", args["action"].Value)
	assert.Equal(t, int64(30), args["timeAmount"].Value)
	assert.Equal(t, "DAYS", args["timeUnit"].Value)
	assert.Equal(t, []any{"logs/"}, args["inclusionPrefixes"].Value)

	bare := lifecycleRuleArgs(objectstorage.ObjectLifecycleRule{Name: new("r")})
	assert.Equal(t, false, bare["isEnabled"].Value)
	assert.Equal(t, []any{}, bare["inclusionPrefixes"].Value, "no filter applies the rule to every object")
}

func TestBastionSessionArgs(t *testing.T) {
	ssh, inst := bastionSessionArgs(bastion.SessionSummary{
		Id: new("s1"),
		TargetResourceDetails: bastion.ManagedSshSessionTargetResourceDetails{
			TargetResourceId:                      new("ocid1.instance..i"),
			TargetResourcePrivateIpAddress:        new("10.0.0.5"),
			TargetResourcePort:                    new(22),
			TargetResourceOperatingSystemUserName: new("opc"),
		},
	})
	assert.Equal(t, "MANAGED_SSH", ssh["sessionType"].Value)
	assert.Equal(t, "opc", ssh["targetUser"].Value)
	assert.Equal(t, int64(22), ssh["targetPort"].Value)
	assert.Equal(t, "ocid1.instance..i", inst)

	pf, inst := bastionSessionArgs(bastion.SessionSummary{
		Id: new("s2"),
		TargetResourceDetails: bastion.PortForwardingSessionTargetResourceDetails{
			TargetResourcePrivateIpAddress: new("10.0.0.9"),
			TargetResourcePort:             new(5432),
		},
	})
	assert.Equal(t, "PORT_FORWARDING", pf["sessionType"].Value)
	assert.Equal(t, "", pf["targetUser"].Value)
	assert.Empty(t, inst, "a port forwarding session to an IP address has no instance")

	dyn, _ := bastionSessionArgs(bastion.SessionSummary{Id: new("s3"), TargetResourceDetails: bastion.DynamicPortForwardingSessionTargetResourceDetails{}})
	assert.Equal(t, "DYNAMIC_PORT_FORWARDING", dyn["sessionType"].Value)
	assert.Nil(t, dyn["targetPort"].Value)
}

func TestTargetRecipeIDs(t *testing.T) {
	detector, responder := targetRecipeIDs(&cloudguard.Target{
		TargetDetectorRecipes: []cloudguard.TargetDetectorRecipe{
			{Id: new("copy1"), DetectorRecipeId: new("recipe1")},
			{Id: new("copy2")},
		},
		TargetResponderRecipes: []cloudguard.TargetResponderRecipe{{Id: new("copy3"), ResponderRecipeId: new("recipe3")}},
	})
	assert.Equal(t, []string{"recipe1"}, detector, "the source recipe, not the target's copy")
	assert.Equal(t, []string{"recipe3"}, responder)
}

func TestOciServiceStatus(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, ociServiceStatus(fakeServiceError{status: http.StatusNotFound, code: "NotFound"}))
	assert.Equal(t, 0, ociServiceStatus(errors.New("timeout")), "a transport failure has no status")
	assert.Equal(t, 0, ociServiceStatus(nil))
}

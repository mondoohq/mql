// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
	"strconv"
)

// CheckTypeApproval is the type id of an Approval check, the same in every
// organization. Azure DevOps sends it in upper case, so compare it without
// regard to letter case.
const CheckTypeApproval = "8c6f20a7-a545-4486-9777-f762fafe0d4d"

// Environment is a pipeline environment of a project, such as production.
type Environment struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CheckConfiguration is a check that guards deployments to an environment. The
// settings come back only when the request asks for them.
type CheckConfiguration struct {
	ID       int64          `json:"id"`
	Type     CheckType      `json:"type"`
	Settings map[string]any `json:"settings"`
}

// CheckType names the kind of a check, for example Approval or Task Check.
type CheckType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RequesterCannotBeApprover reports whether the settings keep the person who ran
// the pipeline from approving it. A check of another type has no such setting.
func (c CheckConfiguration) RequesterCannotBeApprover() bool {
	v, _ := c.Settings["requesterCannotBeApprover"].(bool)
	return v
}

// MinRequiredApprovers is the number of approvals an approval check needs.
// Azure DevOps stores zero for "every approver must approve"; that is reported
// as the number of approvers, so a policy can compare it with a minimum. A check
// of another type has no approvers and reports zero.
func (c CheckConfiguration) MinRequiredApprovers() int64 {
	v, _ := c.Settings["minRequiredApprovers"].(float64)
	if v > 0 {
		return int64(v)
	}
	// Azure DevOps stores 0 for "all approvers must approve", the default.
	// Each listed approver, user or group, gives one approval.
	approvers, _ := c.Settings["approvers"].([]any)
	return int64(len(approvers))
}

// Environments lists the pipeline environments of a project. The read happens
// once per project for the life of the client.
func (c *Client) Environments(ctx context.Context, project string) ([]Environment, error) {
	return c.environments.get(project, func() ([]Environment, error) {
		return listAll[Environment](ctx, c, request{
			segments:   []string{project, "_apis", "distributedtask", "environments"},
			apiVersion: PreviewAPIVersion,
		}, 0)
	})
}

// EnvironmentChecks lists the checks of one environment, with their settings.
// The read happens once per environment for the life of the client.
func (c *Client) EnvironmentChecks(ctx context.Context, project string, envID int64) ([]CheckConfiguration, error) {
	id := strconv.FormatInt(envID, 10)
	return c.checks.get(project+"/"+id, func() ([]CheckConfiguration, error) {
		return listAll[CheckConfiguration](ctx, c, request{
			segments: []string{project, "_apis", "pipelines", "checks", "configurations"},
			query: url.Values{
				"resourceType": {"environment"},
				"resourceId":   {id},
				"$expand":      {"settings"},
			},
			apiVersion: PreviewAPIVersion,
		}, 0)
	})
}

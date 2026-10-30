// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// VCN flow logs are modeled in OCI as `logging.Log` resources whose
// configuration source has `service = "flowlogs"` and whose `resource` field
// points at the VCN, subnet, or VNIC the flow is captured for. This file
// wires a filtering view of the existing log catalogue onto the VCN and
// Subnet resources so policies can query flow-log coverage without reaching
// into the raw `configuration` dict.

// flowLogs returns the subset of oci.logging.log resources whose source is
// the flowlogs service and whose resource OCID matches this VCN.
func (o *mqlOciNetworkVcn) flowLogs() ([]any, error) {
	return collectFlowLogsForResource(o.MqlRuntime, o.Id.Data)
}

// flowLogs returns the subset of oci.logging.log resources whose source is
// the flowlogs service and whose resource OCID matches this subnet.
func (o *mqlOciNetworkSubnet) flowLogs() ([]any, error) {
	return collectFlowLogsForResource(o.MqlRuntime, o.Id.Data)
}

// collectFlowLogsForResource walks every log group and returns flow logs
// whose source resource OCID matches the given id. Log groups and their
// logs are cached by the runtime, so repeated calls on adjacent resources
// don't re-hit the API.
func collectFlowLogsForResource(runtime *plugin.Runtime, resourceID string) ([]any, error) {
	if resourceID == "" {
		return []any{}, nil
	}

	obj, err := CreateResource(runtime, "oci.logging", nil)
	if err != nil {
		return nil, err
	}
	logs := obj.(*mqlOciLogging)

	rawGroups := logs.GetLogGroups()
	if rawGroups.Error != nil {
		return nil, rawGroups.Error
	}

	res := []any{}
	for _, rawGroup := range rawGroups.Data {
		group := rawGroup.(*mqlOciLoggingLogGroup)
		rawLogs := group.GetLogs()
		if rawLogs.Error != nil {
			return nil, rawLogs.Error
		}
		for _, rawLog := range rawLogs.Data {
			log := rawLog.(*mqlOciLoggingLog)
			if log.SourceService.Data != "flowlogs" {
				continue
			}
			if log.SourceResource.Data != resourceID {
				continue
			}
			res = append(res, log)
		}
	}

	return res, nil
}

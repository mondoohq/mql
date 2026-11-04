// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jenkins/connection"
)

// initJenkinsSecurity assembles the controller-wide security posture
// singleton from a single deep fetch against the Jenkins root API tree. It is
// queried directly as `jenkins.security`.
func initJenkinsSecurity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.JenkinsConnection)

	// Pointers so that a field the controller does not export stays null: a
	// Jenkins tree query drops what it cannot answer instead of failing, and
	// a value type would report that silence as a real setting.
	var resp struct {
		UseSecurity    *bool  `json:"useSecurity"`
		UseCrumbs      *bool  `json:"useCrumbs"`
		SlaveAgentPort *int64 `json:"slaveAgentPort"`
	}

	_, err := conn.Client().Requester.GetJSON(context.Background(), "/", &resp, map[string]string{
		"tree": "useSecurity,useCrumbs,slaveAgentPort",
	})
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(conn.BaseUrl() + "/security")
	args["securityEnabled"] = llx.BoolDataPtr(resp.UseSecurity)
	args["csrfProtectionEnabled"] = llx.BoolDataPtr(resp.UseCrumbs)
	args["slaveAgentPort"] = llx.IntDataPtr(resp.SlaveAgentPort)

	return args, nil, nil
}

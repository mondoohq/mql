// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/jenkins/connection"
	"go.mondoo.com/mql/v13/types"
)

// unsecuredAuthorizationStrategyClass is the legacy authorization strategy
// that grants every user, including anonymous ones, full administrative
// rights.
const unsecuredAuthorizationStrategyClass = "hudson.security.AuthorizationStrategy$Unsecured"

// initJenkinsSecurity assembles the controller-wide security posture
// singleton from a single deep fetch against the Jenkins root API tree, plus
// the agent-to-controller access control state. It is queried directly as
// `jenkins.security`.
func initJenkinsSecurity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.JenkinsConnection)

	var resp struct {
		UseSecurity           bool     `json:"useSecurity"`
		UseCrumbs             bool     `json:"useCrumbs"`
		SlaveAgentPort        int64    `json:"slaveAgentPort"`
		AgentProtocols        []string `json:"agentProtocols"`
		AuthorizationStrategy struct {
			Class string `json:"_class"`
		} `json:"authorizationStrategy"`
		SecurityRealm struct {
			Class string `json:"_class"`
		} `json:"securityRealm"`
		MarkupFormatter struct {
			Class string `json:"_class"`
		} `json:"markupFormatter"`
	}

	_, err := conn.Client().Requester.GetJSON(context.Background(), "/", &resp, map[string]string{
		"tree": "useSecurity,useCrumbs,slaveAgentPort,agentProtocols," +
			"authorizationStrategy[_class],securityRealm[_class],markupFormatter[_class]",
	})
	if err != nil {
		return nil, nil, err
	}

	unsecuredStrategy := resp.AuthorizationStrategy.Class == unsecuredAuthorizationStrategyClass
	allowsAnonymousAdmin := !resp.UseSecurity || unsecuredStrategy

	agentControlEnabled, err := fetchAgentToControllerAccessControl(conn)
	if err != nil {
		// Not every Jenkins deployment exposes this administrative monitor
		// over the remote API (it depends on core version and installed
		// plugins). Log and fall back to the secure Jenkins default
		// (enabled since Jenkins 2.319) rather than failing the whole query.
		log.Debug().Err(err).Msg("jenkins> unable to determine agent-to-controller access control state, assuming enabled")
		agentControlEnabled = true
	}

	protocols := make([]any, 0, len(resp.AgentProtocols))
	for _, p := range resp.AgentProtocols {
		protocols = append(protocols, p)
	}

	args["__id"] = llx.StringData(conn.BaseUrl() + "/security")
	args["authorizationStrategy"] = llx.StringData(resp.AuthorizationStrategy.Class)
	args["securityRealm"] = llx.StringData(resp.SecurityRealm.Class)
	args["securityEnabled"] = llx.BoolData(resp.UseSecurity)
	args["csrfProtectionEnabled"] = llx.BoolData(resp.UseCrumbs)
	args["allowsAnonymousAdmin"] = llx.BoolData(allowsAnonymousAdmin)
	args["agentToControllerAccessControlEnabled"] = llx.BoolData(agentControlEnabled)
	args["agentProtocols"] = llx.ArrayData(protocols, types.String)
	args["slaveAgentPort"] = llx.IntData(resp.SlaveAgentPort)
	args["markupFormatter"] = llx.StringData(resp.MarkupFormatter.Class)

	return args, nil, nil
}

// fetchAgentToControllerAccessControl reads the state of the Agent Access
// Control subsystem (the "kill switch" for agent-to-controller commands)
// from its administrative monitor. This is a best-effort read: the monitor
// is not part of the stable, universally documented Remote Access API
// surface, so callers should treat a failure as "unknown" rather than fatal.
func fetchAgentToControllerAccessControl(conn *connection.JenkinsConnection) (bool, error) {
	var resp struct {
		MasterKillSwitch bool `json:"masterKillSwitch"`
	}
	_, err := conn.Client().Requester.GetJSON(context.Background(),
		"/administrativeMonitor/slaveToMasterAccessControl", &resp, map[string]string{
			"tree": "masterKillSwitch",
		})
	if err != nil {
		return false, err
	}
	// masterKillSwitch true means access control is DISABLED (the kill
	// switch has been thrown), so the enabled state is its negation.
	return !resp.MasterKillSwitch, nil
}

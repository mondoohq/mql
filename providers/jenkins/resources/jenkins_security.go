// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers/jenkins/connection"
	"go.mondoo.com/mql/v13/types"
)

// unsecuredAuthorizationStrategyClass is the legacy authorization strategy
// that grants every user, including anonymous ones, full administrative
// rights.
const unsecuredAuthorizationStrategyClass = "hudson.security.AuthorizationStrategy$Unsecured"

// security assembles the controller-wide security posture singleton from a
// single deep fetch against the Jenkins root API tree, plus the
// agent-to-controller access control state.
func (r *mqlJenkins) security() (*mqlJenkinsSecurity, error) {
	conn := r.conn()

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
		return nil, err
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

	res, err := CreateResource(r.MqlRuntime, "jenkins.security", map[string]*llx.RawData{
		"__id":                                  llx.StringData(conn.BaseUrl() + "/security"),
		"authorizationStrategy":                 llx.StringData(resp.AuthorizationStrategy.Class),
		"securityRealm":                         llx.StringData(resp.SecurityRealm.Class),
		"securityEnabled":                       llx.BoolData(resp.UseSecurity),
		"csrfProtectionEnabled":                 llx.BoolData(resp.UseCrumbs),
		"allowsAnonymousAdmin":                  llx.BoolData(allowsAnonymousAdmin),
		"agentToControllerAccessControlEnabled": llx.BoolData(agentControlEnabled),
		"agentProtocols":                        llx.ArrayData(protocols, types.String),
		"slaveAgentPort":                        llx.IntData(resp.SlaveAgentPort),
		"markupFormatter":                       llx.StringData(resp.MarkupFormatter.Class),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJenkinsSecurity), nil
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

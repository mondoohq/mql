// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jenkins/connection"
	"go.mondoo.com/mql/types"
)

// builtInNodeName is the internal (often empty or "master"/"(built-in)")
// node name Jenkins uses for the controller's own executor, depending on
// core version.
const builtInNodeName = ""

// builtInNodeDisplayName is the display name surfaced for the controller
// node regardless of which internal name the connected Jenkins core uses.
const builtInNodeDisplayName = "Built-In Node"

// jenkinsNodeData is the shape fetched from the Jenkins computer collection,
// scoped with a tree query to avoid the executor and monitor-data payload
// the default endpoint returns.
type jenkinsNodeData struct {
	Class              string `json:"_class"`
	DisplayName        string `json:"displayName"`
	Description        string `json:"description"`
	Offline            *bool  `json:"offline"`
	TemporarilyOffline *bool  `json:"temporarilyOffline"`
	OfflineCauseReason string `json:"offlineCauseReason"`
	NumExecutors       *int64 `json:"numExecutors"`
	AssignedLabels     []struct {
		Name string `json:"name"`
	} `json:"assignedLabels"`
}

// isControllerNode reports whether a fetched node identifies the built-in
// controller node rather than an agent. The computer's Java class is the
// version-independent signal and is authoritative when present. The name
// list is only a fallback for a response that carries no class, because an
// agent is free to be named "master": treating such an agent as the
// controller would also collide with the controller's cache key and drop
// the agent's real data from the node list.
func isControllerNode(class, displayName string) bool {
	if class != "" {
		return strings.Contains(class, "MasterComputer")
	}
	switch displayName {
	case builtInNodeName, "master", "(built-in)", builtInNodeDisplayName:
		return true
	default:
		return false
	}
}

// nodeDisplayName normalizes a fetched node's display name, always
// surfacing the controller under the same name regardless of the internal
// name reported by the connected Jenkins core version.
func nodeDisplayName(n jenkinsNodeData) string {
	if isControllerNode(n.Class, n.DisplayName) {
		return builtInNodeDisplayName
	}
	return n.DisplayName
}

// nodes lists every build agent and the built-in controller node in a single
// deep fetch against the computer collection.
func (r *mqlJenkins) nodes() ([]any, error) {
	conn := r.conn()
	computers, err := fetchNodes(conn)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(computers))
	for _, c := range computers {
		res, err := newMqlJenkinsNode(r.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// fetchNodes retrieves every node (agents plus the built-in controller node)
// in a single deep fetch. The result is memoized on the connection so that
// resolving N job.node references does not trigger N /computer reads.
func fetchNodes(conn *connection.JenkinsConnection) ([]jenkinsNodeData, error) {
	v, err := conn.CachedNodes(func() (any, error) {
		var resp struct {
			Computer []jenkinsNodeData `json:"computer"`
		}
		_, err := conn.Client().Requester.GetJSON(context.Background(), "/computer", &resp, map[string]string{
			"tree": "computer[_class,displayName,description,offline,temporarilyOffline," +
				"offlineCauseReason,numExecutors,assignedLabels[name]]",
		})
		if err != nil {
			return nil, err
		}
		return resp.Computer, nil
	})
	if err != nil {
		return nil, err
	}
	nodes, ok := v.([]jenkinsNodeData)
	if !ok {
		return nil, fmt.Errorf("unexpected cached nodes type %T", v)
	}
	return nodes, nil
}

// newMqlJenkinsNode maps a single node's fetched data to its MQL resource.
// The node has no user-meaningful id field of its own (its display name is
// exposed as `name` directly), so the cache key is passed via `__id`.
func newMqlJenkinsNode(runtime *plugin.Runtime, c jenkinsNodeData) (plugin.Resource, error) {
	name := nodeDisplayName(c)
	isController := isControllerNode(c.Class, c.DisplayName)

	labels := make([]any, 0, len(c.AssignedLabels))
	for _, l := range c.AssignedLabels {
		labels = append(labels, l.Name)
	}

	res, err := CreateResource(runtime, "jenkins.node", map[string]*llx.RawData{
		"__id":               llx.StringData("jenkins.node/" + name),
		"name":               llx.StringData(name),
		"description":        llx.StringData(c.Description),
		"isController":       llx.BoolData(isController),
		"offline":            llx.BoolDataPtr(c.Offline),
		"temporarilyOffline": llx.BoolDataPtr(c.TemporarilyOffline),
		"offlineCauseReason": llx.StringData(c.OfflineCauseReason),
		"numExecutors":       llx.IntDataPtr(c.NumExecutors),
		"labels":             llx.ArrayData(labels, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// initJenkinsNode resolves a single node by name on demand, for the typed
// jenkins.job.node reference. Accepts either the normalized "Built-In Node"
// display name or the raw internal name (e.g. "", "master") a build's
// builtOn field may report.
func initJenkinsNode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameArg, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("jenkins.node requires a name")
	}
	name, ok := nameArg.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("jenkins.node requires a valid name")
	}

	conn := runtime.Connection.(*connection.JenkinsConnection)
	computers, err := fetchNodes(conn)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range computers {
		if c.DisplayName == name || nodeDisplayName(c) == name {
			res, err := newMqlJenkinsNode(runtime, c)
			if err != nil {
				return nil, nil, err
			}
			return args, res, nil
		}
	}

	return nil, nil, fmt.Errorf("jenkins.node with name %q not found", name)
}

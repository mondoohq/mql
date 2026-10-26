// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/n8n/connection"
	"go.mondoo.com/mql/types"
)

type mqlN8nWorkflowInternal struct {
	tagIDs          []string
	credentialIDs   []string
	callerIDs       []string
	errorWorkflowID string
}

type mqlN8nWorkflowNodeInternal struct {
	credentialIDs []string
}

func (r *mqlN8n) workflows() ([]any, error) {
	workflows, err := n8nConnection(r.MqlRuntime).Client().Workflows(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(workflows))
	for _, w := range workflows {
		res, err := newWorkflow(r.MqlRuntime, w)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newWorkflow(runtime *plugin.Runtime, w connection.Workflow) (*mqlN8nWorkflow, error) {
	nodes := make([]any, 0, len(w.Nodes))
	for _, n := range w.Nodes {
		node, err := newWorkflowNode(runtime, w.ID, n)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	s := w.Settings
	res, err := CreateResource(runtime, ResourceN8nWorkflow, map[string]*llx.RawData{
		"id":                       llx.StringData(w.ID),
		"name":                     llx.StringData(w.Name),
		"active":                   llx.BoolData(w.Active()),
		"isArchived":               llx.BoolData(w.IsArchived),
		"versionId":                llx.StringData(w.VersionID),
		"triggerCount":             llx.IntData(w.TriggerCount),
		"createdAt":                llx.TimeData(w.CreatedAt),
		"updatedAt":                llx.TimeData(w.UpdatedAt),
		"nodes":                    llx.ArrayData(nodes, types.Resource(ResourceN8nWorkflowNode)),
		"callerPolicy":             optString(s.CallerPolicy),
		"executionOrder":           optString(s.ExecutionOrder),
		"executionTimeout":         llx.IntDataPtr(s.ExecutionTimeout),
		"timezone":                 optString(s.Timezone),
		"saveDataErrorExecution":   optString(s.SaveDataErrorExecution),
		"saveDataSuccessExecution": optString(s.SaveDataSuccessExecution),
		"redactionPolicy":          optString(s.RedactionPolicy),
		"availableInMcp":           llx.BoolDataPtr(s.AvailableInMCP),
	})
	if err != nil {
		return nil, err
	}
	wf := res.(*mqlN8nWorkflow)
	wf.tagIDs = w.TagIDs
	wf.credentialIDs = workflowCredentialIDs(w.Nodes)
	wf.callerIDs = s.CallerIDs
	wf.errorWorkflowID = s.ErrorWorkflowID
	return wf, nil
}

// workflowCredentialIDs is the sorted set of credentials the workflow's
// nodes reference.
func workflowCredentialIDs(nodes []connection.Node) []string {
	seen := map[string]struct{}{}
	var ids []string
	for _, n := range nodes {
		for _, id := range n.CredentialIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func initN8nWorkflow(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return lookupInit(args, ResourceN8nWorkflow, func() (map[string]*mqlN8nWorkflow, error) {
		return workflowsByID(runtime)
	})
}

func (r *mqlN8nWorkflow) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlN8nWorkflow) tags() ([]any, error) {
	index, err := tagsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.tagIDs), nil
}

func (r *mqlN8nWorkflow) credentials() ([]any, error) {
	index, err := credentialsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.credentialIDs), nil
}

func (r *mqlN8nWorkflow) callers() ([]any, error) {
	index, err := workflowsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.callerIDs), nil
}

func (r *mqlN8nWorkflow) errorWorkflow() (*mqlN8nWorkflow, error) {
	if r.errorWorkflowID == "" {
		r.ErrorWorkflow.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	index, err := workflowsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	wf, ok := index[r.errorWorkflowID]
	if !ok {
		r.ErrorWorkflow.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return wf, nil
}

func newWorkflowNode(runtime *plugin.Runtime, workflowID string, n connection.Node) (*mqlN8nWorkflowNode, error) {
	// Node IDs are unique within a workflow and names are too; older
	// workflows can carry nodes without an ID, so the name stands in.
	key := n.ID
	if key == "" {
		key = n.Name
	}
	res, err := CreateResource(runtime, ResourceN8nWorkflowNode, map[string]*llx.RawData{
		"__id":                   llx.StringData(workflowID + "/" + key),
		"id":                     llx.StringData(n.ID),
		"name":                   llx.StringData(n.Name),
		"type":                   llx.StringData(n.Type),
		"typeVersion":            llx.FloatData(n.TypeVersion),
		"disabled":               llx.BoolData(n.Disabled),
		"authentication":         optString(n.Authentication),
		"path":                   optString(n.Path),
		"public":                 llx.BoolDataPtr(n.Public),
		"allowedOrigins":         optStringArray(n.AllowedOrigins),
		"ipAllowlist":            optStringArray(n.IPAllowlist),
		"allowUnauthorizedCerts": llx.BoolDataPtr(n.AllowUnauthorizedCerts),
		"requestHost":            optString(n.RequestHost),
		"webhookId":              optString(n.WebhookID),
		"onError":                optString(n.OnError),
		"retryOnFail":            llx.BoolData(n.RetryOnFail),
	})
	if err != nil {
		return nil, err
	}
	node := res.(*mqlN8nWorkflowNode)
	node.credentialIDs = n.CredentialIDs
	return node, nil
}

func (r *mqlN8nWorkflowNode) credentials() ([]any, error) {
	index, err := credentialsByID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return pick(index, r.credentialIDs), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuditLocationIDs(t *testing.T) {
	// Measured: locations from the nodes and credentials reports of a local
	// n8n 2.44.6, 2026-10-25. Two nodes of one workflow name it once.
	workflows, credentials := auditLocationIDs([]map[string]any{
		{"kind": "node", "nodeId": "11111111-2222-4333-8444-555555555552", "nodeName": "HTTP Request", "nodeType": "n8n-nodes-base.httpRequest", "workflowId": "x31EzXkkNa3xwaHt", "workflowName": "mql-verify-http"},
		{"kind": "node", "nodeId": "11111111-2222-4333-8444-555555555553", "nodeName": "Code", "nodeType": "n8n-nodes-base.code", "workflowId": "x31EzXkkNa3xwaHt", "workflowName": "mql-verify-http"},
		{"kind": "credential", "id": "Y2ILtunxAFKvFQyE", "name": "mql-verify-httpheader"},
		{"kind": "credential", "id": "CaLU2QV6Pt9NggSt", "name": "mql-verify-unused"},
		{"kind": "community", "nodeType": "n8n-nodes-text-manipulation.textManipulation", "packageUrl": "https://www.npmjs.com/package/n8n-nodes-text-manipulation"},
	})
	assert.Equal(t, []string{"x31EzXkkNa3xwaHt"}, workflows)
	assert.Equal(t, []string{"CaLU2QV6Pt9NggSt", "Y2ILtunxAFKvFQyE"}, credentials)
}

func TestAuditLocationIDsIgnoresOtherKinds(t *testing.T) {
	// Synthetic: a custom node location carries neither id, and an id key
	// on a node location is not a credential.
	workflows, credentials := auditLocationIDs([]map[string]any{
		{"kind": "custom", "nodeType": "CUSTOM.myNode", "filePath": "/home/node/.n8n/custom/MyNode.node.js"},
		{"kind": "node", "id": "not-a-credential", "workflowId": ""},
	})
	assert.Empty(t, workflows)
	assert.Empty(t, credentials)
}

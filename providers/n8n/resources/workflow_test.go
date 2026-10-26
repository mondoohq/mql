// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/n8n/connection"
)

func TestWorkflowCredentialIDs(t *testing.T) {
	// Synthetic: two nodes sharing a credential; the local instance had one
	// credentialed node.
	ids := workflowCredentialIDs([]connection.Node{
		{Name: "Get issues", CredentialIDs: []string{"jira", "slack"}},
		{Name: "Trigger"},
		{Name: "Post", CredentialIDs: []string{"slack"}},
	})
	assert.Equal(t, []string{"jira", "slack"}, ids)

	assert.Empty(t, workflowCredentialIDs(nil))
}

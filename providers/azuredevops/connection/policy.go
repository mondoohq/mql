// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"strings"
)

// Type ids of the branch policies the provider reads. Azure DevOps uses the
// same ids in every organization.
const (
	PolicyTypeMinimumReviewers  = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
	PolicyTypeRequiredReviewers = "fd2167ab-b0be-447a-8ec8-39368250530e"
	PolicyTypeCommentResolution = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
	PolicyTypeBuild             = "0609b952-1397-4640-95ec-e00a01b2c241"
	PolicyTypeStatus            = "cbdc66da-9728-4af8-aada-9a5a32e4a226"
)

// PolicyConfiguration is one entry of GET /{project}/_apis/policy/configurations.
type PolicyConfiguration struct {
	ID         int64          `json:"id"`
	IsEnabled  bool           `json:"isEnabled"`
	IsBlocking bool           `json:"isBlocking"`
	IsDeleted  bool           `json:"isDeleted"`
	Type       PolicyType     `json:"type"`
	Settings   PolicySettings `json:"settings"`
}

// PolicyType names the kind of a policy.
type PolicyType struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// PolicySettings holds the settings of a policy. Each policy type has its own
// settings, so they are kept whole in All, and the scope that every branch
// policy carries is decoded into Scope.
type PolicySettings struct {
	Scope []PolicyScope
	All   map[string]any
}

// UnmarshalJSON decodes the scope and keeps every setting.
func (s *PolicySettings) UnmarshalJSON(data []byte) error {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	var scoped struct {
		Scope []PolicyScope `json:"scope"`
	}
	if err := json.Unmarshal(data, &scoped); err != nil {
		return err
	}
	s.All = all
	s.Scope = scoped.Scope
	return nil
}

// PolicyScope is one place a policy applies. An empty RepositoryID means every
// repository of the project.
type PolicyScope struct {
	RepositoryID string `json:"repositoryId"`
	RefName      string `json:"refName"`
	// MatchKind is Exact, Prefix or DefaultBranch.
	MatchKind string `json:"matchKind"`
}

// Covers reports whether the scope entry applies to the branch refName of the
// repository repoID, whose default branch is defaultBranch. Azure DevOps
// compares repository ids and branch names without regard to letter case. An
// Exact or Prefix entry with no refName covers no branch.
func (s PolicyScope) Covers(repoID, refName, defaultBranch string) bool {
	if s.RepositoryID != "" && !strings.EqualFold(s.RepositoryID, repoID) {
		return false
	}
	switch strings.ToLower(s.MatchKind) {
	case "defaultbranch":
		return defaultBranch != "" && strings.EqualFold(refName, defaultBranch)
	case "prefix":
		return s.RefName != "" && len(refName) >= len(s.RefName) && strings.EqualFold(refName[:len(s.RefName)], s.RefName)
	default:
		return s.RefName != "" && strings.EqualFold(refName, s.RefName)
	}
}

// AppliesToRepository reports whether any scope entry names the repository or
// every repository of the project.
func (p PolicyConfiguration) AppliesToRepository(repoID string) bool {
	for _, s := range p.Settings.Scope {
		if s.RepositoryID == "" || strings.EqualFold(s.RepositoryID, repoID) {
			return true
		}
	}
	return false
}

// Covers reports whether any scope entry applies to the branch.
func (p PolicyConfiguration) Covers(repoID, refName, defaultBranch string) bool {
	for _, s := range p.Settings.Scope {
		if s.Covers(repoID, refName, defaultBranch) {
			return true
		}
	}
	return false
}

// Enforced reports a policy that is on, blocks the merge when it fails, and was
// not deleted. Only an enforced policy protects a branch.
func (p PolicyConfiguration) Enforced() bool {
	return p.IsEnabled && p.IsBlocking && !p.IsDeleted
}

// PolicyConfigurations lists the policies of a project. Every repository and
// branch of the project reads the same list, so it is fetched once per client.
func (c *Client) PolicyConfigurations(ctx context.Context, project string) ([]PolicyConfiguration, error) {
	return c.policies.get(project, func() ([]PolicyConfiguration, error) {
		return listAll[PolicyConfiguration](ctx, c, request{
			segments: []string{project, "_apis", "policy", "configurations"},
		}, 0)
	})
}

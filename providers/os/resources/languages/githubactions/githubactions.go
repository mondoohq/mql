// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package githubactions

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/sbom"
)

// NewPackageUrl creates a GitHub Actions package URL.
// See https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/github-definition.md
func NewPackageUrl(owner, repo, ref string) string {
	return packageurl.NewPackageURL(
		"github",
		owner,
		repo,
		ref,
		nil,
		"").String()
}

// NewEvidenceList converts a list of file paths to evidence entries.
func NewEvidenceList(evidence []string) []*sbom.Evidence {
	evidenceList := make([]*sbom.Evidence, len(evidence))
	for i, e := range evidence {
		evidenceList[i] = &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: e,
		}
	}
	return evidenceList
}

// ActionRef represents a parsed GitHub Actions `uses` reference.
type ActionRef struct {
	// Owner is the GitHub organization or user (e.g., "actions").
	Owner string
	// Repo is the repository name (e.g., "checkout").
	Repo string
	// Path is the optional sub-path within the repo (e.g., "init" in "github/codeql-action/init@v3").
	Path string
	// Ref is the version tag, branch, or commit SHA (e.g., "v4").
	Ref string
}

// Name returns the display name as "owner/repo" (or "owner/repo/path" if path is set).
func (a ActionRef) Name() string {
	if a.Path != "" {
		return a.Owner + "/" + a.Repo + "/" + a.Path
	}
	return a.Owner + "/" + a.Repo
}

// ParseUses parses a GitHub Actions `uses` directive into an ActionRef.
// Returns nil for local actions (./), Docker actions (docker://), or invalid formats.
func ParseUses(uses string) *ActionRef {
	uses = strings.TrimSpace(uses)

	// Skip local actions
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		return nil
	}

	// Skip Docker actions
	if strings.HasPrefix(uses, "docker://") {
		return nil
	}

	// Split on @ to get action and ref
	action, ref, ok := strings.Cut(uses, "@")
	if !ok || ref == "" {
		return nil
	}

	// Split action into owner/repo[/path]
	parts := strings.SplitN(action, "/", 3)
	if len(parts) < 2 {
		return nil
	}

	result := &ActionRef{
		Owner: parts[0],
		Repo:  parts[1],
		Ref:   ref,
	}

	if len(parts) == 3 {
		result.Path = parts[2]
	}

	return result
}

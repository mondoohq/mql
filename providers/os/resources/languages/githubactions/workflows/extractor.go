// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package workflows

import (
	"io"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/githubactions"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*workflow)(nil)
)

// Extractor parses GitHub Actions workflow YAML files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "github-actions-workflow"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var wf workflow

	if filename != "" {
		wf.evidence = append(wf.evidence, filename)
	}

	if err := yaml.NewDecoder(r).Decode(&wf); err != nil {
		return nil, err
	}

	if len(wf.Jobs) == 0 {
		log.Debug().Str("file", filename).Msg("workflow has no jobs (may not be a workflow file)")
	}

	return &wf, nil
}

// Root returns nil — workflows don't have a root package.
func (w *workflow) Root() *languages.Package {
	return nil
}

// Direct returns nil — all actions are treated equally.
func (w *workflow) Direct() languages.Packages {
	return nil
}

// Transitive returns all unique action and reusable workflow references found
// in the workflow.
func (w *workflow) Transitive() languages.Packages {
	seen := make(map[string]bool)
	var packages languages.Packages

	for _, job := range w.Jobs {
		// a job-level `uses` calls a reusable workflow, which runs the
		// called repository's code just like a step-level action
		uses := make([]string, 0, len(job.Steps)+1)
		if job.Uses != "" {
			uses = append(uses, job.Uses)
		}
		for _, step := range job.Steps {
			if step.Uses != "" {
				uses = append(uses, step.Uses)
			}
		}

		for _, u := range uses {
			ref := githubactions.ParseUses(u)
			if ref == nil {
				continue
			}

			// Deduplicate by full uses string (owner/repo@ref)
			key := ref.Name() + "@" + ref.Ref
			if seen[key] {
				continue
			}
			seen[key] = true

			packages = append(packages, &languages.Package{
				Name:         ref.Name(),
				Version:      ref.Ref,
				Purl:         githubactions.NewPackageUrl(ref.Owner, ref.Repo, ref.Ref),
				EvidenceList: githubactions.NewEvidenceList(w.evidence),
			})
		}
	}

	return packages
}

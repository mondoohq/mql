// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// commitSHA matches a full 40-character git commit SHA, the only action
// reference that pins the code a step will run. Short SHAs are excluded
// deliberately: GitHub resolves them, but they are ambiguous by construction.
var commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// imageDigest matches the digest form of a container reference, which pins a
// container action the same way a commit SHA pins a repository action.
var imageDigest = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)

// workflowConfig returns the workflow's parsed YAML as a map. It reports a nil
// map when the workflow file could not be read or did not parse into an
// object, which callers treat as "nothing to report" rather than an error.
func (g *mqlGithubWorkflow) workflowConfig() (map[string]any, error) {
	config := g.GetConfiguration()
	if config.Error != nil {
		return nil, config.Error
	}
	// A workflow registered from a non-default branch has no file to parse, so
	// the configuration is legitimately null.
	parsed, ok := config.Data.(map[string]any)
	if !ok {
		return nil, nil
	}
	return parsed, nil
}

func (g *mqlGithubWorkflow) triggers() ([]any, error) {
	config, err := g.workflowConfig()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(workflowTriggers(config)), nil
}

func (g *mqlGithubWorkflow) tokenPermissions() (any, error) {
	config, err := g.workflowConfig()
	if err != nil {
		return nil, err
	}
	permissions := workflowTokenPermissions(config)
	if permissions == nil {
		// The workflow sets no top-level permissions, so the repository or
		// organization default applies. Reporting an empty map would read as
		// "no permissions granted", which is the opposite of what is true.
		return nil, nil
	}
	return convert.JsonToDict(permissions)
}

func (g *mqlGithubWorkflow) runsOnLabels() ([]any, error) {
	config, err := g.workflowConfig()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(workflowRunsOnLabels(config)), nil
}

func (g *mqlGithubWorkflow) actionRefs() ([]any, error) {
	config, err := g.workflowConfig()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(workflowActionRefs(config)), nil
}

func (g *mqlGithubWorkflow) unpinnedActionRefs() ([]any, error) {
	config, err := g.workflowConfig()
	if err != nil {
		return nil, err
	}
	unpinned := []string{}
	for _, ref := range workflowActionRefs(config) {
		if !isPinnedActionRef(ref) {
			unpinned = append(unpinned, ref)
		}
	}
	return convert.SliceAnyToInterface(unpinned), nil
}

// ---------- parsing helpers ----------

// workflowTriggerBlock returns the workflow's trigger block.
//
// The block is written `on:`, but the workflow file is parsed as YAML 1.1,
// where the bare word `on` is the boolean true. Every trigger block therefore
// arrives under the key "true". The literal "on" is still checked first, for a
// workflow that quoted the key and for any future parser that does not fold
// it.
func workflowTriggerBlock(config map[string]any) any {
	if on, ok := config["on"]; ok {
		return on
	}
	return config["true"]
}

// workflowTriggers returns the event names in the workflow's `on` block. The
// block accepts three shapes: a single event name, a list of them, or a map
// keyed by event name.
func workflowTriggers(config map[string]any) []string {
	switch on := workflowTriggerBlock(config).(type) {
	case string:
		return []string{on}
	case []any:
		return sortedUnique(stringsIn(on))
	case map[string]any:
		return sortedUnique(keysOf(on))
	}
	return []string{}
}

// workflowTokenPermissions returns the workflow's top-level `permissions`
// block as a scope-to-access map, or nil when the workflow sets none. The
// shorthand string forms read-all and write-all are reported under the key
// "all" so callers see one shape.
func workflowTokenPermissions(config map[string]any) map[string]any {
	switch permissions := config["permissions"].(type) {
	case string:
		return map[string]any{"all": permissions}
	case map[string]any:
		return permissions
	}
	return nil
}

// workflowRunsOnLabels returns every distinct runner label the workflow's jobs
// request. A job names them directly as a string or list, or selects a runner
// group, in which case both the group name and any labels are reported.
func workflowRunsOnLabels(config map[string]any) []string {
	labels := []string{}
	for _, job := range jobsOf(config) {
		switch runsOn := job["runs-on"].(type) {
		case string:
			labels = append(labels, runsOn)
		case []any:
			labels = append(labels, stringsIn(runsOn)...)
		case map[string]any:
			if group, ok := runsOn["group"].(string); ok {
				labels = append(labels, group)
			}
			switch groupLabels := runsOn["labels"].(type) {
			case string:
				labels = append(labels, groupLabels)
			case []any:
				labels = append(labels, stringsIn(groupLabels)...)
			}
		}
	}
	return sortedUnique(labels)
}

// workflowActionRefs returns every distinct `uses` value in the workflow,
// covering both the steps of a job and a job that calls a reusable workflow.
func workflowActionRefs(config map[string]any) []string {
	refs := []string{}
	for _, job := range jobsOf(config) {
		// A job that calls a reusable workflow carries `uses` itself and has
		// no steps.
		if uses, ok := job["uses"].(string); ok {
			refs = append(refs, uses)
		}

		steps, ok := job["steps"].([]any)
		if !ok {
			continue
		}
		for _, entry := range steps {
			step, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if uses, ok := step["uses"].(string); ok {
				refs = append(refs, uses)
			}
		}
	}
	return sortedUnique(refs)
}

// isPinnedActionRef reports whether the reference identifies immutable code.
// Local actions live in the repository itself and are pinned by the commit
// being built, container actions are pinned by an image digest, and everything
// else is pinned only by a full commit SHA.
func isPinnedActionRef(ref string) bool {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, ".\\") {
		return true
	}

	_, version, ok := strings.CutLast(ref, "@")
	if !ok {
		return false
	}

	if strings.HasPrefix(ref, "docker://") {
		return imageDigest.MatchString(version)
	}
	return commitSHA.MatchString(version)
}

// jobsOf returns the workflow's job definitions, skipping any entry that is
// not an object.
func jobsOf(config map[string]any) []map[string]any {
	rawJobs, ok := config["jobs"].(map[string]any)
	if !ok {
		return nil
	}

	// Iterate in name order so repeated reads report the same thing.
	jobs := make([]map[string]any, 0, len(rawJobs))
	for _, name := range sortedUnique(keysOf(rawJobs)) {
		if job, ok := rawJobs[name].(map[string]any); ok {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// stringsIn returns the string elements of a parsed YAML list, skipping any
// element of another type.
func stringsIn(values []any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

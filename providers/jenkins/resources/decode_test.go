// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Every record in this package is decoded from a Jenkins tree query by struct
// tag alone. Two failure modes are silent:
//
//  1. A mistyped tag compiles, lints, and yields a zero value, which reaches
//     the user as a confident "false" or "" instead of an error. A false
//     `disabled` or `offline` inverts the finding an audit draws from it.
//  2. A tree query omits a field it cannot export rather than failing, so the
//     pointer fields exist to keep "the controller did not report this" apart
//     from "the controller reported false". A test that only exercises the
//     present case would let a value type through unnoticed.
//
// Go's encoding/json matches keys case-insensitively, so a payload written
// with the wrong casing still decodes against a wrongly-cased tag and proves
// nothing. The payloads below use the exact keys Jenkins returns, and each
// security-relevant field also gets a negative case built from a *different*
// key, which is what actually pins the tag.

// ptrOr renders a *string for failure messages, distinguishing nil from "".
func ptrOr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return "\"" + *s + "\""
}

func TestJenkinsJobDataDecodesFreestyleJob(t *testing.T) {
	// A freestyle job that has built: buildable/disabled are exported, and the
	// build reports builtOn as the empty string because it ran on the
	// controller's own executor.
	const payload = `{
		"_class": "hudson.model.FreeStyleProject",
		"name": "deploy-service",
		"fullName": "team-a/deploy-service",
		"url": "https://jenkins.example.com/job/team-a/job/deploy-service/",
		"buildable": true,
		"disabled": false,
		"description": "example freestyle job",
		"lastBuild": {"number": 42, "builtOn": ""},
		"lastSuccessfulBuild": {"number": 41},
		"lastFailedBuild": {"number": 40}
	}`

	var job jenkinsJobData
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if job.Class != "hudson.model.FreeStyleProject" {
		t.Errorf("_class should map to Class, got %q", job.Class)
	}
	if job.Name != "deploy-service" || job.FullName != "team-a/deploy-service" {
		t.Errorf("name=%q fullName=%q", job.Name, job.FullName)
	}
	if job.URL != "https://jenkins.example.com/job/team-a/job/deploy-service/" {
		t.Errorf("url = %q", job.URL)
	}
	if job.Description != "example freestyle job" {
		t.Errorf("description = %q", job.Description)
	}

	// A job that reports disabled:false is materially different from one that
	// does not report the field at all, so both must be non-nil here.
	if job.Buildable == nil || !*job.Buildable {
		t.Errorf("buildable = %v, want a non-nil true", job.Buildable)
	}
	if job.Disabled == nil {
		t.Fatal("disabled was exported as false and must decode non-nil")
	}
	if *job.Disabled {
		t.Error("disabled = true, want false")
	}

	// The empty string is the controller ("built-in node"), not an unknown
	// node. node() depends on the distinction, so the pointer must be set.
	if job.LastBuild.BuiltOn == nil {
		t.Fatal("builtOn was present as \"\" and must decode to a non-nil pointer")
	}
	if *job.LastBuild.BuiltOn != "" {
		t.Errorf("builtOn = %q, want the empty string", *job.LastBuild.BuiltOn)
	}

	if job.LastBuild.Number != 42 || job.LastSuccessfulBuild.Number != 41 || job.LastFailedBuild.Number != 40 {
		t.Errorf("build numbers: last=%d success=%d failed=%d",
			job.LastBuild.Number, job.LastSuccessfulBuild.Number, job.LastFailedBuild.Number)
	}
}

func TestJenkinsJobDataPipelineOmitsBuiltOn(t *testing.T) {
	// A pipeline build does not export builtOn at all. This is the entire
	// reason BuiltOn is a pointer: collapsing it to "" would report every
	// pipeline job as having run on the controller.
	const payload = `{
		"_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
		"name": "build-pipeline",
		"fullName": "team-a/build-pipeline",
		"url": "https://jenkins.example.com/job/team-a/job/build-pipeline/",
		"buildable": true,
		"lastBuild": {"number": 7}
	}`

	var job jenkinsJobData
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if job.LastBuild.Number != 7 {
		t.Errorf("lastBuild.number = %d, want 7", job.LastBuild.Number)
	}
	if job.LastBuild.BuiltOn != nil {
		t.Errorf("absent builtOn must stay nil, got %s", ptrOr(job.LastBuild.BuiltOn))
	}
	// disabled is not exported by a pipeline job either.
	if job.Disabled != nil {
		t.Errorf("absent disabled must stay nil, got %v", job.Disabled)
	}
}

func TestJenkinsJobDataFolderOmitsBuildableAndDisabled(t *testing.T) {
	// A folder is not a buildable item, so Jenkins exports neither flag. Both
	// must stay nil: a false `buildable` would look like a deliberately
	// blocked job, and a false `disabled` would assert the folder is active
	// on no evidence at all.
	const payload = `{
		"_class": "com.cloudbees.hudson.plugins.folder.Folder",
		"name": "team-a",
		"fullName": "team-a",
		"url": "https://jenkins.example.com/job/team-a/"
	}`

	var job jenkinsJobData
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if job.Buildable != nil {
		t.Errorf("absent buildable must stay nil, got %v", *job.Buildable)
	}
	if job.Disabled != nil {
		t.Errorf("absent disabled must stay nil, got %v", *job.Disabled)
	}
	if job.LastBuild.Number != 0 || job.LastBuild.BuiltOn != nil {
		t.Errorf("a folder has no builds: number=%d builtOn=%s",
			job.LastBuild.Number, ptrOr(job.LastBuild.BuiltOn))
	}
	if !isFolderClass(job.Class) {
		t.Errorf("isFolderClass(%q) = false, want true", job.Class)
	}
}

func TestJenkinsJobDataDecodesNestedChildren(t *testing.T) {
	// The provider issues one nested tree query, so children arrive inline
	// under `jobs`. If that tag did not decode, every job inside a folder
	// would vanish from jenkins.jobs and from the folder-credential walk.
	const payload = `{
		"_class": "com.cloudbees.hudson.plugins.folder.Folder",
		"name": "team-a",
		"fullName": "team-a",
		"url": "https://jenkins.example.com/job/team-a/",
		"jobs": [
			{
				"_class": "com.cloudbees.hudson.plugins.folder.Folder",
				"name": "sub",
				"fullName": "team-a/sub",
				"url": "https://jenkins.example.com/job/team-a/job/sub/",
				"jobs": [
					{
						"_class": "hudson.model.FreeStyleProject",
						"name": "deploy-service",
						"fullName": "team-a/sub/deploy-service",
						"url": "https://jenkins.example.com/job/team-a/job/sub/job/deploy-service/",
						"disabled": true
					}
				]
			},
			{
				"_class": "hudson.model.FreeStyleProject",
				"name": "lint",
				"fullName": "team-a/lint",
				"url": "https://jenkins.example.com/job/team-a/job/lint/"
			}
		]
	}`

	var job jenkinsJobData
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(job.Jobs) != 2 {
		t.Fatalf("expected 2 children, got %d", len(job.Jobs))
	}
	if len(job.Jobs[0].Jobs) != 1 {
		t.Fatalf("expected 1 grandchild, got %d", len(job.Jobs[0].Jobs))
	}

	leaf := job.Jobs[0].Jobs[0]
	if leaf.FullName != "team-a/sub/deploy-service" {
		t.Errorf("grandchild fullName = %q", leaf.FullName)
	}
	if leaf.Disabled == nil || !*leaf.Disabled {
		t.Errorf("grandchild disabled = %v, want a non-nil true", leaf.Disabled)
	}
	if !isFolderClass(job.Jobs[0].Class) {
		t.Error("nested folder should still be recognized as a folder")
	}
	if isFolderClass(job.Jobs[1].Class) {
		t.Error("a freestyle child must not be recognized as a folder")
	}
}

func TestJenkinsJobDataWrongKeysStayZero(t *testing.T) {
	// Negative pin. Every key below is a plausible-but-wrong spelling of a
	// real one. If any tag were written this way, the positive tests above
	// would still pass (Go matches keys case-insensitively, so only a
	// genuinely different key proves the tag).
	const payload = `{
		"class": "hudson.model.FreeStyleProject",
		"jobName": "deploy-service",
		"full_name": "team-a/deploy-service",
		"isBuildable": true,
		"is_disabled": true,
		"lastBuild": {"buildNumber": 42, "built_on": "linux-agent-01"},
		"childJobs": [{"name": "lint"}]
	}`

	var job jenkinsJobData
	if err := json.Unmarshal([]byte(payload), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if job.Class != "" {
		t.Errorf("Class must come from _class only, got %q", job.Class)
	}
	if job.Name != "" || job.FullName != "" {
		t.Errorf("name=%q fullName=%q, both should stay empty", job.Name, job.FullName)
	}
	if job.Buildable != nil {
		t.Errorf("Buildable must come from buildable only, got %v", *job.Buildable)
	}
	if job.Disabled != nil {
		t.Errorf("Disabled must come from disabled only, got %v", *job.Disabled)
	}
	if job.LastBuild.Number != 0 {
		t.Errorf("LastBuild.Number must come from number only, got %d", job.LastBuild.Number)
	}
	if job.LastBuild.BuiltOn != nil {
		t.Errorf("BuiltOn must come from builtOn only, got %s", ptrOr(job.LastBuild.BuiltOn))
	}
	if len(job.Jobs) != 0 {
		t.Errorf("Jobs must come from jobs only, got %d children", len(job.Jobs))
	}
}

func TestJenkinsNodeDataDecodesAgent(t *testing.T) {
	const payload = `{
		"_class": "hudson.slaves.SlaveComputer",
		"displayName": "linux-agent-01",
		"description": "example build agent",
		"offline": true,
		"temporarilyOffline": false,
		"offlineCauseReason": "disconnected",
		"numExecutors": 4,
		"assignedLabels": [{"name": "linux"}, {"name": "docker"}]
	}`

	var node jenkinsNodeData
	if err := json.Unmarshal([]byte(payload), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if node.Class != "hudson.slaves.SlaveComputer" {
		t.Errorf("_class should map to Class, got %q", node.Class)
	}
	if node.DisplayName != "linux-agent-01" || node.Description != "example build agent" {
		t.Errorf("displayName=%q description=%q", node.DisplayName, node.Description)
	}
	if node.Offline == nil || !*node.Offline {
		t.Errorf("offline = %v, want a non-nil true", node.Offline)
	}
	// An agent taken offline on purpose reads differently from one that fell
	// over, so an exported false must not be confused with an absent field.
	if node.TemporarilyOffline == nil {
		t.Fatal("temporarilyOffline was exported as false and must decode non-nil")
	}
	if *node.TemporarilyOffline {
		t.Error("temporarilyOffline = true, want false")
	}
	if node.OfflineCauseReason != "disconnected" {
		t.Errorf("offlineCauseReason = %q", node.OfflineCauseReason)
	}
	if node.NumExecutors == nil || *node.NumExecutors != 4 {
		t.Errorf("numExecutors = %v, want 4", node.NumExecutors)
	}
	if len(node.AssignedLabels) != 2 ||
		node.AssignedLabels[0].Name != "linux" || node.AssignedLabels[1].Name != "docker" {
		t.Errorf("assignedLabels = %+v", node.AssignedLabels)
	}
}

func TestJenkinsNodeDataAbsentFieldsStayNil(t *testing.T) {
	// A tree query drops a field the controller cannot export. All three of
	// these must stay nil rather than reporting an online node with zero
	// executors, which is a posture claim nothing supports.
	var node jenkinsNodeData
	if err := json.Unmarshal([]byte(`{"_class":"hudson.model.Hudson$MasterComputer","displayName":"Built-In Node"}`), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if node.Offline != nil {
		t.Errorf("absent offline must stay nil, got %v", *node.Offline)
	}
	if node.TemporarilyOffline != nil {
		t.Errorf("absent temporarilyOffline must stay nil, got %v", *node.TemporarilyOffline)
	}
	if node.NumExecutors != nil {
		t.Errorf("absent numExecutors must stay nil, got %d", *node.NumExecutors)
	}
	if len(node.AssignedLabels) != 0 {
		t.Errorf("absent assignedLabels must stay empty, got %+v", node.AssignedLabels)
	}
}

func TestJenkinsNodeDataWrongKeysStayZero(t *testing.T) {
	// Negative pin, same reasoning as the job case.
	const payload = `{
		"class": "hudson.slaves.SlaveComputer",
		"name": "linux-agent-01",
		"isOffline": true,
		"temporarily_offline": true,
		"executors": 4,
		"labels": [{"name": "linux"}]
	}`

	var node jenkinsNodeData
	if err := json.Unmarshal([]byte(payload), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if node.Class != "" {
		t.Errorf("Class must come from _class only, got %q", node.Class)
	}
	if node.DisplayName != "" {
		t.Errorf("DisplayName must come from displayName only, got %q", node.DisplayName)
	}
	if node.Offline != nil {
		t.Errorf("Offline must come from offline only, got %v", *node.Offline)
	}
	if node.TemporarilyOffline != nil {
		t.Errorf("TemporarilyOffline must come from temporarilyOffline only, got %v", *node.TemporarilyOffline)
	}
	if node.NumExecutors != nil {
		t.Errorf("NumExecutors must come from numExecutors only, got %d", *node.NumExecutors)
	}
	if len(node.AssignedLabels) != 0 {
		t.Errorf("AssignedLabels must come from assignedLabels only, got %+v", node.AssignedLabels)
	}
}

func TestJenkinsCredentialDataDecodes(t *testing.T) {
	// Only identifying metadata is requested; secret material is never part
	// of this response. typeName is what an audit reads to tell a
	// username/password entry from a certificate or an SSH key.
	const payload = `{
		"id": "deploy-service-token",
		"typeName": "Username with password",
		"description": "example credential"
	}`

	var cred jenkinsCredentialData
	if err := json.Unmarshal([]byte(payload), &cred); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cred.Id != "deploy-service-token" {
		t.Errorf("id = %q", cred.Id)
	}
	if cred.TypeName != "Username with password" {
		t.Errorf("typeName = %q", cred.TypeName)
	}
	if cred.Description != "example credential" {
		t.Errorf("description = %q", cred.Description)
	}
}

func TestJenkinsCredentialDataWrongKeysStayZero(t *testing.T) {
	const payload = `{
		"credentialId": "deploy-service-token",
		"type_name": "Username with password",
		"displayName": "example credential"
	}`

	var cred jenkinsCredentialData
	if err := json.Unmarshal([]byte(payload), &cred); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cred.Id != "" || cred.TypeName != "" || cred.Description != "" {
		t.Errorf("no field should decode from wrong keys, got %+v", cred)
	}
}

func TestIsControllerNode(t *testing.T) {
	tests := []struct {
		name        string
		class       string
		displayName string
		want        bool
	}{
		{
			name:        "controller class",
			class:       "hudson.model.Hudson$MasterComputer",
			displayName: "Built-In Node",
			want:        true,
		},
		{
			name:        "controller class under the older internal name",
			class:       "hudson.model.Hudson$MasterComputer",
			displayName: "master",
			want:        true,
		},
		{
			// Regression guard. An agent is free to be named "master". The
			// class is authoritative when present, so a non-controller class
			// wins over the name: otherwise the agent would be reported as
			// the controller and would collide on the controller's cache key,
			// dropping its real data from the node list.
			name:        "agent named master is not the controller",
			class:       "hudson.slaves.SlaveComputer",
			displayName: "master",
			want:        false,
		},
		{
			name:        "agent named Built-In Node is not the controller",
			class:       "hudson.slaves.SlaveComputer",
			displayName: "Built-In Node",
			want:        false,
		},
		{
			name:        "agent with a normal name",
			class:       "hudson.slaves.SlaveComputer",
			displayName: "linux-agent-01",
			want:        false,
		},
		// Fallback: a response that carries no class at all.
		{name: "no class, empty name", class: "", displayName: "", want: true},
		{name: "no class, master", class: "", displayName: "master", want: true},
		{name: "no class, (built-in)", class: "", displayName: "(built-in)", want: true},
		{name: "no class, Built-In Node", class: "", displayName: "Built-In Node", want: true},
		{name: "no class, agent name", class: "", displayName: "linux-agent-01", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isControllerNode(tc.class, tc.displayName); got != tc.want {
				t.Errorf("isControllerNode(%q, %q) = %v, want %v", tc.class, tc.displayName, got, tc.want)
			}
		})
	}
}

func TestNodeDisplayName(t *testing.T) {
	tests := []struct {
		name string
		node jenkinsNodeData
		want string
	}{
		{
			// The controller is surfaced under one name whatever the
			// connected core version calls it internally.
			name: "controller reported as master normalizes",
			node: jenkinsNodeData{Class: "hudson.model.Hudson$MasterComputer", DisplayName: "master"},
			want: builtInNodeDisplayName,
		},
		{
			name: "controller reported with an empty name normalizes",
			node: jenkinsNodeData{Class: "hudson.model.Hudson$MasterComputer", DisplayName: ""},
			want: builtInNodeDisplayName,
		},
		{
			name: "no class and an empty name falls back to the controller",
			node: jenkinsNodeData{DisplayName: builtInNodeName},
			want: builtInNodeDisplayName,
		},
		{
			// An agent's name is never rewritten, whatever it is called.
			name: "agent name is preserved",
			node: jenkinsNodeData{Class: "hudson.slaves.SlaveComputer", DisplayName: "linux-agent-01"},
			want: "linux-agent-01",
		},
		{
			name: "agent named master keeps its own name",
			node: jenkinsNodeData{Class: "hudson.slaves.SlaveComputer", DisplayName: "master"},
			want: "master",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeDisplayName(tc.node); got != tc.want {
				t.Errorf("nodeDisplayName(%+v) = %q, want %q", tc.node, got, tc.want)
			}
		})
	}
}

func TestIsFolderClass(t *testing.T) {
	tests := []struct {
		class string
		want  bool
	}{
		{class: "com.cloudbees.hudson.plugins.folder.Folder", want: true},
		{class: "jenkins.branch.OrganizationFolder", want: true},
		{class: "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject", want: false},
		{class: "hudson.model.FreeStyleProject", want: false},
		{class: "org.jenkinsci.plugins.workflow.job.WorkflowJob", want: false},
		// A class-less response must not be mistaken for a folder, or the
		// credential walk would probe a folder store that does not exist.
		{class: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.class, func(t *testing.T) {
			if got := isFolderClass(tc.class); got != tc.want {
				t.Errorf("isFolderClass(%q) = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}

func TestJobsTreeQueryNestsRequestedDepth(t *testing.T) {
	// The whole job tree arrives in one request, so the nesting depth of this
	// query is the only thing that decides whether jobs inside folders are
	// seen at all. depth=n yields n+1 levels of `jobs[...]`.
	for _, depth := range []int{0, 1, 3, jobRecursionDepth} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			q := jobsTreeQuery(depth)

			if got := strings.Count(q, "jobs["); got != depth+1 {
				t.Errorf("depth %d: got %d jobs[ levels, want %d", depth, got, depth+1)
			}
			if got := strings.Count(q, jobTreeFields); got != depth+1 {
				t.Errorf("depth %d: field set repeated %d times, want %d", depth, got, depth+1)
			}
			if opens, closes := strings.Count(q, "["), strings.Count(q, "]"); opens != closes {
				t.Errorf("depth %d: unbalanced brackets (%d open, %d close) in %q", depth, opens, closes, q)
			}
			if !strings.HasPrefix(q, "jobs[") || !strings.HasSuffix(q, "]") {
				t.Errorf("depth %d: query should be a single jobs[...] block, got %q", depth, q)
			}
			// builtOn and disabled must be requested at every level, or a
			// nested job's flags come back absent and read as unknown.
			if !strings.Contains(jobTreeFields, "builtOn") || !strings.Contains(jobTreeFields, "disabled") {
				t.Errorf("job tree fields must request builtOn and disabled, got %q", jobTreeFields)
			}
		})
	}
}

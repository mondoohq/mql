// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models the CI/CD credentials and egress paths a project carries:
// trigger tokens, pipeline schedules, secure files, Kubernetes agents, and push
// mirrors. Every identifier GitLab assigns to these is unique only within the
// project, so all of them key on projectScopedID.
//
// The secret material these APIs return -- PipelineTrigger.Token and
// AgentToken.Token -- is deliberately not modeled. The security questions
// ("which credentials exist, who owns them, are they still in use") are all
// answered by the metadata, and copying live tokens into scan results would
// spread them further than GitLab does.

const gitlabPerPage = int64(50)

// gitlabUserRef resolves a GitLab user embedded in an API response to a typed
// gitlab.user. initGitlabUser degrades to a bare resource on 403/404, so this
// stays safe for tokens that cannot read /users/:id.
func gitlabUserRef(runtime *plugin.Runtime, userID int64) (*mqlGitlabUser, error) {
	res, err := NewResource(runtime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(userID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

//
// Pipeline trigger tokens
//

func (t *mqlGitlabProjectPipelineTrigger) id() (string, error) {
	return projectScopedID("gitlab.project.pipelineTrigger", t.projectID, strconv.FormatInt(t.Id.Data, 10)), nil
}

// mqlGitlabProjectPipelineTriggerInternal carries the parent project (for the
// cache key) and the owner id the typed accessor resolves lazily.
type mqlGitlabProjectPipelineTriggerInternal struct {
	projectID    int64
	cacheOwnerID int64
}

// owner returns the user whose permissions triggered pipelines run with.
func (t *mqlGitlabProjectPipelineTrigger) owner() (*mqlGitlabUser, error) {
	if t.cacheOwnerID <= 0 {
		t.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(t.MqlRuntime, t.cacheOwnerID)
}

// pipelineTriggers lists the trigger tokens registered on the project.
func (p *mqlGitlabProject) pipelineTriggers() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.PipelineTrigger
	page := int64(1)
	for {
		triggers, resp, err := conn.Client().PipelineTriggers.ListPipelineTriggers(projectID, &gitlab.ListPipelineTriggersOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, triggers...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, trigger := range all {
		// Token is intentionally omitted: GitLab returns the live secret here.
		mqlTrigger, err := CreateResource(p.MqlRuntime, "gitlab.project.pipelineTrigger", map[string]*llx.RawData{
			"id":          llx.IntData(trigger.ID),
			"description": llx.StringData(trigger.Description),
			"createdAt":   llx.TimeDataPtr(trigger.CreatedAt),
			"updatedAt":   llx.TimeDataPtr(trigger.UpdatedAt),
			"lastUsedAt":  llx.TimeDataPtr(trigger.LastUsed),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlTrigger.(*mqlGitlabProjectPipelineTrigger)
		internal.projectID = p.Id.Data
		if trigger.Owner != nil {
			internal.cacheOwnerID = trigger.Owner.ID
		}

		res = append(res, mqlTrigger)
	}

	return res, nil
}

//
// Pipeline schedules
//

func (s *mqlGitlabProjectPipelineSchedule) id() (string, error) {
	return projectScopedID("gitlab.project.pipelineSchedule", s.projectID, strconv.FormatInt(s.Id.Data, 10)), nil
}

// mqlGitlabProjectPipelineScheduleInternal backs the fields the list endpoint
// does not return. GET /pipeline_schedules omits both `variables` and
// `last_pipeline`; only GET /pipeline_schedules/:id carries them. One fetch
// serves all five computed accessors.
type mqlGitlabProjectPipelineScheduleInternal struct {
	projectID    int64
	cacheOwnerID int64

	detailOnce sync.Once
	detail     *gitlab.PipelineSchedule
	detailErr  error
}

// owner returns the user whose permissions the scheduled pipeline runs with.
func (s *mqlGitlabProjectPipelineSchedule) owner() (*mqlGitlabUser, error) {
	if s.cacheOwnerID <= 0 {
		s.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(s.MqlRuntime, s.cacheOwnerID)
}

// fetchDetail loads the single-schedule representation once per resource.
func (s *mqlGitlabProjectPipelineSchedule) fetchDetail() (*gitlab.PipelineSchedule, error) {
	s.detailOnce.Do(func() {
		conn := s.MqlRuntime.Connection.(*connection.GitLabConnection)
		schedule, _, err := conn.Client().PipelineSchedules.GetPipelineSchedule(int(s.projectID), s.Id.Data)
		if err != nil {
			s.detailErr = err
			return
		}
		s.detail = schedule
	})
	return s.detail, s.detailErr
}

// variables reports the names and types of the CI/CD variables the schedule
// injects. Values are omitted on purpose -- GitLab returns them in clear text.
// GitLab itself withholds the list from anyone below Maintainer who does not
// own the schedule, which surfaces here as an empty map.
func (s *mqlGitlabProjectPipelineSchedule) variables() (map[string]any, error) {
	detail, err := s.fetchDetail()
	if err != nil {
		return nil, err
	}

	vars := map[string]any{}
	if detail == nil {
		return vars, nil
	}
	for _, v := range detail.Variables {
		if v == nil {
			continue
		}
		vars[v.Key] = string(v.VariableType)
	}
	return vars, nil
}

func (s *mqlGitlabProjectPipelineSchedule) lastPipelineId() (int64, error) {
	detail, err := s.fetchDetail()
	if err != nil || detail == nil || detail.LastPipeline == nil {
		return 0, err
	}
	return detail.LastPipeline.ID, nil
}

func (s *mqlGitlabProjectPipelineSchedule) lastPipelineSha() (string, error) {
	detail, err := s.fetchDetail()
	if err != nil || detail == nil || detail.LastPipeline == nil {
		return "", err
	}
	return detail.LastPipeline.SHA, nil
}

func (s *mqlGitlabProjectPipelineSchedule) lastPipelineRef() (string, error) {
	detail, err := s.fetchDetail()
	if err != nil || detail == nil || detail.LastPipeline == nil {
		return "", err
	}
	return detail.LastPipeline.Ref, nil
}

func (s *mqlGitlabProjectPipelineSchedule) lastPipelineStatus() (string, error) {
	detail, err := s.fetchDetail()
	if err != nil || detail == nil || detail.LastPipeline == nil {
		return "", err
	}
	return detail.LastPipeline.Status, nil
}

// pipelineSchedules lists the recurring pipeline runs configured on the project.
func (p *mqlGitlabProject) pipelineSchedules() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.PipelineSchedule
	page := int64(1)
	for {
		schedules, resp, err := conn.Client().PipelineSchedules.ListPipelineSchedules(projectID, &gitlab.ListPipelineSchedulesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, schedules...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, schedule := range all {
		// variables and lastPipeline* are absent from this response and are
		// resolved by fetchDetail on first access.
		mqlSchedule, err := CreateResource(p.MqlRuntime, "gitlab.project.pipelineSchedule", map[string]*llx.RawData{
			"id":           llx.IntData(schedule.ID),
			"description":  llx.StringData(schedule.Description),
			"ref":          llx.StringData(schedule.Ref),
			"cron":         llx.StringData(schedule.Cron),
			"cronTimezone": llx.StringData(schedule.CronTimezone),
			"nextRunAt":    llx.TimeDataPtr(schedule.NextRunAt),
			"active":       llx.BoolData(schedule.Active),
			"createdAt":    llx.TimeDataPtr(schedule.CreatedAt),
			"updatedAt":    llx.TimeDataPtr(schedule.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlSchedule.(*mqlGitlabProjectPipelineSchedule)
		internal.projectID = p.Id.Data
		if schedule.Owner != nil {
			internal.cacheOwnerID = schedule.Owner.ID
		}

		res = append(res, mqlSchedule)
	}

	return res, nil
}

//
// Secure files
//

func (f *mqlGitlabProjectSecureFile) id() (string, error) {
	return projectScopedID("gitlab.project.secureFile", f.projectID, strconv.FormatInt(f.Id.Data, 10)), nil
}

type mqlGitlabProjectSecureFileInternal struct {
	projectID int64
}

// secureFiles lists the certificates and keystores CI jobs can mount.
func (p *mqlGitlabProject) secureFiles() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.SecureFile
	page := int64(1)
	for {
		files, resp, err := conn.Client().SecureFiles.ListProjectSecureFiles(projectID, &gitlab.ListProjectSecureFilesOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, files...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, file := range all {
		// Certificate metadata is only present for files GitLab could parse as
		// a certificate; keystores and provisioning profiles leave it nil.
		certificateID := ""
		var certificateExpiresAt *time.Time
		issuer := map[string]any{}
		subject := map[string]any{}
		if file.Metadata != nil {
			certificateID = file.Metadata.ID
			certificateExpiresAt = file.Metadata.ExpiresAt
			issuer = distinguishedName(file.Metadata.Issuer.CN, file.Metadata.Issuer.O, file.Metadata.Issuer.OU, file.Metadata.Issuer.C, "")
			subject = distinguishedName(file.Metadata.Subject.CN, file.Metadata.Subject.O, file.Metadata.Subject.OU, file.Metadata.Subject.C, file.Metadata.Subject.UID)
		}

		mqlFile, err := CreateResource(p.MqlRuntime, "gitlab.project.secureFile", map[string]*llx.RawData{
			"id":                   llx.IntData(file.ID),
			"name":                 llx.StringData(file.Name),
			"checksum":             llx.StringData(file.Checksum),
			"checksumAlgorithm":    llx.StringData(file.ChecksumAlgorithm),
			"createdAt":            llx.TimeDataPtr(file.CreatedAt),
			"expiresAt":            llx.TimeDataPtr(file.ExpiresAt),
			"certificateId":        llx.StringData(certificateID),
			"certificateExpiresAt": llx.TimeDataPtr(certificateExpiresAt),
			"issuer":               llx.DictData(issuer),
			"subject":              llx.DictData(subject),
		})
		if err != nil {
			return nil, err
		}

		mqlFile.(*mqlGitlabProjectSecureFile).projectID = p.Id.Data
		res = append(res, mqlFile)
	}

	return res, nil
}

// distinguishedName builds the dict for a certificate issuer or subject,
// dropping components the certificate does not carry so an absent OU reads as
// absent rather than as an empty string.
func distinguishedName(cn, o, ou, c, uid string) map[string]any {
	dn := map[string]any{}
	for key, value := range map[string]string{"CN": cn, "O": o, "OU": ou, "C": c, "UID": uid} {
		if value != "" {
			dn[key] = value
		}
	}
	return dn
}

//
// Agents for Kubernetes
//

func (a *mqlGitlabProjectClusterAgent) id() (string, error) {
	return projectScopedID("gitlab.project.clusterAgent", a.projectID, strconv.FormatInt(a.Id.Data, 10)), nil
}

type mqlGitlabProjectClusterAgentInternal struct {
	projectID          int64
	cacheCreatedByID   int64
	cacheConfigProject int64
}

func (a *mqlGitlabProjectClusterAgent) createdBy() (*mqlGitlabUser, error) {
	if a.cacheCreatedByID <= 0 {
		a.CreatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(a.MqlRuntime, a.cacheCreatedByID)
}

// configProject returns the project holding the agent configuration, which
// governs which other projects are allowed to use the agent.
func (a *mqlGitlabProjectClusterAgent) configProject() (*mqlGitlabProject, error) {
	if a.cacheConfigProject <= 0 {
		a.ConfigProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
		"id": llx.IntData(a.cacheConfigProject),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabProject), nil
}

// tokens lists the credentials the in-cluster agent authenticates with. This is
// one API call per agent, so it stays lazy: listing agents does not pay for it.
func (a *mqlGitlabProjectClusterAgent) tokens() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.GitLabConnection)

	var all []*gitlab.AgentToken
	page := int64(1)
	for {
		tokens, resp, err := conn.Client().ClusterAgents.ListAgentTokens(int(a.projectID), a.Id.Data, &gitlab.ListAgentTokensOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, tokens...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, token := range all {
		// Token is intentionally omitted: GitLab returns the live secret here.
		mqlToken, err := CreateResource(a.MqlRuntime, "gitlab.project.clusterAgent.token", map[string]*llx.RawData{
			"id":          llx.IntData(token.ID),
			"name":        llx.StringData(token.Name),
			"description": llx.StringData(token.Description),
			"status":      llx.StringData(token.Status),
			"createdAt":   llx.TimeDataPtr(token.CreatedAt),
			"lastUsedAt":  llx.TimeDataPtr(token.LastUsedAt),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlToken.(*mqlGitlabProjectClusterAgentToken)
		internal.projectID = a.projectID
		internal.agentID = a.Id.Data
		internal.cacheCreatedByID = token.CreatedByUserID

		res = append(res, mqlToken)
	}

	return res, nil
}

func (t *mqlGitlabProjectClusterAgentToken) id() (string, error) {
	return projectScopedID("gitlab.project.clusterAgent.token", t.projectID,
		strconv.FormatInt(t.agentID, 10), strconv.FormatInt(t.Id.Data, 10)), nil
}

type mqlGitlabProjectClusterAgentTokenInternal struct {
	projectID        int64
	agentID          int64
	cacheCreatedByID int64
}

func (t *mqlGitlabProjectClusterAgentToken) createdBy() (*mqlGitlabUser, error) {
	if t.cacheCreatedByID <= 0 {
		t.CreatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(t.MqlRuntime, t.cacheCreatedByID)
}

// clusterAgents lists the Kubernetes clusters connected to the project.
func (p *mqlGitlabProject) clusterAgents() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.Agent
	page := int64(1)
	for {
		agents, resp, err := conn.Client().ClusterAgents.ListAgents(projectID, &gitlab.ListAgentsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, agents...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, agent := range all {
		mqlAgent, err := CreateResource(p.MqlRuntime, "gitlab.project.clusterAgent", map[string]*llx.RawData{
			"id":          llx.IntData(agent.ID),
			"name":        llx.StringData(agent.Name),
			"createdAt":   llx.TimeDataPtr(agent.CreatedAt),
			"isReceptive": llx.BoolData(agent.IsReceptive),
		})
		if err != nil {
			return nil, err
		}

		internal := mqlAgent.(*mqlGitlabProjectClusterAgent)
		internal.projectID = p.Id.Data
		internal.cacheCreatedByID = agent.CreatedByUserID
		internal.cacheConfigProject = agent.ConfigProject.ID

		res = append(res, mqlAgent)
	}

	return res, nil
}

//
// Push mirrors
//

func (m *mqlGitlabProjectRemoteMirror) id() (string, error) {
	return projectScopedID("gitlab.project.remoteMirror", m.projectID, strconv.FormatInt(m.Id.Data, 10)), nil
}

type mqlGitlabProjectRemoteMirrorInternal struct {
	projectID int64
}

// remoteMirrors lists the external repositories this project pushes to. GitLab
// redacts any password embedded in the URL before returning it.
func (p *mqlGitlabProject) remoteMirrors() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := int(p.Id.Data)

	var all []*gitlab.ProjectMirror
	page := int64(1)
	for {
		mirrors, resp, err := conn.Client().ProjectMirrors.ListProjectMirror(projectID, &gitlab.ListProjectMirrorOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, mirrors...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, mirror := range all {
		mqlMirror, err := CreateResource(p.MqlRuntime, "gitlab.project.remoteMirror", map[string]*llx.RawData{
			"id":                     llx.IntData(mirror.ID),
			"enabled":                llx.BoolData(mirror.Enabled),
			"url":                    llx.StringData(mirror.URL),
			"authMethod":             llx.StringData(mirror.AuthMethod),
			"onlyProtectedBranches":  llx.BoolData(mirror.OnlyProtectedBranches),
			"keepDivergentRefs":      llx.BoolData(mirror.KeepDivergentRefs),
			"mirrorBranchRegex":      llx.StringData(mirror.MirrorBranchRegex),
			"updateStatus":           llx.StringData(mirror.UpdateStatus),
			"lastError":              llx.StringData(mirror.LastError),
			"lastUpdateAt":           llx.TimeDataPtr(mirror.LastUpdateAt),
			"lastSuccessfulUpdateAt": llx.TimeDataPtr(mirror.LastSuccessfulUpdateAt),
		})
		if err != nil {
			return nil, err
		}

		mqlMirror.(*mqlGitlabProjectRemoteMirror).projectID = p.Id.Data
		res = append(res, mqlMirror)
	}

	return res, nil
}

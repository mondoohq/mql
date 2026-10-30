// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenaiFineTuningJobInternal struct {
	cacheTrainingFileID   string
	cacheValidationFileID string
}

// mapFineTuningJob builds the resource args for an openai.fineTuningJob. Both
// the collection path and the single-object init share it so the two paths
// cannot diverge. The training/validation file IDs are cached on the resource
// separately by the caller (see newFineTuningJob).
func mapFineTuningJob(j openai.FineTuningJob) map[string]*llx.RawData {
	var nEpochs any
	if j.Hyperparameters.NEpochs.OfAuto != "" {
		nEpochs = string(j.Hyperparameters.NEpochs.OfAuto)
	} else {
		nEpochs = j.Hyperparameters.NEpochs.OfInt
	}
	hyperparams := map[string]any{
		"n_epochs": nEpochs,
	}

	var errInfo any
	if j.Error.Code != "" {
		errInfo = map[string]any{
			"code":    j.Error.Code,
			"message": j.Error.Message,
			"param":   j.Error.Param,
		}
	}

	return map[string]*llx.RawData{
		"__id":            llx.StringData(j.ID),
		"id":              llx.StringData(j.ID),
		"model":           llx.StringData(j.Model),
		"status":          llx.StringData(string(j.Status)),
		"createdAt":       llx.TimeDataPtr(unixToNullableTime(j.CreatedAt)),
		"finishedAt":      llx.TimeDataPtr(unixToNullableTime(j.FinishedAt)),
		"fineTunedModel":  llx.StringData(j.FineTunedModel),
		"trainedTokens":   llx.IntData(j.TrainedTokens),
		"seed":            llx.IntData(j.Seed),
		"organizationId":  llx.StringData(j.OrganizationID),
		"hyperparameters": llx.DictData(hyperparams),
		"error":           llx.DictData(errInfo),
	}
}

// newFineTuningJob creates the resource and caches the file IDs needed by the
// typed trainingFile/validationFile accessors.
func newFineTuningJob(runtime *plugin.Runtime, j openai.FineTuningJob) (*mqlOpenaiFineTuningJob, error) {
	res, err := CreateResource(runtime, "openai.fineTuningJob", mapFineTuningJob(j))
	if err != nil {
		return nil, err
	}
	job := res.(*mqlOpenaiFineTuningJob)
	job.cacheTrainingFileID = j.TrainingFile
	job.cacheValidationFileID = j.ValidationFile
	return job, nil
}

func (r *mqlOpenai) fineTuningJobs() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.fineTuningJobs")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.FineTuning.Jobs.ListAutoPaging(ctx, openai.FineTuningJobListParams{})
	var res []any
	for iter.Next() {
		j := iter.Current()
		job, err := newFineTuningJob(r.MqlRuntime, j)
		if err != nil {
			return nil, err
		}
		res = append(res, job)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list fine-tuning jobs: %w", err)
	}
	return res, nil
}

func initOpenaiFineTuningJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	jobID, ok := idRaw.Value.(string)
	if !ok || jobID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.fineTuningJob")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch fine-tuning job %s: no project API key configured", jobID)
	}
	j, err := client.FineTuning.Jobs.Get(context.Background(), jobID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get fine-tuning job %s: %w", jobID, err)
	}
	job, err := newFineTuningJob(runtime, *j)
	if err != nil {
		return nil, nil, err
	}
	return nil, job, nil
}

func (r *mqlOpenaiFineTuningJob) trainingFile() (*mqlOpenaiFile, error) {
	if r.cacheTrainingFileID == "" {
		r.TrainingFile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openai.file", map[string]*llx.RawData{
		"__id": llx.StringData(r.cacheTrainingFileID),
		"id":   llx.StringData(r.cacheTrainingFileID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenaiFile), nil
}

func (r *mqlOpenaiFineTuningJob) validationFile() (*mqlOpenaiFile, error) {
	if r.cacheValidationFileID == "" {
		r.ValidationFile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openai.file", map[string]*llx.RawData{
		"__id": llx.StringData(r.cacheValidationFileID),
		"id":   llx.StringData(r.cacheValidationFileID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenaiFile), nil
}

type mqlOpenaiFineTuningJobCheckpointInternal struct {
	cacheCheckpointModel string
}

type mqlOpenaiFineTuningJobCheckpointPermissionInternal struct {
	cacheProjectId string
}

func (r *mqlOpenaiFineTuningJob) checkpoints() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.fineTuningJob.checkpoints")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.FineTuning.Jobs.Checkpoints.ListAutoPaging(ctx, r.Id.Data, openai.FineTuningJobCheckpointListParams{}),
		func(c openai.FineTuningJobCheckpoint) string { return c.ID },
		func(c openai.FineTuningJobCheckpoint) error {
			mqlCheckpoint, err := CreateResource(r.MqlRuntime, "openai.fineTuningJob.checkpoint", map[string]*llx.RawData{
				"__id":                     llx.StringData(c.ID),
				"id":                       llx.StringData(c.ID),
				"fineTunedModelCheckpoint": llx.StringData(c.FineTunedModelCheckpoint),
				"stepNumber":               llx.IntData(c.StepNumber),
				"createdAt":                llx.TimeDataPtr(unixToNullableTime(c.CreatedAt)),
			})
			if err != nil {
				return err
			}
			mqlCheckpoint.(*mqlOpenaiFineTuningJobCheckpoint).cacheCheckpointModel = c.FineTunedModelCheckpoint
			res = append(res, mqlCheckpoint)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list checkpoints for fine-tuning job %s: %w", r.Id.Data, err)
	}
	return res, nil
}

// permissions lists the projects a checkpoint has been shared into. Listing
// the checkpoints is a project-key call while reading their permissions is an
// admin-key one, so this field is the half of the pair that needs the admin
// credential and it is only answerable on a connection carrying both.
func (r *mqlOpenaiFineTuningJobCheckpoint) permissions() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.fineTuningJob.checkpoint.permissions")
	if err != nil {
		return nil, err
	}
	if client == nil || r.cacheCheckpointModel == "" {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.FineTuning.Checkpoints.Permissions.ListAutoPaging(ctx, r.cacheCheckpointModel,
			openai.FineTuningCheckpointPermissionListParams{}),
		func(p openai.FineTuningCheckpointPermissionListResponse) string { return p.ID },
		func(p openai.FineTuningCheckpointPermissionListResponse) error {
			mqlPermission, err := CreateResource(r.MqlRuntime, "openai.fineTuningJob.checkpoint.permission", map[string]*llx.RawData{
				"__id":      llx.StringData(p.ID),
				"id":        llx.StringData(p.ID),
				"createdAt": llx.TimeDataPtr(unixToNullableTime(p.CreatedAt)),
			})
			if err != nil {
				return err
			}
			mqlPermission.(*mqlOpenaiFineTuningJobCheckpointPermission).cacheProjectId = p.ProjectID
			res = append(res, mqlPermission)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list permissions for checkpoint %s: %w", r.cacheCheckpointModel, err)
	}
	return res, nil
}

func (r *mqlOpenaiFineTuningJobCheckpointPermission) project() (*mqlOpenaiProject, error) {
	if r.cacheProjectId == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

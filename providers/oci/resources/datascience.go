// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/datascience"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciAiDataScience) id() (string, error) {
	return "oci.ai.dataScience", nil
}

// listRegional runs fetch against the Data Science API in every subscribed
// region and every admitted compartment (see ociListRegionalAI).
func (o *mqlOciAiDataScience) listRegional(fetch func(svc *datascience.DataScienceClient, compartmentID string) ([]any, error)) ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociListRegionalAI(o.MqlRuntime, func(region string, compartmentID string) ([]any, error) {
		svc, err := conn.DataScienceClient(region)
		if err != nil {
			return nil, err
		}
		return fetch(svc, compartmentID)
	})
}

// ----- projects -----

func (o *mqlOciAiDataScience) projects() ([]any, error) {
	return o.listRegional(o.fetchProjects)
}

func (o *mqlOciAiDataScience) fetchProjects(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.ProjectSummary, *string, error) {
		resp, err := svc.ListProjects(ctx, datascience.ListProjectsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		p := items[i]
		mqlProject, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.project", map[string]*llx.RawData{
			"id":            llx.StringDataPtr(p.Id),
			"name":          llx.StringDataPtr(p.DisplayName),
			"compartmentID": llx.StringDataPtr(p.CompartmentId),
			"description":   llx.StringDataPtr(p.Description),
			"createdBy":     llx.StringDataPtr(p.CreatedBy),
			"state":         llx.StringData(string(p.LifecycleState)),
			"created":       sdkTimeData(p.TimeCreated),
			"freeformTags":  llx.MapData(strMapToAny(p.FreeformTags), types.String),
			"definedTags":   llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProject)
	}
	return res, nil
}

func initOciAiDataScienceProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.project", (*mqlOciAiDataScience).GetProjects)
}

func (o *mqlOciAiDataScienceProject) id() (string, error) {
	return "oci.ai.dataScience.project/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceProject) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

// ----- notebook sessions -----

func (o *mqlOciAiDataScience) notebookSessions() ([]any, error) {
	return o.listRegional(o.fetchNotebookSessions)
}

func (o *mqlOciAiDataScience) fetchNotebookSessions(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.NotebookSessionSummary, *string, error) {
		resp, err := svc.ListNotebookSessions(ctx, datascience.ListNotebookSessionsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		ns := items[i]

		var shape, subnetID, privateEndpointID string
		var blockStorage int64
		if cfg := ns.NotebookSessionConfigDetails; cfg != nil {
			shape = stringValue(cfg.Shape)
			subnetID = stringValue(cfg.SubnetId)
			privateEndpointID = stringValue(cfg.PrivateEndpointId)
			blockStorage = intValue(cfg.BlockStorageSizeInGBs)
		} else if cfg := ns.NotebookSessionConfigurationDetails; cfg != nil {
			shape = stringValue(cfg.Shape)
			subnetID = stringValue(cfg.SubnetId)
			privateEndpointID = stringValue(cfg.PrivateEndpointId)
			blockStorage = intValue(cfg.BlockStorageSizeInGBs)
		}

		mqlSession, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.notebookSession", map[string]*llx.RawData{
			"id":                    llx.StringDataPtr(ns.Id),
			"name":                  llx.StringDataPtr(ns.DisplayName),
			"compartmentID":         llx.StringDataPtr(ns.CompartmentId),
			"projectID":             llx.StringDataPtr(ns.ProjectId),
			"createdBy":             llx.StringDataPtr(ns.CreatedBy),
			"shape":                 llx.StringData(shape),
			"subnetID":              llx.StringData(subnetID),
			"blockStorageSizeInGBs": llx.IntData(blockStorage),
			"privateEndpointID":     llx.StringData(privateEndpointID),
			"notebookSessionUrl":    llx.StringDataPtr(ns.NotebookSessionUrl),
			"state":                 llx.StringData(string(ns.LifecycleState)),
			"created":               sdkTimeData(ns.TimeCreated),
			"freeformTags":          llx.MapData(strMapToAny(ns.FreeformTags), types.String),
			"definedTags":           llx.MapData(definedTagsToAny(ns.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlSessionTyped := mqlSession.(*mqlOciAiDataScienceNotebookSession)
		mqlSessionTyped.cacheProjectID = stringValue(ns.ProjectId)
		mqlSessionTyped.cacheSubnetID = subnetID
		res = append(res, mqlSessionTyped)
	}
	return res, nil
}

type mqlOciAiDataScienceNotebookSessionInternal struct {
	cacheProjectID string
	cacheSubnetID  string
}

func initOciAiDataScienceNotebookSession(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.notebookSession", (*mqlOciAiDataScience).GetNotebookSessions)
}

func (o *mqlOciAiDataScienceNotebookSession) id() (string, error) {
	return "oci.ai.dataScience.notebookSession/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceNotebookSession) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataScienceNotebookSession) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

func (o *mqlOciAiDataScienceNotebookSession) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciNetworkSubnet), nil
}

// ----- models -----

func (o *mqlOciAiDataScience) models() ([]any, error) {
	return o.listRegional(o.fetchModels)
}

func (o *mqlOciAiDataScience) fetchModels(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.ModelSummary, *string, error) {
		resp, err := svc.ListModels(ctx, datascience.ListModelsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		m := items[i]
		mqlModel, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.model", map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(m.Id),
			"name":                llx.StringDataPtr(m.DisplayName),
			"compartmentID":       llx.StringDataPtr(m.CompartmentId),
			"projectID":           llx.StringDataPtr(m.ProjectId),
			"createdBy":           llx.StringDataPtr(m.CreatedBy),
			"modelVersionSetID":   llx.StringDataPtr(m.ModelVersionSetId),
			"modelVersionSetName": llx.StringDataPtr(m.ModelVersionSetName),
			"versionId":           llx.IntDataPtr(m.VersionId),
			"versionLabel":        llx.StringDataPtr(m.VersionLabel),
			"category":            llx.StringData(string(m.Category)),
			"isModelByReference":  llx.BoolDataPtr(m.IsModelByReference),
			"state":               llx.StringData(string(m.LifecycleState)),
			"lifecycleDetails":    llx.StringDataPtr(m.LifecycleDetails),
			"created":             sdkTimeData(m.TimeCreated),
			"freeformTags":        llx.MapData(strMapToAny(m.FreeformTags), types.String),
			"definedTags":         llx.MapData(definedTagsToAny(m.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlModelTyped := mqlModel.(*mqlOciAiDataScienceModel)
		mqlModelTyped.cacheProjectID = stringValue(m.ProjectId)
		mqlModelTyped.cacheModelVersionSetID = stringValue(m.ModelVersionSetId)
		res = append(res, mqlModelTyped)
	}
	return res, nil
}

type mqlOciAiDataScienceModelInternal struct {
	cacheProjectID         string
	cacheModelVersionSetID string
}

func initOciAiDataScienceModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.model", (*mqlOciAiDataScience).GetModels)
}

func (o *mqlOciAiDataScienceModel) id() (string, error) {
	return "oci.ai.dataScience.model/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceModel) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataScienceModel) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

func (o *mqlOciAiDataScienceModel) modelVersionSet() (*mqlOciAiDataScienceModelVersionSet, error) {
	if o.cacheModelVersionSetID == "" {
		o.ModelVersionSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.ai.dataScience.modelVersionSet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheModelVersionSetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiDataScienceModelVersionSet), nil
}

// ----- model version sets -----

func (o *mqlOciAiDataScience) modelVersionSets() ([]any, error) {
	return o.listRegional(o.fetchModelVersionSets)
}

func (o *mqlOciAiDataScience) fetchModelVersionSets(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.ModelVersionSetSummary, *string, error) {
		resp, err := svc.ListModelVersionSets(ctx, datascience.ListModelVersionSetsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		mvs := items[i]
		mqlSet, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.modelVersionSet", map[string]*llx.RawData{
			"id":            llx.StringDataPtr(mvs.Id),
			"name":          llx.StringDataPtr(mvs.Name),
			"compartmentID": llx.StringDataPtr(mvs.CompartmentId),
			"projectID":     llx.StringDataPtr(mvs.ProjectId),
			"createdBy":     llx.StringDataPtr(mvs.CreatedBy),
			"category":      llx.StringData(string(mvs.Category)),
			"state":         llx.StringData(string(mvs.LifecycleState)),
			"created":       sdkTimeData(mvs.TimeCreated),
			"timeUpdated":   sdkTimeData(mvs.TimeUpdated),
			"freeformTags":  llx.MapData(strMapToAny(mvs.FreeformTags), types.String),
			"definedTags":   llx.MapData(definedTagsToAny(mvs.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlSetTyped := mqlSet.(*mqlOciAiDataScienceModelVersionSet)
		mqlSetTyped.cacheProjectID = stringValue(mvs.ProjectId)
		res = append(res, mqlSetTyped)
	}
	return res, nil
}

type mqlOciAiDataScienceModelVersionSetInternal struct {
	cacheProjectID string
}

func initOciAiDataScienceModelVersionSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.modelVersionSet", (*mqlOciAiDataScience).GetModelVersionSets)
}

func (o *mqlOciAiDataScienceModelVersionSet) id() (string, error) {
	return "oci.ai.dataScience.modelVersionSet/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceModelVersionSet) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataScienceModelVersionSet) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

// ----- model deployments -----

func (o *mqlOciAiDataScience) modelDeployments() ([]any, error) {
	return o.listRegional(o.fetchModelDeployments)
}

func (o *mqlOciAiDataScience) fetchModelDeployments(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.ModelDeploymentSummary, *string, error) {
		resp, err := svc.ListModelDeployments(ctx, datascience.ListModelDeploymentsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		md := items[i]

		configuration, err := convert.JsonToDict(md.ModelDeploymentConfigurationDetails)
		if err != nil {
			return nil, err
		}
		logging, err := convert.JsonToDict(md.CategoryLogDetails)
		if err != nil {
			return nil, err
		}

		mqlDeployment, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.modelDeployment", map[string]*llx.RawData{
			"id":                   llx.StringDataPtr(md.Id),
			"name":                 llx.StringDataPtr(md.DisplayName),
			"compartmentID":        llx.StringDataPtr(md.CompartmentId),
			"projectID":            llx.StringDataPtr(md.ProjectId),
			"createdBy":            llx.StringDataPtr(md.CreatedBy),
			"description":          llx.StringDataPtr(md.Description),
			"modelDeploymentUrl":   llx.StringDataPtr(md.ModelDeploymentUrl),
			"configuration":        llx.DictData(configuration),
			"loggingConfiguration": llx.DictData(logging),
			"state":                llx.StringData(string(md.LifecycleState)),
			"created":              sdkTimeData(md.TimeCreated),
			"freeformTags":         llx.MapData(strMapToAny(md.FreeformTags), types.String),
			"definedTags":          llx.MapData(definedTagsToAny(md.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlDeploymentTyped := mqlDeployment.(*mqlOciAiDataScienceModelDeployment)
		mqlDeploymentTyped.cacheProjectID = stringValue(md.ProjectId)
		res = append(res, mqlDeploymentTyped)
	}
	return res, nil
}

type mqlOciAiDataScienceModelDeploymentInternal struct {
	cacheProjectID string
}

func initOciAiDataScienceModelDeployment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.modelDeployment", (*mqlOciAiDataScience).GetModelDeployments)
}

func (o *mqlOciAiDataScienceModelDeployment) id() (string, error) {
	return "oci.ai.dataScience.modelDeployment/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceModelDeployment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataScienceModelDeployment) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

// ----- jobs -----

func (o *mqlOciAiDataScience) jobs() ([]any, error) {
	return o.listRegional(o.fetchJobs)
}

func (o *mqlOciAiDataScience) fetchJobs(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.JobSummary, *string, error) {
		resp, err := svc.ListJobs(ctx, datascience.ListJobsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		j := items[i]
		mqlJob, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.job", map[string]*llx.RawData{
			"id":            llx.StringDataPtr(j.Id),
			"name":          llx.StringDataPtr(j.DisplayName),
			"compartmentID": llx.StringDataPtr(j.CompartmentId),
			"projectID":     llx.StringDataPtr(j.ProjectId),
			"createdBy":     llx.StringDataPtr(j.CreatedBy),
			"state":         llx.StringData(string(j.LifecycleState)),
			"created":       sdkTimeData(j.TimeCreated),
			"freeformTags":  llx.MapData(strMapToAny(j.FreeformTags), types.String),
			"definedTags":   llx.MapData(definedTagsToAny(j.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlJobTyped := mqlJob.(*mqlOciAiDataScienceJob)
		mqlJobTyped.cacheProjectID = stringValue(j.ProjectId)
		res = append(res, mqlJobTyped)
	}
	return res, nil
}

type mqlOciAiDataScienceJobInternal struct {
	cacheProjectID string
}

func initOciAiDataScienceJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.job", (*mqlOciAiDataScience).GetJobs)
}

func (o *mqlOciAiDataScienceJob) id() (string, error) {
	return "oci.ai.dataScience.job/" + o.Id.Data, nil
}

func (o *mqlOciAiDataScienceJob) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataScienceJob) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

// ----- pipelines -----

func (o *mqlOciAiDataScience) pipelines() ([]any, error) {
	return o.listRegional(o.fetchPipelines)
}

func (o *mqlOciAiDataScience) fetchPipelines(svc *datascience.DataScienceClient, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]datascience.PipelineSummary, *string, error) {
		resp, err := svc.ListPipelines(ctx, datascience.ListPipelinesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		p := items[i]
		mqlPipeline, err := CreateResource(o.MqlRuntime, "oci.ai.dataScience.pipeline", map[string]*llx.RawData{
			"id":            llx.StringDataPtr(p.Id),
			"name":          llx.StringDataPtr(p.DisplayName),
			"compartmentID": llx.StringDataPtr(p.CompartmentId),
			"projectID":     llx.StringDataPtr(p.ProjectId),
			"createdBy":     llx.StringDataPtr(p.CreatedBy),
			"state":         llx.StringData(string(p.LifecycleState)),
			"created":       sdkTimeData(p.TimeCreated),
			"timeUpdated":   sdkTimeData(p.TimeUpdated),
			"freeformTags":  llx.MapData(strMapToAny(p.FreeformTags), types.String),
			"definedTags":   llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlPipelineTyped := mqlPipeline.(*mqlOciAiDataSciencePipeline)
		mqlPipelineTyped.cacheProjectID = stringValue(p.ProjectId)
		res = append(res, mqlPipelineTyped)
	}
	return res, nil
}

type mqlOciAiDataSciencePipelineInternal struct {
	cacheProjectID string
}

func initOciAiDataSciencePipeline(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciDataScienceByID(runtime, args, "oci.ai.dataScience.pipeline", (*mqlOciAiDataScience).GetPipelines)
}

func (o *mqlOciAiDataSciencePipeline) id() (string, error) {
	return "oci.ai.dataScience.pipeline/" + o.Id.Data, nil
}

func (o *mqlOciAiDataSciencePipeline) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiDataSciencePipeline) project() (*mqlOciAiDataScienceProject, error) {
	return resolveOciDataScienceProject(o.MqlRuntime, o.cacheProjectID, &o.Project)
}

// ----- helpers -----

// findOciDataScienceByID powers the init functions for Data Science resources:
// it lists the requested collection and returns the entry whose id matches the
// "id" argument, so a resource can be selected directly by OCID.
func findOciDataScienceByID(runtime *plugin.Runtime, args map[string]*llx.RawData, resourceName string, list func(svc *mqlOciAiDataScience) *plugin.TValue[[]any]) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.dataScience", nil)
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlOciAiDataScience)
	items := list(svc)
	if items.Error != nil {
		return nil, nil, items.Error
	}
	for _, raw := range items.Data {
		res := raw.(plugin.Resource)
		if res.MqlID() == "" {
			continue
		}
		if idField, ok := raw.(interface{ GetId() *plugin.TValue[string] }); ok && idField.GetId().Data == idVal {
			return args, res, nil
		}
	}
	return nil, nil, errors.New(resourceName + " not found: " + idVal)
}

// resolveOciDataScienceProject resolves a typed project resource from a project
// OCID. Returns (nil, nil) and marks the field null when the OCID is empty.
func resolveOciDataScienceProject(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciAiDataScienceProject]) (*mqlOciAiDataScienceProject, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "oci.ai.dataScience.project", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiDataScienceProject), nil
}

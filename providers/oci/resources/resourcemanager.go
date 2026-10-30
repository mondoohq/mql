// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/oracle/oci-go-sdk/v65/resourcemanager"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciResourceManager) id() (string, error) {
	return "oci.resourceManager", nil
}

func (o *mqlOciResourceManager) stacks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.ResourceManagerClient(region)
			if err != nil {
				return nil, err
			}

			stacks, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]resourcemanager.StackSummary, *string, error) {
				response, err := client.ListStacks(ctx, resourcemanager.ListStacksRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(stacks))
			for i := range stacks {
				s := stacks[i]

				mqlStack, err := CreateResource(o.MqlRuntime, "oci.resourceManager.stack", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(s.Id),
					"name":             llx.StringDataPtr(s.DisplayName),
					"description":      llx.StringDataPtr(s.Description),
					"terraformVersion": llx.StringDataPtr(s.TerraformVersion),
					"state":            llx.StringData(string(s.LifecycleState)),
					"created":          sdkTimeData(s.TimeCreated),
					"freeformTags":     llx.MapData(strMapToAny(s.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(s.DefinedTags), types.Any),
					"systemTags":       llx.MapData(definedTagsToAny(s.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlStackTyped := mqlStack.(*mqlOciResourceManagerStack)
				mqlStackTyped.cacheCompartmentID = stringValue(s.CompartmentId)
				mqlStackTyped.cacheRegion = region
				res = append(res, mqlStackTyped)
			}

			return res, nil
		})
}

// Drift status, the config source and the variable names are all detail-only,
// so they share one fetch.
type mqlOciResourceManagerStackInternal struct {
	cacheCompartmentID string
	cacheRegion        string

	detail ociLazy[*resourcemanager.Stack]
}

func (o *mqlOciResourceManagerStack) id() (string, error) {
	return "oci.resourceManager.stack/" + o.Id.Data, nil
}

func (o *mqlOciResourceManagerStack) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciResourceManagerStack) getDetail() (*resourcemanager.Stack, error) {
	return o.detail.get(func() (*resourcemanager.Stack, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.ResourceManagerClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetStack(context.Background(), resourcemanager.GetStackRequest{
			StackId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.Stack, nil
	})
}

func (o *mqlOciResourceManagerStack) driftStatus() (string, error) {
	detail, err := o.getDetail()
	if err != nil {
		return "", err
	}
	// An unset drift status means drift has never been evaluated, which is a
	// distinct answer from IN_SYNC and must not be reported as an empty string.
	if detail.StackDriftStatus == "" {
		return string(resourcemanager.StackStackDriftStatusNotChecked), nil
	}
	return string(detail.StackDriftStatus), nil
}

func (o *mqlOciResourceManagerStack) driftLastChecked() (*time.Time, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if detail.TimeDriftLastChecked == nil {
		return nil, nil
	}
	return &detail.TimeDriftLastChecked.Time, nil
}

func (o *mqlOciResourceManagerStack) configSource() (any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if detail.ConfigSource == nil {
		return nil, nil
	}
	return convert.JsonToDict(detail.ConfigSource)
}

// variableNames returns the names of a stack's Terraform variables, never the
// values.
//
// Resource Manager stores variable values as plain strings with no sensitivity
// marking of any kind, and stacks routinely carry database passwords, API
// tokens and private keys in them. Returning the values would copy every one of
// those secrets into the scan result and anywhere that result is stored. The
// names alone answer the auditable question - whether a stack is carrying
// credentials it should be sourcing from Vault.
func (o *mqlOciResourceManagerStack) variableNames() ([]any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(detail.Variables))
	for name := range detail.Variables {
		names = append(names, name)
	}
	// Go randomizes map iteration; sort so the list is stable across queries.
	sort.Strings(names)

	return stringsToAny(names), nil
}

func (o *mqlOciResourceManagerStack) isThirdPartyProviderExperienceEnabled() (bool, error) {
	detail, err := o.getDetail()
	if err != nil {
		return false, err
	}
	return boolValue(detail.IsThirdPartyProviderExperienceEnabled), nil
}

func (o *mqlOciResourceManagerStack) jobs() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.ResourceManagerClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	jobs, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]resourcemanager.JobSummary, *string, error) {
		response, err := client.ListJobs(ctx, resourcemanager.ListJobsRequest{
			StackId: new(o.Id.Data),
			Page:    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(jobs))
	for i := range jobs {
		job := jobs[i]

		mqlJob, err := CreateResource(o.MqlRuntime, "oci.resourceManager.job", map[string]*llx.RawData{
			"id":           llx.StringDataPtr(job.Id),
			"name":         llx.StringDataPtr(job.DisplayName),
			"operation":    llx.StringData(string(job.Operation)),
			"state":        llx.StringData(string(job.LifecycleState)),
			"created":      sdkTimeData(job.TimeCreated),
			"finished":     sdkTimeData(job.TimeFinished),
			"freeformTags": llx.MapData(strMapToAny(job.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(job.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlJobTyped := mqlJob.(*mqlOciResourceManagerJob)
		mqlJobTyped.cacheCompartmentID = stringValue(job.CompartmentId)
		mqlJobTyped.cacheStackID = stringValue(job.StackId)
		res = append(res, mqlJobTyped)
	}

	return res, nil
}

type mqlOciResourceManagerJobInternal struct {
	cacheCompartmentID string
	cacheStackID       string
}

func (o *mqlOciResourceManagerJob) id() (string, error) {
	return "oci.resourceManager.job/" + o.Id.Data, nil
}

func (o *mqlOciResourceManagerJob) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciResourceManagerJob) stack() (*mqlOciResourceManagerStack, error) {
	if o.cacheStackID == "" {
		o.Stack.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.resourceManager.stack", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheStackID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciResourceManagerStack), nil
}

// initOciResourceManagerStack resolves a stack by OCID.
//
// The job accessor above reaches a stack by id, and without an init
// NewResource would build one from that id alone: correct cache key, every
// other field unset, and a detail fetch pointed at no region. Resolving
// through the stack listing hands back the populated resource instead.
func initOciResourceManagerStack(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.resourceManager.stack")
	}

	obj, err := CreateResource(runtime, "oci.resourceManager", nil)
	if err != nil {
		return nil, nil, err
	}
	rm := obj.(*mqlOciResourceManager)

	rawStacks := rm.GetStacks()
	if rawStacks.Error != nil {
		return nil, nil, rawStacks.Error
	}

	for _, raw := range rawStacks.Data {
		stack := raw.(*mqlOciResourceManagerStack)
		if stack.Id.Data == idVal {
			return args, stack, nil
		}
	}

	return nil, nil, errors.New("oci.resourceManager.stack not found: " + idVal)
}

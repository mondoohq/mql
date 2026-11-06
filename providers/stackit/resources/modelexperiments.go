// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	modelexperiments "github.com/stackitcloud/stackit-sdk-go/services/modelexperiments/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlStackitModelExperimentsInstanceInternal struct {
	// cacheBucketName holds the artifact bucket name so bucket() can resolve
	// it against the Object Storage bucket list.
	cacheBucketName string
}

func modelExperimentsInstanceArgs(i *modelexperiments.Instance) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                         llx.StringData(i.GetId()),
		"name":                       llx.StringData(i.GetName()),
		"description":                llx.StringData(i.GetDescription()),
		"url":                        llx.StringData(i.GetUrl()),
		"deletedExperimentRetention": llx.StringData(i.GetDeletedExperimentRetention()),
		"state":                      llx.StringData(string(i.GetState())),
		"errorMessage":               llx.StringData(i.GetErrorMessage()),
		"region":                     llx.StringData(i.GetRegion()),
		"labels":                     labelData(i.GetLabels()),
	}
}

// modelExperimentsTokenArgs maps token metadata to resource args. The list
// endpoint returns TokenMetadata, which carries no secret content.
func modelExperimentsTokenArgs(t *modelexperiments.TokenMetadata) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":          llx.StringData(t.GetId()),
		"name":        llx.StringData(t.GetName()),
		"description": llx.StringData(t.GetDescription()),
		"state":       llx.StringData(string(t.GetState())),
		"region":      llx.StringData(t.GetRegion()),
		"validUntil":  llx.TimeDataPtr(timeOrNil(t.GetValidUntilOk())),
		"labels":      labelData(t.GetLabels()),
	}
}

func (r *mqlStackitModelExperiments) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ModelExperiments()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetInstances()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.modelExperiments.instance", modelExperimentsInstanceArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		inst := res.(*mqlStackitModelExperimentsInstance)
		inst.cacheBucketName = items[i].GetBucketName()
		out = append(out, inst)
	}
	return out, nil
}

func (r *mqlStackitModelExperimentsInstance) id() (string, error) {
	return "stackit.modelExperiments.instance/" + r.Id.Data, nil
}

func (r *mqlStackitModelExperimentsInstance) bucket() (*mqlStackitObjectStorageBucket, error) {
	return objectStorageBucketRef(r.MqlRuntime, r.cacheBucketName, &r.Bucket)
}

func (r *mqlStackitModelExperimentsInstance) tokens() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ModelExperiments()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstanceTokens(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	tokens := resp.GetTokens()
	out := make([]any, 0, len(tokens))
	for i := range tokens {
		args := modelExperimentsTokenArgs(&tokens[i])
		args["__id"] = llx.StringData(qualifiedId("stackit.modelExperiments.instance.token", r.Id.Data, tokens[i].GetId()))
		res, err := CreateResource(r.MqlRuntime, "stackit.modelExperiments.instance.token", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// objectStorageBucketRef resolves a bucket by name through the project's
// cached bucket list, marking the field null when the name is empty or the
// list does not carry the bucket.
func objectStorageBucketRef(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlStackitObjectStorageBucket]) (*mqlStackitObjectStorageBucket, error) {
	if name == "" {
		return markNull[mqlStackitObjectStorageBucket](field)
	}
	ns, err := makeNamespace(runtime, "stackit.objectStorage")
	if err != nil {
		return nil, err
	}
	buckets := ns.(*mqlStackitObjectStorage).GetBuckets()
	if buckets.Error != nil {
		return nil, buckets.Error
	}
	if b := findBucket(buckets.Data, name); b != nil {
		return b, nil
	}
	return markNull[mqlStackitObjectStorageBucket](field)
}

func findBucket(buckets []any, name string) *mqlStackitObjectStorageBucket {
	for _, item := range buckets {
		if b, ok := item.(*mqlStackitObjectStorageBucket); ok && b.Name.Data == name {
			return b
		}
	}
	return nil
}

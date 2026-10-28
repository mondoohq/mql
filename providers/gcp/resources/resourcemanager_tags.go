// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

const (
	tagKeyResourceName   = "gcp.organization.tagKey"
	tagValueResourceName = "gcp.organization.tagValue"
)

// resourceManagerClient returns the HTTP client for Resource Manager calls.
// Each caller builds its own service from it with NewService, which is what
// the permissions extractor recognizes to attribute the calls made on it.
func resourceManagerClient(runtime *plugin.Runtime) (*http.Client, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope)
}

// policyBindings converts the bindings of an IAM policy into
// gcp.resourcemanager.binding resources. parent is the resource name the
// policy belongs to; it keys each binding together with its position.
func policyBindings(runtime *plugin.Runtime, parent string, policy *cloudresourcemanager.Policy) ([]any, error) {
	if policy == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(policy.Bindings))
	for i, b := range policy.Bindings {
		if b == nil {
			continue
		}
		condTitle, condExpr, condDesc := "", "", ""
		if b.Condition != nil {
			condTitle = b.Condition.Title
			condExpr = b.Condition.Expression
			condDesc = b.Condition.Description
		}
		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(parent + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(condTitle),
			"conditionExpression":  llx.StringData(condExpr),
			"conditionDescription": llx.StringData(condDesc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func tagKeyArgs(k *cloudresourcemanager.TagKey) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":               llx.StringData(k.Name),
		"shortName":          llx.StringData(k.ShortName),
		"namespacedName":     llx.StringData(k.NamespacedName),
		"description":        llx.StringData(k.Description),
		"purpose":            llx.StringData(k.Purpose),
		"purposeData":        llx.MapData(convert.MapToInterfaceMap(k.PurposeData), types.String),
		"allowedValuesRegex": llx.StringData(k.AllowedValuesRegex),
		"createTime":         llx.TimeDataPtr(parseTime(k.CreateTime)),
		"updateTime":         llx.TimeDataPtr(parseTime(k.UpdateTime)),
	}
}

func tagValueArgs(v *cloudresourcemanager.TagValue) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":           llx.StringData(v.Name),
		"shortName":      llx.StringData(v.ShortName),
		"namespacedName": llx.StringData(v.NamespacedName),
		"description":    llx.StringData(v.Description),
		"createTime":     llx.TimeDataPtr(parseTime(v.CreateTime)),
		"updateTime":     llx.TimeDataPtr(parseTime(v.UpdateTime)),
	}
}

func newMqlTagKey(runtime *plugin.Runtime, k *cloudresourcemanager.TagKey) (*mqlGcpOrganizationTagKey, error) {
	res, err := CreateResource(runtime, tagKeyResourceName, tagKeyArgs(k))
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpOrganizationTagKey), nil
}

func newMqlTagValue(runtime *plugin.Runtime, v *cloudresourcemanager.TagValue) (*mqlGcpOrganizationTagValue, error) {
	res, err := CreateResource(runtime, tagValueResourceName, tagValueArgs(v))
	if err != nil {
		return nil, err
	}
	mqlValue := res.(*mqlGcpOrganizationTagValue)
	mqlValue.cacheTagKeyName = v.Parent
	return mqlValue, nil
}

// listTagKeys lists the tag keys whose parent is organizations/{id} or
// projects/{id}.
func listTagKeys(runtime *plugin.Runtime, parent string) ([]any, error) {
	client, err := resourceManagerClient(runtime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	res := []any{}
	err = svc.TagKeys.List().Parent(parent).Pages(context.Background(), func(page *cloudresourcemanager.ListTagKeysResponse) error {
		for _, k := range page.TagKeys {
			if k == nil {
				continue
			}
			mqlKey, err := newMqlTagKey(runtime, k)
			if err != nil {
				return err
			}
			res = append(res, mqlKey)
		}
		return nil
	})
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagKeys.list"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpOrganization) tagKeys() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listTagKeys(g.MqlRuntime, organizationResourceName(g.Id.Data))
}

func (g *mqlGcpProject) tagKeys() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	return listTagKeys(g.MqlRuntime, "projects/"+g.Id.Data)
}

// Tag keys

func (g *mqlGcpOrganizationTagKey) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func initGcpOrganizationTagKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameArg, ok := args["name"]
	if !ok || nameArg == nil {
		return nil, nil, errors.New("gcp.organization.tagKey requires a name (e.g. tagKeys/123)")
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("gcp.organization.tagKey requires a name (e.g. tagKeys/123)")
	}
	if cached := cachedResource(runtime, tagKeyResourceName, name); cached != nil {
		return nil, cached, nil
	}

	client, err := resourceManagerClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}
	k, err := svc.TagKeys.Get(name).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagKeys.get"); rerr != nil {
			return nil, nil, rerr
		}
		return nil, nil, fmt.Errorf("gcp.organization.tagKey with name %q not found: %w", name, err)
	}
	return tagKeyArgs(k), nil, nil
}

func (g *mqlGcpOrganizationTagKey) values() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	res := []any{}
	err = svc.TagValues.List().Parent(g.Name.Data).Pages(context.Background(), func(page *cloudresourcemanager.ListTagValuesResponse) error {
		for _, v := range page.TagValues {
			if v == nil {
				continue
			}
			mqlValue, err := newMqlTagValue(g.MqlRuntime, v)
			if err != nil {
				return err
			}
			res = append(res, mqlValue)
		}
		return nil
	})
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagValues.list"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpOrganizationTagKey) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.TagKeys.GetIamPolicy(g.Name.Data, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagKeys.getIamPolicy"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return policyBindings(g.MqlRuntime, g.Name.Data, policy)
}

// Tag values

type mqlGcpOrganizationTagValueInternal struct {
	// cacheTagKeyName is the parent of the tag value, the resource name of
	// its tag key (tagKeys/123).
	cacheTagKeyName string
}

func (g *mqlGcpOrganizationTagValue) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func initGcpOrganizationTagValue(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameArg, ok := args["name"]
	if !ok || nameArg == nil {
		return nil, nil, errors.New("gcp.organization.tagValue requires a name (e.g. tagValues/456)")
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("gcp.organization.tagValue requires a name (e.g. tagValues/456)")
	}
	if cached := cachedResource(runtime, tagValueResourceName, name); cached != nil {
		return nil, cached, nil
	}

	client, err := resourceManagerClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}
	v, err := svc.TagValues.Get(name).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagValues.get"); rerr != nil {
			return nil, nil, rerr
		}
		return nil, nil, fmt.Errorf("gcp.organization.tagValue with name %q not found: %w", name, err)
	}
	// Build through CreateResource so the parent key name lands on the
	// internal struct, which init args cannot carry.
	res, err := newMqlTagValue(runtime, v)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (g *mqlGcpOrganizationTagValue) tagKey() (*mqlGcpOrganizationTagKey, error) {
	if g.cacheTagKeyName == "" {
		g.TagKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, tagKeyResourceName, map[string]*llx.RawData{
		"name": llx.StringData(g.cacheTagKeyName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpOrganizationTagKey), nil
}

func (g *mqlGcpOrganizationTagValue) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.TagValues.GetIamPolicy(g.Name.Data, &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagValues.getIamPolicy"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return policyBindings(g.MqlRuntime, g.Name.Data, policy)
}

// Tag bindings

func (g *mqlGcpProjectTagBinding) value() (*mqlGcpOrganizationTagValue, error) {
	if g.TagValue.Error != nil {
		return nil, g.TagValue.Error
	}
	if g.TagValue.Data == "" {
		g.Value.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, tagValueResourceName, map[string]*llx.RawData{
		"name": llx.StringData(g.TagValue.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpOrganizationTagValue), nil
}

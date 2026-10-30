// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless/document"
	aosstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// aossBatchGetCollectionLimit is the most collection IDs BatchGetCollection
// accepts in one request.
const aossBatchGetCollectionLimit = 100

func (a *mqlAwsOpensearchserverless) id() (string, error) {
	return "aws.opensearchserverless", nil
}

// aossTime converts the epoch-millisecond timestamps OpenSearch Serverless
// reports, keeping an absent value null rather than the Unix epoch.
func aossTime(ms *int64) *time.Time {
	if ms == nil {
		return nil
	}
	t := time.UnixMilli(*ms).UTC()
	return &t
}

// aossKmsKeyArn returns the collection's KMS key ARN, or nil when the
// collection uses an AWS owned key, which the service reports as a
// placeholder rather than an ARN.
func aossKmsKeyArn(v *string) *string {
	if v == nil || !strings.HasPrefix(*v, "arn:") {
		return nil
	}
	return v
}

func (a *mqlAwsOpensearchserverless) collections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "opensearchserverless", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.OpenSearchServerless(region)
		ids := []string{}
		paginator := opensearchserverless.NewListCollectionsPaginator(svc, &opensearchserverless.ListCollectionsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, c := range page.CollectionSummaries {
				if c.Id != nil && *c.Id != "" {
					ids = append(ids, *c.Id)
				}
			}
		}

		res := []any{}
		for _, batch := range chunkStrings(ids, aossBatchGetCollectionLimit) {
			out, err := svc.BatchGetCollection(ctx, &opensearchserverless.BatchGetCollectionInput{Ids: batch})
			if err != nil {
				return nil, err
			}
			for _, detail := range out.CollectionDetails {
				mqlCollection, err := newMqlAossCollection(a.MqlRuntime, region, detail)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlCollection)
			}
		}
		return res, nil
	})
}

func newMqlAossCollection(runtime *plugin.Runtime, region string, c aosstypes.CollectionDetail) (*mqlAwsOpensearchserverlessCollection, error) {
	res, err := CreateResource(runtime, ResourceAwsOpensearchserverlessCollection, map[string]*llx.RawData{
		"__id":                      llx.StringDataPtr(c.Arn),
		"arn":                       llx.StringDataPtr(c.Arn),
		"id":                        llx.StringDataPtr(c.Id),
		"name":                      llx.StringDataPtr(c.Name),
		"region":                    llx.StringData(region),
		"status":                    llx.StringDataPtr(nonEmptyEnum(c.Status)),
		"type":                      llx.StringDataPtr(nonEmptyEnum(c.Type)),
		"description":               llx.StringDataPtr(c.Description),
		"collectionEndpoint":        llx.StringDataPtr(c.CollectionEndpoint),
		"dashboardEndpoint":         llx.StringDataPtr(c.DashboardEndpoint),
		"standbyReplicasEnabled":    llx.BoolData(c.StandbyReplicas == aosstypes.StandbyReplicasEnabled),
		"deletionProtectionEnabled": llx.BoolData(c.DeletionProtection == aosstypes.DeletionProtectionEnabled),
		"collectionGroupName":       llx.StringDataPtr(c.CollectionGroupName),
		"createdAt":                 llx.TimeDataPtr(aossTime(c.CreatedDate)),
		"updatedAt":                 llx.TimeDataPtr(aossTime(c.LastModifiedDate)),
	})
	if err != nil {
		return nil, err
	}
	mqlCollection := res.(*mqlAwsOpensearchserverlessCollection)
	mqlCollection.cacheKmsKeyArn = aossKmsKeyArn(c.KmsKeyArn)
	return mqlCollection, nil
}

type mqlAwsOpensearchserverlessCollectionInternal struct {
	cacheKmsKeyArn *string
}

func (a *mqlAwsOpensearchserverlessCollection) id() (string, error) {
	return a.Arn.Data, nil
}

// initAwsOpensearchserverlessCollection resolves a collection from its ARN,
// for the references other resources hold, such as a Bedrock knowledge base
// vector store.
func initAwsOpensearchserverlessCollection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws opensearchserverless collection")
	}
	if cached := cachedArgByArn(runtime, ResourceAwsOpensearchserverlessCollection, args); cached != nil {
		return args, cached, nil
	}
	collectionArn, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	region, collectionID, err := aossCollectionFromArn(collectionArn)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.OpenSearchServerless(region)
	out, err := svc.BatchGetCollection(context.Background(), &opensearchserverless.BatchGetCollectionInput{
		Ids: []string{collectionID},
	})
	if err != nil {
		return nil, nil, err
	}
	for _, detail := range out.CollectionDetails {
		if convert.ToValue(detail.Id) == collectionID {
			res, err := newMqlAossCollection(runtime, region, detail)
			if err != nil {
				return nil, nil, err
			}
			return args, res, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.opensearchserverless.collection with arn %q not found", collectionArn)
}

// aossCollectionFromArn splits a collection ARN of the form
// arn:aws:aoss:<region>:<account>:collection/<id>.
func aossCollectionFromArn(collectionArn string) (region, id string, err error) {
	parsed, err := arn.Parse(collectionArn)
	if err != nil {
		return "", "", err
	}
	id, ok := strings.CutPrefix(parsed.Resource, "collection/")
	if !ok || id == "" || parsed.Region == "" {
		return "", "", fmt.Errorf("not an OpenSearch Serverless collection ARN: %q", collectionArn)
	}
	return parsed.Region, id, nil
}

func (a *mqlAwsOpensearchserverlessCollection) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKeyArn, a.Region.Data, &a.KmsKey.State)
}

func (a *mqlAwsOpensearchserverlessCollection) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.OpenSearchServerless(a.Region.Data)
	collectionArn := a.Arn.Data
	out, err := svc.ListTagsForResource(context.Background(), &opensearchserverless.ListTagsForResourceInput{
		ResourceArn: &collectionArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.Tags.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("aoss:ListTagsForResource"))
		}
		return nil, err
	}
	res := map[string]any{}
	for _, t := range out.Tags {
		if t.Key != nil {
			res[*t.Key] = convert.ToValue(t.Value)
		}
	}
	return res, nil
}

// --- policy documents ---

// decodeAossPolicy turns a policy document into plain JSON values (maps,
// slices, strings, bools, float64 numbers), the shapes a dict field carries.
func decodeAossPolicy(doc document.Interface) (any, error) {
	if doc == nil {
		return nil, nil
	}
	raw, err := doc.MarshalSmithyDocument()
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// aossPolicyEntries returns the rule sets of a policy document. Network and
// data access policies are lists of rule sets; an encryption policy is a single
// one.
func aossPolicyEntries(doc any) []map[string]any {
	switch v := doc.(type) {
	case []any:
		res := make([]map[string]any, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				res = append(res, m)
			}
		}
		return res
	case map[string]any:
		return []map[string]any{v}
	default:
		return nil
	}
}

// stringSet collects strings in order of first appearance without repeats.
type stringSet struct {
	seen  map[string]struct{}
	items []any
}

func (s *stringSet) add(v any) {
	switch x := v.(type) {
	case string:
		if s.seen == nil {
			s.seen = map[string]struct{}{}
		}
		if _, ok := s.seen[x]; ok {
			return
		}
		s.seen[x] = struct{}{}
		s.items = append(s.items, x)
	case []any:
		for _, e := range x {
			s.add(e)
		}
	}
}

func (s *stringSet) list() []any {
	if s.items == nil {
		return []any{}
	}
	return s.items
}

// aossPolicySummary is what the derived policy fields read from a document.
type aossPolicySummary struct {
	resources       []any
	permissions     []any
	principals      []any
	allowFromPublic bool
	sourceVpces     []any
	sourceServices  []any
	awsOwnedKey     *bool
	kmsKeyArn       string
}

func summarizeAossPolicy(doc any) aossPolicySummary {
	var resources, permissions, principals, vpces, services stringSet
	sum := aossPolicySummary{}
	for _, entry := range aossPolicyEntries(doc) {
		if rules, ok := entry["Rules"].([]any); ok {
			for _, r := range rules {
				rule, ok := r.(map[string]any)
				if !ok {
					continue
				}
				resources.add(rule["Resource"])
				permissions.add(rule["Permission"])
			}
		}
		principals.add(entry["Principal"])
		vpces.add(entry["SourceVPCEs"])
		services.add(entry["SourceServices"])
		if public, ok := entry["AllowFromPublic"].(bool); ok && public {
			sum.allowFromPublic = true
		}
		if owned, ok := entry["AWSOwnedKey"].(bool); ok {
			sum.awsOwnedKey = &owned
		}
		if key, ok := entry["KmsARN"].(string); ok && key != "" {
			sum.kmsKeyArn = key
		}
	}
	sum.resources = resources.list()
	sum.permissions = permissions.list()
	sum.principals = principals.list()
	sum.sourceVpces = vpces.list()
	sum.sourceServices = services.list()
	return sum
}

// aossPolicyCache reads a policy document once and shares it between the
// policy field and the fields derived from it. A nil document with a nil
// error means the document could not be read and structured errors are off.
type aossPolicyCache struct {
	lock    sync.Mutex
	fetched bool
	doc     any
	summary aossPolicySummary
}

func (c *aossPolicyCache) load(permission string, fetch func() (document.Interface, error)) (any, *aossPolicySummary, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.fetched {
		if c.doc == nil {
			return nil, nil, nil
		}
		return c.doc, &c.summary, nil
	}
	raw, err := fetch()
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				c.fetched = true
				return nil, nil, nil
			}
			return nil, nil, llx.Forbidden(err, llx.WithPermissions(permission))
		}
		return nil, nil, err
	}
	doc, err := decodeAossPolicy(raw)
	if err != nil {
		return nil, nil, err
	}
	c.doc = doc
	c.summary = summarizeAossPolicy(doc)
	c.fetched = true
	if c.doc == nil {
		return nil, nil, nil
	}
	return c.doc, &c.summary, nil
}

// --- security policies ---

func (a *mqlAwsOpensearchserverless) securityPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "opensearchserverless", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.OpenSearchServerless(region)
		res := []any{}
		for _, policyType := range []aosstypes.SecurityPolicyType{aosstypes.SecurityPolicyTypeNetwork, aosstypes.SecurityPolicyTypeEncryption} {
			paginator := opensearchserverless.NewListSecurityPoliciesPaginator(svc, &opensearchserverless.ListSecurityPoliciesInput{
				Type: policyType,
			})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, p := range page.SecurityPolicySummaries {
					name := convert.ToValue(p.Name)
					mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsOpensearchserverlessSecurityPolicy, map[string]*llx.RawData{
						"__id":          llx.StringData("aws.opensearchserverless.securityPolicy/" + region + "/" + string(policyType) + "/" + name),
						"name":          llx.StringData(name),
						"type":          llx.StringData(string(policyType)),
						"region":        llx.StringData(region),
						"description":   llx.StringDataPtr(p.Description),
						"policyVersion": llx.StringDataPtr(p.PolicyVersion),
						"createdAt":     llx.TimeDataPtr(aossTime(p.CreatedDate)),
						"updatedAt":     llx.TimeDataPtr(aossTime(p.LastModifiedDate)),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPolicy)
				}
			}
		}
		return res, nil
	})
}

type mqlAwsOpensearchserverlessSecurityPolicyInternal struct {
	policyCache aossPolicyCache
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) fetchPolicy() (any, *aossPolicySummary, error) {
	return a.policyCache.load("aoss:GetSecurityPolicy", func() (document.Interface, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.OpenSearchServerless(a.Region.Data)
		name := a.Name.Data
		out, err := svc.GetSecurityPolicy(context.Background(), &opensearchserverless.GetSecurityPolicyInput{
			Name: &name,
			Type: aosstypes.SecurityPolicyType(a.Type.Data),
		})
		if err != nil {
			return nil, err
		}
		if out.SecurityPolicyDetail == nil {
			return nil, nil
		}
		return out.SecurityPolicyDetail.Policy, nil
	})
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) isNetwork() bool {
	return a.Type.Data == string(aosstypes.SecurityPolicyTypeNetwork)
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) isEncryption() bool {
	return a.Type.Data == string(aosstypes.SecurityPolicyTypeEncryption)
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) policy() (any, error) {
	doc, _, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if doc == nil {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return doc, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) resources() ([]any, error) {
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if sum == nil {
		a.Resources.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sum.resources, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) allowFromPublic() (bool, error) {
	if !a.isNetwork() {
		a.AllowFromPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return false, err
	}
	if sum == nil {
		a.AllowFromPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return sum.allowFromPublic, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) sourceVpcEndpointIds() ([]any, error) {
	if !a.isNetwork() {
		a.SourceVpcEndpointIds.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if sum == nil {
		a.SourceVpcEndpointIds.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sum.sourceVpces, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) sourceServices() ([]any, error) {
	if !a.isNetwork() {
		a.SourceServices.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if sum == nil {
		a.SourceServices.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sum.sourceServices, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) awsOwnedKey() (bool, error) {
	if !a.isEncryption() {
		a.AwsOwnedKey.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return false, err
	}
	if sum == nil || sum.awsOwnedKey == nil {
		a.AwsOwnedKey.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *sum.awsOwnedKey, nil
}

func (a *mqlAwsOpensearchserverlessSecurityPolicy) kmsKey() (*mqlAwsKmsKey, error) {
	if !a.isEncryption() {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if sum == nil || sum.kmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveKmsKeyRef(a.MqlRuntime, &sum.kmsKeyArn, a.Region.Data, &a.KmsKey.State)
}

// --- access policies ---

func (a *mqlAwsOpensearchserverless) accessPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "opensearchserverless", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.OpenSearchServerless(region)
		res := []any{}
		paginator := opensearchserverless.NewListAccessPoliciesPaginator(svc, &opensearchserverless.ListAccessPoliciesInput{
			Type: aosstypes.AccessPolicyTypeData,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, p := range page.AccessPolicySummaries {
				name := convert.ToValue(p.Name)
				policyType := string(p.Type)
				if policyType == "" {
					policyType = string(aosstypes.AccessPolicyTypeData)
				}
				mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsOpensearchserverlessAccessPolicy, map[string]*llx.RawData{
					"__id":          llx.StringData("aws.opensearchserverless.accessPolicy/" + region + "/" + policyType + "/" + name),
					"name":          llx.StringData(name),
					"type":          llx.StringData(policyType),
					"region":        llx.StringData(region),
					"description":   llx.StringDataPtr(p.Description),
					"policyVersion": llx.StringDataPtr(p.PolicyVersion),
					"createdAt":     llx.TimeDataPtr(aossTime(p.CreatedDate)),
					"updatedAt":     llx.TimeDataPtr(aossTime(p.LastModifiedDate)),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlPolicy)
			}
		}
		return res, nil
	})
}

type mqlAwsOpensearchserverlessAccessPolicyInternal struct {
	policyCache aossPolicyCache
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) fetchPolicy() (any, *aossPolicySummary, error) {
	return a.policyCache.load("aoss:GetAccessPolicy", func() (document.Interface, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.OpenSearchServerless(a.Region.Data)
		name := a.Name.Data
		out, err := svc.GetAccessPolicy(context.Background(), &opensearchserverless.GetAccessPolicyInput{
			Name: &name,
			Type: aosstypes.AccessPolicyType(a.Type.Data),
		})
		if err != nil {
			return nil, err
		}
		if out.AccessPolicyDetail == nil {
			return nil, nil
		}
		return out.AccessPolicyDetail.Policy, nil
	})
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) policy() (any, error) {
	doc, _, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if doc == nil {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return doc, nil
}

// accessPolicyList reads one derived list off the access policy, null when
// the document could not be read.
func (a *mqlAwsOpensearchserverlessAccessPolicy) accessPolicyList(field *plugin.TValue[[]any], pick func(*aossPolicySummary) []any) ([]any, error) {
	_, sum, err := a.fetchPolicy()
	if err != nil {
		return nil, err
	}
	if sum == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pick(sum), nil
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) principals() ([]any, error) {
	return a.accessPolicyList(&a.Principals, func(s *aossPolicySummary) []any { return s.principals })
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) permissions() ([]any, error) {
	return a.accessPolicyList(&a.Permissions, func(s *aossPolicySummary) []any { return s.permissions })
}

func (a *mqlAwsOpensearchserverlessAccessPolicy) resources() ([]any, error) {
	return a.accessPolicyList(&a.Resources, func(s *aossPolicySummary) []any { return s.resources })
}

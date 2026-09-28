// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (g *mqlGcpProject) cloudTasks() (*mqlGcpProjectCloudTasksService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudTasksService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudTasksService), nil
}

func (g *mqlGcpProjectCloudTasksService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudTasksService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCloudTasksService) queues() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudtasks.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudtasks.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// The Cloud Tasks ListQueues API rejects the "projects/<p>/locations/-"
	// wildcard, so we enumerate the available locations first and list
	// queues in each one.
	locations, err := listCloudTasksLocations(ctx, client, projectId)
	if err != nil {
		return nil, err
	}

	cmek := &cloudTasksCmekCache{projectId: projectId, keys: map[string]string{}}
	var res []any
	for _, location := range locations {
		it := client.ListQueues(ctx, &cloudtaskspb.ListQueuesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location),
		})

		for {
			queue, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			rateLimits, err := cloudTasksConvertRateLimits(queue.RateLimits)
			if err != nil {
				return nil, err
			}
			retryConfig, err := cloudTasksRetryConfig(g.MqlRuntime, queue.Name, queue.RetryConfig)
			if err != nil {
				return nil, err
			}
			appEngineRouting, err := cloudTasksConvertAppEngineRouting(queue.AppEngineRoutingOverride)
			if err != nil {
				return nil, err
			}

			queueArgs := map[string]*llx.RawData{
				"projectId":                llx.StringData(projectId),
				"name":                     llx.StringData(queue.Name),
				"state":                    llx.StringData(queue.State.String()),
				"rateLimits":               llx.DictData(rateLimits),
				"appEngineRoutingOverride": llx.DictData(appEngineRouting),
			}
			if retryConfig != nil {
				queueArgs["retryConfig"] = llx.ResourceData(retryConfig, "gcp.retryConfig")
			}
			httpTarget, err := newCloudTasksHttpTarget(g.MqlRuntime, projectId, queue.Name, queue.HttpTarget)
			if err != nil {
				return nil, err
			}
			if httpTarget != nil {
				queueArgs["httpTarget"] = llx.ResourceData(httpTarget, "gcp.project.cloudTasksService.queue.httpTargetConfig")
			}
			mqlQueue, err := CreateResource(g.MqlRuntime, "gcp.project.cloudTasksService.queue", queueArgs)
			if err != nil {
				return nil, err
			}
			mqlQ := mqlQueue.(*mqlGcpProjectCloudTasksServiceQueue)
			if retryConfig == nil {
				mqlQ.RetryConfig.State = plugin.StateIsNull | plugin.StateIsSet
			}
			if httpTarget == nil {
				mqlQ.HttpTarget.State = plugin.StateIsNull | plugin.StateIsSet
			}
			mqlQ.cacheLocation = location
			mqlQ.cmek = cmek
			res = append(res, mqlQueue)
		}
	}

	return res, nil
}

// listCloudTasksLocations returns the location IDs where Cloud Tasks is
// available for the project. The Cloud Tasks ListQueues API rejects the
// "-" location wildcard, so queues must be listed per location.
func listCloudTasksLocations(ctx context.Context, client *cloudtasks.Client, projectId string) ([]string, error) {
	it := client.ListLocations(ctx, &locationpb.ListLocationsRequest{
		Name: fmt.Sprintf("projects/%s", projectId),
	})
	var locations []string
	for {
		l, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		locations = append(locations, l.LocationId)
	}
	return locations, nil
}

func (g *mqlGcpProjectCloudTasksServiceQueue) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudTasksService.queue/%s", g.ProjectId.Data, g.Name.Data), nil
}

type mqlGcpProjectCloudTasksServiceQueueInternal struct {
	cacheLocation string
	cmek          *cloudTasksCmekCache
}

// cloudTasksCmekCache holds the CMEK key per location for one project. Cloud
// Tasks configures CMEK per project and location, so every queue in a location
// shares one GetCmekConfig call.
type cloudTasksCmekCache struct {
	projectId string
	mu        sync.Mutex
	keys      map[string]string
}

func (c *cloudTasksCmekCache) kmsKeyName(runtime *plugin.Runtime, location string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key, ok := c.keys[location]; ok {
		return key, nil
	}

	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudtasks.DefaultAuthScopes()...)
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	client, err := cloudtasks.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return "", err
	}
	defer client.Close()

	cfg, err := client.GetCmekConfig(ctx, &cloudtaskspb.GetCmekConfigRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/cmekConfig", c.projectId, location),
	})
	if err != nil {
		if s, ok := grpcStatusOf(err); ok {
			switch s.Code() {
			case codes.NotFound:
				// No CMEK config exists for the location: Google-managed encryption.
				c.keys[location] = ""
				return "", nil
			case codes.PermissionDenied:
				if saysServiceDisabled(err) {
					return "", llx.NotApplicable(err)
				}
				return "", llx.Forbidden(err, llx.WithPermissions("cloudtasks.cmekConfig.get"))
			}
		}
		return "", err
	}
	c.keys[location] = cfg.GetKmsKey()
	return c.keys[location], nil
}

func (g *mqlGcpProjectCloudTasksServiceQueue) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cmek == nil || g.cacheLocation == "" {
		return nil, errors.New("cloud tasks queue was not created from a queue listing, cannot resolve its location")
	}
	keyName, err := g.cmek.kmsKeyName(g.MqlRuntime, g.cacheLocation)
	if err != nil {
		return nil, err
	}
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, keyName)
}

type mqlGcpProjectCloudTasksServiceQueueHttpTargetConfigInternal struct {
	projectId                     string
	cacheOidcServiceAccountEmail  string
	cacheOauthServiceAccountEmail string
}

// cloudTasksHttpTarget is the flattened form of a queue-level HttpTarget.
// Nil pointers mean the queue does not set that value.
type cloudTasksHttpTarget struct {
	httpMethod             string
	headerOverrides        map[string]any
	uriScheme              *string
	uriHost                *string
	uriPort                *int64
	uriPath                *string
	uriQuery               *string
	uriOverrideEnforceMode *string
	oidcServiceAccount     string
	oidcAudience           *string
	oauthServiceAccount    string
	oauthScope             *string
}

// convertCloudTasksHttpTarget flattens a queue's HttpTarget. It returns nil
// when the queue has no HTTP target.
func convertCloudTasksHttpTarget(ht *cloudtaskspb.HttpTarget) *cloudTasksHttpTarget {
	if ht == nil {
		return nil
	}
	res := &cloudTasksHttpTarget{
		httpMethod:      ht.GetHttpMethod().String(),
		headerOverrides: map[string]any{},
	}
	for _, h := range ht.GetHeaderOverrides() {
		if hdr := h.GetHeader(); hdr != nil {
			res.headerOverrides[hdr.GetKey()] = hdr.GetValue()
		}
	}
	if uo := ht.GetUriOverride(); uo != nil {
		if uo.Scheme != nil {
			scheme := uo.GetScheme().String()
			res.uriScheme = &scheme
		}
		res.uriHost = uo.Host
		res.uriPort = uo.Port
		if po := uo.GetPathOverride(); po != nil {
			path := po.GetPath()
			res.uriPath = &path
		}
		if qo := uo.GetQueryOverride(); qo != nil {
			query := qo.GetQueryParams()
			res.uriQuery = &query
		}
		mode := uo.GetUriOverrideEnforceMode().String()
		res.uriOverrideEnforceMode = &mode
	}
	if oidc := ht.GetOidcToken(); oidc != nil {
		res.oidcServiceAccount = oidc.GetServiceAccountEmail()
		audience := oidc.GetAudience()
		res.oidcAudience = &audience
	}
	if oauth := ht.GetOauthToken(); oauth != nil {
		res.oauthServiceAccount = oauth.GetServiceAccountEmail()
		scope := oauth.GetScope()
		res.oauthScope = &scope
	}
	return res
}

func newCloudTasksHttpTarget(runtime *plugin.Runtime, projectId, queueName string, ht *cloudtaskspb.HttpTarget) (*mqlGcpProjectCloudTasksServiceQueueHttpTargetConfig, error) {
	t := convertCloudTasksHttpTarget(ht)
	if t == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "gcp.project.cloudTasksService.queue.httpTargetConfig", map[string]*llx.RawData{
		"__id":                   llx.StringData(queueName + "/httpTarget"),
		"httpMethod":             llx.StringData(t.httpMethod),
		"headerOverrides":        llx.MapData(t.headerOverrides, types.String),
		"uriScheme":              llx.StringDataPtr(t.uriScheme),
		"uriHost":                llx.StringDataPtr(t.uriHost),
		"uriPort":                llx.IntDataPtr(t.uriPort),
		"uriPath":                llx.StringDataPtr(t.uriPath),
		"uriQuery":               llx.StringDataPtr(t.uriQuery),
		"uriOverrideEnforceMode": llx.StringDataPtr(t.uriOverrideEnforceMode),
		"oidcAudience":           llx.StringDataPtr(t.oidcAudience),
		"oauthScope":             llx.StringDataPtr(t.oauthScope),
	})
	if err != nil {
		return nil, err
	}
	mqlT := res.(*mqlGcpProjectCloudTasksServiceQueueHttpTargetConfig)
	mqlT.projectId = projectId
	mqlT.cacheOidcServiceAccountEmail = t.oidcServiceAccount
	mqlT.cacheOauthServiceAccountEmail = t.oauthServiceAccount
	return mqlT, nil
}

func (g *mqlGcpProjectCloudTasksServiceQueueHttpTargetConfig) oidcServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheOidcServiceAccountEmail, g.projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.OidcServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudTasksServiceQueueHttpTargetConfig) oauthServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheOauthServiceAccountEmail, g.projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.OauthServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudTasksServiceQueue) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudtasks.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudtasks.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: name, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, name, policy.Bindings)
}

func cloudTasksConvertRateLimits(rl *cloudtaskspb.RateLimits) (map[string]any, error) {
	if rl == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		MaxDispatchesPerSecond  float64 `json:"maxDispatchesPerSecond"`
		MaxBurstSize            int32   `json:"maxBurstSize"`
		MaxConcurrentDispatches int32   `json:"maxConcurrentDispatches"`
	}{
		MaxDispatchesPerSecond:  rl.MaxDispatchesPerSecond,
		MaxBurstSize:            rl.MaxBurstSize,
		MaxConcurrentDispatches: rl.MaxConcurrentDispatches,
	})
}

func cloudTasksRetryConfig(runtime *plugin.Runtime, parentName string, rc *cloudtaskspb.RetryConfig) (*mqlGcpRetryConfig, error) {
	if rc == nil {
		return nil, nil
	}
	var minBackoff, maxBackoff, maxRetryDuration string
	if rc.MinBackoff != nil {
		minBackoff = rc.MinBackoff.AsDuration().String()
	}
	if rc.MaxBackoff != nil {
		maxBackoff = rc.MaxBackoff.AsDuration().String()
	}
	if rc.MaxRetryDuration != nil {
		maxRetryDuration = rc.MaxRetryDuration.AsDuration().String()
	}
	return newRetryConfigResource(runtime, parentName,
		int64(rc.MaxAttempts), minBackoff, maxBackoff, int64(rc.MaxDoublings), maxRetryDuration)
}

func cloudTasksConvertAppEngineRouting(r *cloudtaskspb.AppEngineRouting) (map[string]any, error) {
	if r == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		Service  string `json:"service"`
		Version  string `json:"version"`
		Instance string `json:"instance"`
		Host     string `json:"host"`
	}{
		Service:  r.Service,
		Version:  r.Version,
		Instance: r.Instance,
		Host:     r.Host,
	})
}

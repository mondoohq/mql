// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridge_types "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// ----- connections -----

func (a *mqlAwsEventbridge) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnections(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEventbridge) getConnections(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("eventbridge>getConnections>list")
			svc := conn.EventBridge(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListConnections(ctx, &eventbridge.ListConnectionsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing eventbridge connections")
						return res, nil
					}
					return nil, err
				}

				for _, c := range resp.Connections {
					mqlConn, err := CreateResource(a.MqlRuntime, "aws.eventbridge.connection",
						map[string]*llx.RawData{
							"__id":               llx.StringDataPtr(c.ConnectionArn),
							"arn":                llx.StringDataPtr(c.ConnectionArn),
							"name":               llx.StringDataPtr(c.Name),
							"region":             llx.StringData(region),
							"authorizationType":  llx.StringData(string(c.AuthorizationType)),
							"connectionState":    llx.StringData(string(c.ConnectionState)),
							"stateReason":        llx.StringDataPtr(c.StateReason),
							"creationTime":       llx.TimeDataPtr(c.CreationTime),
							"lastModifiedTime":   llx.TimeDataPtr(c.LastModifiedTime),
							"lastAuthorizedTime": llx.TimeDataPtr(c.LastAuthorizedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlConn)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEventbridgeConnectionInternal struct {
	fetched bool
	desc    *eventbridge.DescribeConnectionOutput
	lock    sync.Mutex
}

// fetchDescribe loads the DescribeConnection response. The List operation
// returns only the lifecycle summary; the secret ARN, the description,
// and the auth/invocation parameter shapes live on DescribeConnection.
func (a *mqlAwsEventbridgeConnection) fetchDescribe() (*eventbridge.DescribeConnectionOutput, error) {
	if a.fetched {
		return a.desc, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.desc, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(a.Region.Data)
	name := a.Name.Data
	resp, err := svc.DescribeConnection(context.Background(), &eventbridge.DescribeConnectionInput{
		Name: &name,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:DescribeConnection")
	}
	a.fetched = true
	a.desc = resp
	return a.desc, nil
}

func (a *mqlAwsEventbridgeConnection) description() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Description == nil {
		return "", nil
	}
	return *resp.Description, nil
}

func (a *mqlAwsEventbridgeConnection) secretArn() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.SecretArn == nil {
		return "", nil
	}
	return *resp.SecretArn, nil
}

func (a *mqlAwsEventbridgeConnection) secret() (*mqlAwsSecretsmanagerSecret, error) {
	arn, err := a.secretArn()
	if err != nil {
		return nil, err
	}
	if arn == "" {
		a.Secret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

// authParameters reports the *shape* of the credential parameters
// (authorization type, OAuth endpoint, header / API-key names) plus
// presence indicator booleans. Plaintext passwords, OAuth client
// secrets, and API-key values are never returned.
func (a *mqlAwsEventbridgeConnection) authParameters() (any, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	out := map[string]any{
		"type": string(resp.AuthorizationType),
	}
	ap := resp.AuthParameters
	if ap == nil {
		return out, nil
	}

	if ap.BasicAuthParameters != nil {
		username := ""
		if ap.BasicAuthParameters.Username != nil {
			username = *ap.BasicAuthParameters.Username
		}
		out["username"] = username
		out["usernamePresent"] = username != ""
		// the password is intentionally never surfaced
	}

	if ap.ApiKeyAuthParameters != nil {
		apiKeyName := ""
		if ap.ApiKeyAuthParameters.ApiKeyName != nil {
			apiKeyName = *ap.ApiKeyAuthParameters.ApiKeyName
		}
		out["apiKeyName"] = apiKeyName
		// the api key value is intentionally never surfaced; presence is
		// inferred from connectionState — when the connection has been
		// authorized at least once the value is set.
		out["apiKeyValuePresent"] = string(resp.ConnectionState) == "AUTHORIZED" ||
			resp.LastAuthorizedTime != nil
	}

	if ap.OAuthParameters != nil {
		oauth := ap.OAuthParameters
		clientID := ""
		if oauth.ClientParameters != nil && oauth.ClientParameters.ClientID != nil {
			clientID = *oauth.ClientParameters.ClientID
		}
		authEndpoint := ""
		if oauth.AuthorizationEndpoint != nil {
			authEndpoint = *oauth.AuthorizationEndpoint
		}
		out["authorizationEndpoint"] = authEndpoint
		out["httpMethod"] = string(oauth.HttpMethod)
		out["clientID"] = clientID
		// the client secret is intentionally never surfaced; presence
		// is inferred the same way as for api key values above.
		out["clientSecretPresent"] = string(resp.ConnectionState) == "AUTHORIZED" ||
			resp.LastAuthorizedTime != nil
		out["oauthHttpParameters"] = connectionHttpParametersToMap(oauth.OAuthHttpParameters)
	}

	return out, nil
}

func (a *mqlAwsEventbridgeConnection) invocationHttpParameters() (any, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.AuthParameters == nil {
		return nil, nil
	}
	return connectionHttpParametersToMap(resp.AuthParameters.InvocationHttpParameters), nil
}

// connectionHttpParametersToMap projects header / query / body
// parameter lists into a dict shape while honoring each entry's
// IsValueSecret flag — values flagged as secret are masked and reported
// only as a presence boolean.
func connectionHttpParametersToMap(p *eventbridge_types.ConnectionHttpParameters) any {
	if p == nil {
		return nil
	}
	convert := func(key string, isSecret bool, value *string) map[string]any {
		entry := map[string]any{
			"key":           key,
			"isValueSecret": isSecret,
		}
		v := ""
		if value != nil {
			v = *value
		}
		entry["valuePresent"] = v != ""
		if !isSecret {
			entry["value"] = v
		}
		return entry
	}

	headers := make([]any, 0, len(p.HeaderParameters))
	for _, h := range p.HeaderParameters {
		key := ""
		if h.Key != nil {
			key = *h.Key
		}
		headers = append(headers, convert(key, h.IsValueSecret, h.Value))
	}

	query := make([]any, 0, len(p.QueryStringParameters))
	for _, q := range p.QueryStringParameters {
		key := ""
		if q.Key != nil {
			key = *q.Key
		}
		query = append(query, convert(key, q.IsValueSecret, q.Value))
	}

	body := make([]any, 0, len(p.BodyParameters))
	for _, b := range p.BodyParameters {
		key := ""
		if b.Key != nil {
			key = *b.Key
		}
		body = append(body, convert(key, b.IsValueSecret, b.Value))
	}

	return map[string]any{
		"headerParameters":      headers,
		"queryStringParameters": query,
		"bodyParameters":        body,
	}
}

func initAwsEventbridgeConnection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if _, ok := args["arn"]; !ok {
		return nil, nil, errors.New("arn required to fetch eventbridge connection")
	}
	arn, ok := args["arn"].Value.(string)
	if !ok || arn == "" {
		return nil, nil, errors.New("arn required to fetch eventbridge connection")
	}
	// Connections are materialized by aws.eventbridge.connections() across
	// regions; resolve the ARN against that set.
	res, err := findEventbridgeArnMatch(runtime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetConnections() },
		func(item any) string { return item.(*mqlAwsEventbridgeConnection).Arn.Data })
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// Returning (args, nil, nil) here would let the runtime create a resource
		// whose fields are all unset, which surfaces as malformed nil data when
		// those fields are queried.
		return nil, nil, fmt.Errorf("aws.eventbridge.connection with arn %q not found", arn)
	}
	return args, res.(*mqlAwsEventbridgeConnection), nil
}

// ----- api destinations -----

func (a *mqlAwsEventbridge) apiDestinations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getApiDestinations(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEventbridge) getApiDestinations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("eventbridge>getApiDestinations>list")
			svc := conn.EventBridge(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListApiDestinations(ctx, &eventbridge.ListApiDestinationsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing eventbridge api destinations")
						return res, nil
					}
					return nil, err
				}

				for _, d := range resp.ApiDestinations {
					var rateLimit int64
					if d.InvocationRateLimitPerSecond != nil {
						rateLimit = int64(*d.InvocationRateLimitPerSecond)
					}
					mqlDest, err := CreateResource(a.MqlRuntime, "aws.eventbridge.apiDestination",
						map[string]*llx.RawData{
							"__id":                         llx.StringDataPtr(d.ApiDestinationArn),
							"arn":                          llx.StringDataPtr(d.ApiDestinationArn),
							"name":                         llx.StringDataPtr(d.Name),
							"region":                       llx.StringData(region),
							"apiDestinationState":          llx.StringData(string(d.ApiDestinationState)),
							"connectionArn":                llx.StringDataPtr(d.ConnectionArn),
							"invocationEndpoint":           llx.StringDataPtr(d.InvocationEndpoint),
							"httpMethod":                   llx.StringData(string(d.HttpMethod)),
							"invocationRateLimitPerSecond": llx.IntData(rateLimit),
							"creationTime":                 llx.TimeDataPtr(d.CreationTime),
							"lastModifiedTime":             llx.TimeDataPtr(d.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDest)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEventbridgeApiDestinationInternal struct {
	fetched bool
	desc    *eventbridge.DescribeApiDestinationOutput
	lock    sync.Mutex
}

func (a *mqlAwsEventbridgeApiDestination) fetchDescribe() (*eventbridge.DescribeApiDestinationOutput, error) {
	if a.fetched {
		return a.desc, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.desc, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(a.Region.Data)
	name := a.Name.Data
	resp, err := svc.DescribeApiDestination(context.Background(), &eventbridge.DescribeApiDestinationInput{
		Name: &name,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:DescribeApiDestination")
	}
	a.fetched = true
	a.desc = resp
	return a.desc, nil
}

func (a *mqlAwsEventbridgeApiDestination) description() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Description == nil {
		return "", nil
	}
	return *resp.Description, nil
}

// findEventbridgeArnMatch materializes the parent aws.eventbridge resource
// and scans `listFn`'s returned slice for the first item whose `arnOf` returns
// the target `arn`. Returns (nil, nil) when arn is empty or no match is found,
// so each typed-ref accessor just has to fold the result into its own
// IsSet|IsNull contract. Keeps cross-reference resolution behavior identical
// across connection / eventSource / destination so future fixes are single-site.
func findEventbridgeArnMatch(
	runtime *plugin.Runtime,
	arn string,
	listFn func(*mqlAwsEventbridge) *plugin.TValue[[]any],
	arnOf func(any) string,
) (any, error) {
	if arn == "" {
		return nil, nil
	}
	parent, err := CreateResource(runtime, "aws.eventbridge", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	coll := listFn(parent.(*mqlAwsEventbridge))
	if coll.Error != nil {
		return nil, coll.Error
	}
	for _, item := range coll.Data {
		if arnOf(item) == arn {
			return item, nil
		}
	}
	return nil, nil
}

func (a *mqlAwsEventbridgeApiDestination) connection() (*mqlAwsEventbridgeConnection, error) {
	res, err := findEventbridgeArnMatch(a.MqlRuntime, a.ConnectionArn.Data,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetConnections() },
		func(item any) string { return item.(*mqlAwsEventbridgeConnection).Arn.Data })
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Connection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAwsEventbridgeConnection), nil
}

func initAwsEventbridgeApiDestination(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if _, ok := args["arn"]; !ok {
		return nil, nil, errors.New("arn required to fetch eventbridge api destination")
	}
	arn, ok := args["arn"].Value.(string)
	if !ok || arn == "" {
		return nil, nil, errors.New("arn required to fetch eventbridge api destination")
	}
	res, err := findEventbridgeArnMatch(runtime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetApiDestinations() },
		func(item any) string { return item.(*mqlAwsEventbridgeApiDestination).Arn.Data })
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// Returning (args, nil, nil) here would let the runtime create a resource
		// whose fields are all unset, which surfaces as malformed nil data when
		// those fields are queried.
		return nil, nil, fmt.Errorf("aws.eventbridge.apiDestination with arn %q not found", arn)
	}
	return args, res.(*mqlAwsEventbridgeApiDestination), nil
}

// ----- archives -----

func (a *mqlAwsEventbridge) archives() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getArchives(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEventbridge) getArchives(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("eventbridge>getArchives>list")
			svc := conn.EventBridge(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListArchives(ctx, &eventbridge.ListArchivesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing eventbridge archives")
						return res, nil
					}
					return nil, err
				}

				accountId := conn.AccountId()
				for _, arch := range resp.Archives {
					name := ""
					if arch.ArchiveName != nil {
						name = *arch.ArchiveName
					}
					// Archive returned by ListArchives lacks its own
					// ARN; assemble the standard EventBridge archive
					// ARN from region + account id + name.
					arn := "arn:aws:events:" + region + ":" + accountId + ":archive/" + name

					var retention int64
					if arch.RetentionDays != nil {
						retention = int64(*arch.RetentionDays)
					}

					mqlArch, err := CreateResource(a.MqlRuntime, "aws.eventbridge.archive",
						map[string]*llx.RawData{
							"__id":           llx.StringData(arn),
							"arn":            llx.StringData(arn),
							"archiveName":    llx.StringData(name),
							"region":         llx.StringData(region),
							"eventSourceArn": llx.StringDataPtr(arch.EventSourceArn),
							"state":          llx.StringData(string(arch.State)),
							"stateReason":    llx.StringDataPtr(arch.StateReason),
							"retentionDays":  llx.IntData(retention),
							"sizeBytes":      llx.IntData(arch.SizeBytes),
							"eventCount":     llx.IntData(arch.EventCount),
							"creationTime":   llx.TimeDataPtr(arch.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlArch)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEventbridgeArchiveInternal struct {
	fetched bool
	desc    *eventbridge.DescribeArchiveOutput
	lock    sync.Mutex
}

func (a *mqlAwsEventbridgeArchive) fetchDescribe() (*eventbridge.DescribeArchiveOutput, error) {
	if a.fetched {
		return a.desc, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.desc, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(a.Region.Data)
	name := a.ArchiveName.Data
	resp, err := svc.DescribeArchive(context.Background(), &eventbridge.DescribeArchiveInput{
		ArchiveName: &name,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:DescribeArchive")
	}
	a.fetched = true
	a.desc = resp
	return a.desc, nil
}

func (a *mqlAwsEventbridgeArchive) description() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Description == nil {
		return "", nil
	}
	return *resp.Description, nil
}

func (a *mqlAwsEventbridgeArchive) eventPattern() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.EventPattern == nil {
		return "", nil
	}
	return *resp.EventPattern, nil
}

func (a *mqlAwsEventbridgeArchive) eventSource() (*mqlAwsEventbridgeEventBus, error) {
	res, err := findEventbridgeArnMatch(a.MqlRuntime, a.EventSourceArn.Data,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetEventBuses() },
		func(item any) string { return item.(*mqlAwsEventbridgeEventBus).Arn.Data })
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.EventSource.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAwsEventbridgeEventBus), nil
}

func initAwsEventbridgeArchive(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if _, ok := args["arn"]; !ok {
		return nil, nil, errors.New("arn required to fetch eventbridge archive")
	}
	arn, ok := args["arn"].Value.(string)
	if !ok || arn == "" {
		return nil, nil, errors.New("arn required to fetch eventbridge archive")
	}
	res, err := findEventbridgeArnMatch(runtime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetArchives() },
		func(item any) string { return item.(*mqlAwsEventbridgeArchive).Arn.Data })
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// Returning (args, nil, nil) here would let the runtime create a resource
		// whose fields are all unset, which surfaces as malformed nil data when
		// those fields are queried.
		return nil, nil, fmt.Errorf("aws.eventbridge.archive with arn %q not found", arn)
	}
	return args, res.(*mqlAwsEventbridgeArchive), nil
}

// ----- replays -----

func (a *mqlAwsEventbridge) replays() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplays(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsEventbridge) getReplays(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("eventbridge>getReplays>list")
			svc := conn.EventBridge(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListReplays(ctx, &eventbridge.ListReplaysInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing eventbridge replays")
						return res, nil
					}
					return nil, err
				}

				accountId := conn.AccountId()
				for _, rep := range resp.Replays {
					name := ""
					if rep.ReplayName != nil {
						name = *rep.ReplayName
					}
					// ListReplays summaries do not carry the replay
					// ARN — assemble the standard format.
					arn := "arn:aws:events:" + region + ":" + accountId + ":replay/" + name

					mqlReplay, err := CreateResource(a.MqlRuntime, "aws.eventbridge.replay",
						map[string]*llx.RawData{
							"__id":                  llx.StringData(arn),
							"arn":                   llx.StringData(arn),
							"replayName":            llx.StringData(name),
							"region":                llx.StringData(region),
							"eventSourceArn":        llx.StringDataPtr(rep.EventSourceArn),
							"state":                 llx.StringData(string(rep.State)),
							"stateReason":           llx.StringDataPtr(rep.StateReason),
							"eventStartTime":        llx.TimeDataPtr(rep.EventStartTime),
							"eventEndTime":          llx.TimeDataPtr(rep.EventEndTime),
							"eventLastReplayedTime": llx.TimeDataPtr(rep.EventLastReplayedTime),
							"replayStartTime":       llx.TimeDataPtr(rep.ReplayStartTime),
							"replayEndTime":         llx.TimeDataPtr(rep.ReplayEndTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlReplay)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEventbridgeReplayInternal struct {
	fetched bool
	desc    *eventbridge.DescribeReplayOutput
	lock    sync.Mutex
}

func (a *mqlAwsEventbridgeReplay) fetchDescribe() (*eventbridge.DescribeReplayOutput, error) {
	if a.fetched {
		return a.desc, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.desc, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(a.Region.Data)
	name := a.ReplayName.Data
	resp, err := svc.DescribeReplay(context.Background(), &eventbridge.DescribeReplayInput{
		ReplayName: &name,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:DescribeReplay")
	}
	a.fetched = true
	a.desc = resp
	return a.desc, nil
}

func (a *mqlAwsEventbridgeReplay) description() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Description == nil {
		return "", nil
	}
	return *resp.Description, nil
}

func (a *mqlAwsEventbridgeReplay) destinationArn() (string, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Destination == nil || resp.Destination.Arn == nil {
		return "", nil
	}
	return *resp.Destination.Arn, nil
}

func (a *mqlAwsEventbridgeReplay) filterArns() ([]any, error) {
	resp, err := a.fetchDescribe()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Destination == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(resp.Destination.FilterArns))
	for _, arn := range resp.Destination.FilterArns {
		out = append(out, arn)
	}
	return out, nil
}

func (a *mqlAwsEventbridgeReplay) eventSource() (*mqlAwsEventbridgeArchive, error) {
	res, err := findEventbridgeArnMatch(a.MqlRuntime, a.EventSourceArn.Data,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetArchives() },
		func(item any) string { return item.(*mqlAwsEventbridgeArchive).Arn.Data })
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.EventSource.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAwsEventbridgeArchive), nil
}

func (a *mqlAwsEventbridgeReplay) destination() (*mqlAwsEventbridgeEventBus, error) {
	arn, err := a.destinationArn()
	if err != nil {
		return nil, err
	}
	res, err := findEventbridgeArnMatch(a.MqlRuntime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetEventBuses() },
		func(item any) string { return item.(*mqlAwsEventbridgeEventBus).Arn.Data })
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Destination.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAwsEventbridgeEventBus), nil
}

func initAwsEventbridgeReplay(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if _, ok := args["arn"]; !ok {
		return nil, nil, errors.New("arn required to fetch eventbridge replay")
	}
	arn, ok := args["arn"].Value.(string)
	if !ok || arn == "" {
		return nil, nil, errors.New("arn required to fetch eventbridge replay")
	}
	res, err := findEventbridgeArnMatch(runtime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetReplays() },
		func(item any) string { return item.(*mqlAwsEventbridgeReplay).Arn.Data })
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// Returning (args, nil, nil) here would let the runtime create a resource
		// whose fields are all unset, which surfaces as malformed nil data when
		// those fields are queried.
		return nil, nil, fmt.Errorf("aws.eventbridge.replay with arn %q not found", arn)
	}
	return args, res.(*mqlAwsEventbridgeReplay), nil
}

// ----- global endpoints -----

func (a *mqlAwsEventbridge) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// Global endpoints are a Region-less concept; the ListEndpoints API
	// returns the same set regardless of the AWS Region the EventBridge
	// client is built for. Pick the first available Region to keep the
	// configured client construction path; fall back to us-east-1.
	region := "us-east-1"
	if regions, err := conn.Regions(); err == nil && len(regions) > 0 {
		region = regions[0]
	}

	svc := conn.EventBridge(region)
	ctx := context.Background()
	res := []any{}

	var nextToken *string
	for {
		resp, err := svc.ListEndpoints(ctx, &eventbridge.ListEndpointsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "events:ListEndpoints")
		}

		for _, ep := range resp.Endpoints {
			eventBusesDict := make([]any, 0, len(ep.EventBuses))
			for _, b := range ep.EventBuses {
				busArn := ""
				if b.EventBusArn != nil {
					busArn = *b.EventBusArn
				}
				eventBusesDict = append(eventBusesDict, map[string]any{
					"eventBusArn": busArn,
				})
			}

			routingConfig := endpointRoutingConfigToMap(ep.RoutingConfig)
			replicationConfig := endpointReplicationConfigToMap(ep.ReplicationConfig)

			mqlEp, err := CreateResource(a.MqlRuntime, "aws.eventbridge.endpoint",
				map[string]*llx.RawData{
					"__id":              llx.StringDataPtr(ep.Arn),
					"arn":               llx.StringDataPtr(ep.Arn),
					"name":              llx.StringDataPtr(ep.Name),
					"description":       llx.StringDataPtr(ep.Description),
					"state":             llx.StringData(string(ep.State)),
					"stateReason":       llx.StringDataPtr(ep.StateReason),
					"endpointId":        llx.StringDataPtr(ep.EndpointId),
					"endpointUrl":       llx.StringDataPtr(ep.EndpointUrl),
					"eventBuses":        llx.ArrayData(eventBusesDict, types.Dict),
					"routingConfig":     llx.DictData(routingConfig),
					"replicationConfig": llx.DictData(replicationConfig),
					"creationTime":      llx.TimeDataPtr(ep.CreationTime),
					"lastModifiedTime":  llx.TimeDataPtr(ep.LastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			mqlEp.(*mqlAwsEventbridgeEndpoint).cacheRoleArn = convert.ToValue(ep.RoleArn)
			res = append(res, mqlEp)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func endpointRoutingConfigToMap(rc *eventbridge_types.RoutingConfig) any {
	if rc == nil || rc.FailoverConfig == nil {
		return nil
	}
	fc := rc.FailoverConfig
	out := map[string]any{}
	if fc.Primary != nil {
		hc := ""
		if fc.Primary.HealthCheck != nil {
			hc = *fc.Primary.HealthCheck
		}
		out["primary"] = map[string]any{"healthCheck": hc}
	}
	if fc.Secondary != nil {
		route := ""
		if fc.Secondary.Route != nil {
			route = *fc.Secondary.Route
		}
		out["secondary"] = map[string]any{"route": route}
	}
	return map[string]any{"failoverConfig": out}
}

func endpointReplicationConfigToMap(rc *eventbridge_types.ReplicationConfig) any {
	if rc == nil {
		return nil
	}
	return map[string]any{
		"state": string(rc.State),
	}
}

func (a *mqlAwsEventbridgeEndpoint) iamRole() (*mqlAwsIamRole, error) {
	arn := a.cacheRoleArn
	if arn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func initAwsEventbridgeEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if _, ok := args["arn"]; !ok {
		return nil, nil, errors.New("arn required to fetch eventbridge endpoint")
	}
	arn, ok := args["arn"].Value.(string)
	if !ok || arn == "" {
		return nil, nil, errors.New("arn required to fetch eventbridge endpoint")
	}
	res, err := findEventbridgeArnMatch(runtime, arn,
		func(eb *mqlAwsEventbridge) *plugin.TValue[[]any] { return eb.GetEndpoints() },
		func(item any) string { return item.(*mqlAwsEventbridgeEndpoint).Arn.Data })
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// Returning (args, nil, nil) here would let the runtime create a resource
		// whose fields are all unset, which surfaces as malformed nil data when
		// those fields are queried.
		return nil, nil, fmt.Errorf("aws.eventbridge.endpoint with arn %q not found", arn)
	}
	return args, res.(*mqlAwsEventbridgeEndpoint), nil
}

type mqlAwsEventbridgeEndpointInternal struct {
	cacheRoleArn string
}

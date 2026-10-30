// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsEc2ManagedPrefixList) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2ManagedPrefixListEntry) id() (string, error) {
	return a.Cidr.Data, nil
}

func initAwsEc2ManagedPrefixList(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	arnRaw, hasArn := args["arn"]
	if !hasArn || arnRaw == nil || arnRaw.Value == nil {
		return nil, nil, fmt.Errorf("arn required to fetch ec2 managed prefix list")
	}
	arnVal, ok := arnRaw.Value.(string)
	if !ok || arnVal == "" {
		return nil, nil, fmt.Errorf("arn required to fetch ec2 managed prefix list")
	}

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(arnVal, "/")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("not a valid ec2 managed prefix list ARN '%s'", arnVal)
	}
	plId := parts[len(parts)-1]

	args["id"] = llx.StringData(plId)
	args["arn"] = llx.StringData(arnVal)
	args["region"] = llx.StringData(region)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	resp, err := svc.DescribeManagedPrefixLists(ctx, &ec2.DescribeManagedPrefixListsInput{
		PrefixListIds: []string{plId},
	})
	if err != nil {
		// Intentionally an error rather than the old (args, nil, nil)
		// fallback: a partially-initialized resource surfaces as malformed
		// nil data when its unset fields are queried. Access-denied gets a
		// descriptive message instead of the raw SDK error.
		if Is400AccessDeniedError(err) {
			return nil, nil, fmt.Errorf("access denied fetching aws.ec2.managedPrefixList with id %q in region %s", plId, region)
		}
		return nil, nil, err
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	if len(resp.PrefixLists) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.managedPrefixList with id %q not found", plId)
	}
	pl := resp.PrefixLists[0]

	var version int64
	if pl.Version != nil {
		version = *pl.Version
	}
	var maxEntries int64
	if pl.MaxEntries != nil {
		maxEntries = int64(*pl.MaxEntries)
	}

	args["id"] = llx.StringData(convert.ToValue(pl.PrefixListId))
	args["name"] = llx.StringData(convert.ToValue(pl.PrefixListName))
	args["state"] = llx.StringData(string(pl.State))
	args["addressFamily"] = llx.StringData(convert.ToValue(pl.AddressFamily))
	args["maxEntries"] = llx.IntData(maxEntries)
	args["version"] = llx.IntData(version)
	args["ownerId"] = llx.StringData(convert.ToValue(pl.OwnerId))
	args["tags"] = llx.MapData(toInterfaceMap(ec2TagsToMap(pl.Tags)), types.String)
	return args, nil, nil
}

func (a *mqlAwsEc2) managedPrefixLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getManagedPrefixLists(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getManagedPrefixLists(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeManagedPrefixListsPaginator(svc, &ec2.DescribeManagedPrefixListsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, pl := range page.PrefixLists {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(pl.Tags)) {
						continue
					}

					var version int64
					if pl.Version != nil {
						version = *pl.Version
					}
					var maxEntries int64
					if pl.MaxEntries != nil {
						maxEntries = int64(*pl.MaxEntries)
					}

					plArn := convert.ToValue(pl.PrefixListArn)
					if plArn == "" {
						plArn = fmt.Sprintf("arn:aws:ec2:%s:%s:prefix-list/%s", region, conn.AccountId(), convert.ToValue(pl.PrefixListId))
					}

					mqlPl, err := CreateResource(a.MqlRuntime, ResourceAwsEc2ManagedPrefixList,
						map[string]*llx.RawData{
							"id":            llx.StringData(convert.ToValue(pl.PrefixListId)),
							"arn":           llx.StringData(plArn),
							"name":          llx.StringData(convert.ToValue(pl.PrefixListName)),
							"region":        llx.StringData(region),
							"state":         llx.StringData(string(pl.State)),
							"addressFamily": llx.StringData(convert.ToValue(pl.AddressFamily)),
							"maxEntries":    llx.IntData(maxEntries),
							"version":       llx.IntData(version),
							"ownerId":       llx.StringData(convert.ToValue(pl.OwnerId)),
							"tags":          llx.MapData(toInterfaceMap(ec2TagsToMap(pl.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPl)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2ManagedPrefixList) entries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	plId := a.Id.Data
	entries := []any{}

	paginator := ec2.NewGetManagedPrefixListEntriesPaginator(svc, &ec2.GetManagedPrefixListEntriesInput{
		PrefixListId: &plId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return entries, nil
			}
			return nil, err
		}
		for _, entry := range page.Entries {
			cidr := convert.ToValue(entry.Cidr)
			mqlEntry, err := CreateResource(a.MqlRuntime, ResourceAwsEc2ManagedPrefixListEntry,
				map[string]*llx.RawData{
					"__id":        llx.StringData(plId + "/" + cidr),
					"cidr":        llx.StringData(cidr),
					"description": llx.StringData(convert.ToValue(entry.Description)),
				})
			if err != nil {
				return nil, err
			}
			entries = append(entries, mqlEntry)
		}
	}
	return entries, nil
}

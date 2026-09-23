// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// ----- Traffic policies -----
// Traffic policies and CIDR collections are global (Route 53 is a global
// service). We make a single un-regioned client call for each.

func (a *mqlAwsRoute53) trafficPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Route53("")

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListTrafficPolicies(ctx, &route53.ListTrafficPoliciesInput{
			TrafficPolicyIdMarker: marker,
		})
		if err != nil {
			return nil, classifyAwsError(err, "route53:ListTrafficPolicies")
		}
		for _, summary := range resp.TrafficPolicySummaries {
			summary := summary
			policy, err := getTrafficPolicy(ctx, svc, summary.Id, summary.LatestVersion)
			if err != nil {
				if Is400AccessDeniedError(err) {
					continue
				}
				return nil, err
			}
			if policy == nil {
				continue
			}
			mqlPolicy, err := newMqlAwsRoute53TrafficPolicy(a.MqlRuntime, policy, true)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
		if !resp.IsTruncated {
			break
		}
		marker = resp.TrafficPolicyIdMarker
	}
	return res, nil
}

func getTrafficPolicy(ctx context.Context, svc *route53.Client, id *string, version *int32) (*route53types.TrafficPolicy, error) {
	if id == nil || version == nil {
		return nil, nil
	}
	resp, err := svc.GetTrafficPolicy(ctx, &route53.GetTrafficPolicyInput{
		Id:      id,
		Version: version,
	})
	if err != nil {
		return nil, err
	}
	return resp.TrafficPolicy, nil
}

func newMqlAwsRoute53TrafficPolicy(runtime *plugin.Runtime, policy *route53types.TrafficPolicy, latestVersion bool) (*mqlAwsRoute53TrafficPolicy, error) {
	id := convert.ToValue(policy.Id)
	version := int64(0)
	if policy.Version != nil {
		version = int64(*policy.Version)
	}
	resource, err := CreateResource(runtime, "aws.route53.trafficPolicy", map[string]*llx.RawData{
		"__id":          llx.StringData(fmt.Sprintf("%s/v%d", id, version)),
		"id":            llx.StringData(id),
		"version":       llx.IntData(version),
		"name":          llx.StringData(convert.ToValue(policy.Name)),
		"type":          llx.StringData(string(policy.Type)),
		"document":      llx.StringData(convert.ToValue(policy.Document)),
		"comment":       llx.StringData(convert.ToValue(policy.Comment)),
		"latestVersion": llx.BoolData(latestVersion),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsRoute53TrafficPolicy), nil
}

func (a *mqlAwsRoute53TrafficPolicy) id() (string, error) {
	return fmt.Sprintf("%s/v%d", a.Id.Data, a.Version.Data), nil
}

func initAwsRoute53TrafficPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	idVal := args["id"].Value.(string)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Route53("")
	ctx := context.Background()

	// If version is supplied, fetch that specific version; otherwise scan
	// the latest-version listing to find the policy by id.
	if args["version"] != nil {
		versionVal := args["version"].Value.(int64)
		v := int32(versionVal)
		resp, err := svc.GetTrafficPolicy(ctx, &route53.GetTrafficPolicyInput{Id: &idVal, Version: &v})
		if err != nil {
			return nil, nil, classifyAwsError(err, "route53:GetTrafficPolicy")
		}
		if resp == nil || resp.TrafficPolicy == nil {
			return args, nil, nil
		}
		mqlPolicy, err := newMqlAwsRoute53TrafficPolicy(runtime, resp.TrafficPolicy, false)
		if err != nil {
			return nil, nil, err
		}
		return args, mqlPolicy, nil
	}

	// Fall back to scanning the namespace listing.
	obj, err := CreateResource(runtime, "aws.route53", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	r53 := obj.(*mqlAwsRoute53)
	raw := r53.GetTrafficPolicies()
	if raw.Error != nil {
		return nil, nil, raw.Error
	}
	for _, item := range raw.Data {
		tp := item.(*mqlAwsRoute53TrafficPolicy)
		if tp.Id.Data == idVal {
			return args, tp, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.route53.trafficpolicy with id %q not found", idVal)
}

// ----- Traffic policy instances -----

func (a *mqlAwsRoute53) trafficPolicyInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Route53("")

	res := []any{}
	var hostedZoneIdMarker *string
	var nameMarker *string
	var typeMarker route53types.RRType
	for {
		input := &route53.ListTrafficPolicyInstancesInput{
			HostedZoneIdMarker:              hostedZoneIdMarker,
			TrafficPolicyInstanceNameMarker: nameMarker,
		}
		if typeMarker != "" {
			input.TrafficPolicyInstanceTypeMarker = typeMarker
		}
		resp, err := svc.ListTrafficPolicyInstances(ctx, input)
		if err != nil {
			return nil, classifyAwsError(err, "route53:ListTrafficPolicyInstances")
		}
		for _, inst := range resp.TrafficPolicyInstances {
			inst := inst
			mqlInst, err := newMqlAwsRoute53TrafficPolicyInstance(a.MqlRuntime, &inst)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlInst)
		}
		if !resp.IsTruncated {
			break
		}
		hostedZoneIdMarker = resp.HostedZoneIdMarker
		nameMarker = resp.TrafficPolicyInstanceNameMarker
		typeMarker = resp.TrafficPolicyInstanceTypeMarker
	}
	return res, nil
}

func newMqlAwsRoute53TrafficPolicyInstance(runtime *plugin.Runtime, inst *route53types.TrafficPolicyInstance) (*mqlAwsRoute53TrafficPolicyInstance, error) {
	id := convert.ToValue(inst.Id)
	version := int64(0)
	if inst.TrafficPolicyVersion != nil {
		version = int64(*inst.TrafficPolicyVersion)
	}
	ttl := int64(0)
	if inst.TTL != nil {
		ttl = *inst.TTL
	}
	resource, err := CreateResource(runtime, "aws.route53.trafficPolicyInstance", map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"id":                   llx.StringData(id),
		"name":                 llx.StringData(convert.ToValue(inst.Name)),
		"hostedZoneId":         llx.StringData(convert.ToValue(inst.HostedZoneId)),
		"trafficPolicyId":      llx.StringData(convert.ToValue(inst.TrafficPolicyId)),
		"trafficPolicyVersion": llx.IntData(version),
		"trafficPolicyType":    llx.StringData(string(inst.TrafficPolicyType)),
		"ttl":                  llx.IntData(ttl),
		"state":                llx.StringData(convert.ToValue(inst.State)),
		"message":              llx.StringData(convert.ToValue(inst.Message)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsRoute53TrafficPolicyInstance), nil
}

func (a *mqlAwsRoute53TrafficPolicyInstance) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53TrafficPolicyInstance) hostedZone() (*mqlAwsRoute53HostedZone, error) {
	hzId := a.HostedZoneId.Data
	if hzId == "" {
		a.HostedZone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.route53.hostedZone", map[string]*llx.RawData{
		"id": llx.StringData(hzId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53HostedZone), nil
}

func (a *mqlAwsRoute53TrafficPolicyInstance) trafficPolicy() (*mqlAwsRoute53TrafficPolicy, error) {
	policyId := a.TrafficPolicyId.Data
	if policyId == "" {
		a.TrafficPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	version := a.TrafficPolicyVersion.Data
	res, err := NewResource(a.MqlRuntime, "aws.route53.trafficPolicy", map[string]*llx.RawData{
		"id":      llx.StringData(policyId),
		"version": llx.IntData(version),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53TrafficPolicy), nil
}

// ----- CIDR collections -----

type mqlAwsRoute53CidrCollectionInternal struct {
	locationsOnce sync.Once
	locationsData []any
	locationsErr  error
}

func (a *mqlAwsRoute53) cidrCollections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Route53("")

	res := []any{}
	paginator := route53.NewListCidrCollectionsPaginator(svc, &route53.ListCidrCollectionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53:ListCidrCollections")
		}
		for _, summary := range page.CidrCollections {
			summary := summary
			arnVal := convert.ToValue(summary.Arn)
			idVal := convert.ToValue(summary.Id)
			version := int64(0)
			if summary.Version != nil {
				version = *summary.Version
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.route53.cidrCollection", map[string]*llx.RawData{
				"__id":    llx.StringData(arnVal),
				"arn":     llx.StringData(arnVal),
				"id":      llx.StringData(idVal),
				"name":    llx.StringData(convert.ToValue(summary.Name)),
				"version": llx.IntData(version),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func (a *mqlAwsRoute53CidrCollection) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRoute53CidrCollection) locations() ([]any, error) {
	a.locationsOnce.Do(func() {
		a.locationsData, a.locationsErr = a.fetchLocations()
	})
	return a.locationsData, a.locationsErr
}

func (a *mqlAwsRoute53CidrCollection) fetchLocations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Route53("")
	collectionId := a.Id.Data

	res := []any{}
	paginator := route53.NewListCidrLocationsPaginator(svc, &route53.ListCidrLocationsInput{
		CollectionId: &collectionId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53:ListCidrLocations")
		}
		for _, loc := range page.CidrLocations {
			locName := convert.ToValue(loc.LocationName)
			blocks, err := fetchCidrBlocks(ctx, svc, collectionId, locName)
			if err != nil {
				return nil, err
			}
			res = append(res, map[string]any{
				"locationName": locName,
				"cidrBlocks":   blocks,
			})
		}
	}
	return res, nil
}

func fetchCidrBlocks(ctx context.Context, svc *route53.Client, collectionId, locationName string) ([]any, error) {
	blocks := []any{}
	paginator := route53.NewListCidrBlocksPaginator(svc, &route53.ListCidrBlocksInput{
		CollectionId: &collectionId,
		LocationName: &locationName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53:ListCidrBlocks")
		}
		for _, b := range page.CidrBlocks {
			blocks = append(blocks, convert.ToValue(b.CidrBlock))
		}
	}
	return blocks, nil
}

// ----- DNSSEC per-zone view -----

func (a *mqlAwsRoute53HostedZone) dnssec() (*mqlAwsRoute53HostedZoneDnssec, error) {
	hostedZoneId := a.Id.Data

	if a.IsPrivate.Data {
		return newMqlAwsRoute53HostedZoneDnssec(a.MqlRuntime, hostedZoneId, "NOT_SIGNING", "DNSSEC is not supported for private hosted zones")
	}

	resp, err := a.getDNSSEC()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		a.Dnssec.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	status := ""
	statusMessage := ""
	if resp.Status != nil {
		status = convert.ToValue(resp.Status.ServeSignature)
		statusMessage = convert.ToValue(resp.Status.StatusMessage)
	}
	return newMqlAwsRoute53HostedZoneDnssec(a.MqlRuntime, hostedZoneId, status, statusMessage)
}

func newMqlAwsRoute53HostedZoneDnssec(runtime *plugin.Runtime, hostedZoneId, status, statusMessage string) (*mqlAwsRoute53HostedZoneDnssec, error) {
	resource, err := CreateResource(runtime, "aws.route53.hostedZone.dnssec", map[string]*llx.RawData{
		"__id":          llx.StringData(hostedZoneId + "/dnssec"),
		"status":        llx.StringData(status),
		"statusMessage": llx.StringData(statusMessage),
	})
	if err != nil {
		return nil, err
	}
	mqlDnssec := resource.(*mqlAwsRoute53HostedZoneDnssec)
	mqlDnssec.hostedZoneId = hostedZoneId
	return mqlDnssec, nil
}

type mqlAwsRoute53HostedZoneDnssecInternal struct {
	hostedZoneId string
}

func (a *mqlAwsRoute53HostedZoneDnssec) keySigningKeys() ([]any, error) {
	if a.hostedZoneId == "" {
		return []any{}, nil
	}
	mqlHz, err := NewResource(a.MqlRuntime, "aws.route53.hostedZone", map[string]*llx.RawData{
		"id": llx.StringData(a.hostedZoneId),
	})
	if err != nil {
		return nil, err
	}
	hz := mqlHz.(*mqlAwsRoute53HostedZone)
	rawKsks := hz.GetKeySigningKeys()
	if rawKsks.Error != nil {
		return nil, rawKsks.Error
	}
	return rawKsks.Data, nil
}

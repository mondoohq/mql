// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// computeSelfLinkPrefixes are the Compute Engine API roots a selfLink can carry.
// The v1 form is what the API returns today; the beta form is accepted so a
// resource fetched through a beta client still resolves.
var computeSelfLinkPrefixes = []string{
	"https://www.googleapis.com/compute/v1/",
	"https://www.googleapis.com/compute/beta/",
	"https://compute.googleapis.com/compute/v1/",
	"https://compute.googleapis.com/compute/beta/",
}

// computeSelfLinkToResourceName converts a Compute Engine selfLink into the full
// resource name the Resource Manager tag APIs expect.
//
//	https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i
//	//compute.googleapis.com/projects/p/zones/z/instances/i
//
// It returns "" for an empty or unrecognized selfLink, which callers treat as
// "cannot resolve" rather than as a resource name.
func computeSelfLinkToResourceName(selfLink string) string {
	if selfLink == "" {
		return ""
	}
	for _, prefix := range computeSelfLinkPrefixes {
		if path, ok := strings.CutPrefix(selfLink, prefix); ok {
			if path == "" {
				return ""
			}
			return "//compute.googleapis.com/" + path
		}
	}
	return ""
}

// effectiveTagsForResource returns every Resource Manager tag value that applies
// to fullResourceName, including values inherited from the enclosing project,
// folder, or organization.
//
// A resource the caller cannot read tags for, or one that has never been bound
// to a tag, yields an empty list rather than an error. That matches the
// behaviour of the older gcp.project.storageService.bucket.tags field, so the
// two report the same thing on the same bucket.
func effectiveTagsForResource(runtime *plugin.Runtime, fullResourceName string) ([]any, error) {
	if fullResourceName == "" {
		return []any{}, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("effective tags require a GCP connection")
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var tags []*cloudresourcemanager.EffectiveTag
	err = svc.EffectiveTags.List().Parent(fullResourceName).Context(ctx).
		Pages(ctx, func(page *cloudresourcemanager.ListEffectiveTagsResponse) error {
			tags = append(tags, page.EffectiveTags...)
			return nil
		})
	if err != nil {
		var gerr *googleapi.Error
		if errors.As(err, &gerr) {
			switch gerr.Code {
			case 403:
				log.Warn().Str("resource", fullResourceName).
					Msg("not permitted to list effective tags, reporting none")
				return []any{}, nil
			case 404:
				log.Debug().Str("resource", fullResourceName).
					Msg("no effective tag bindings for resource")
				return []any{}, nil
			}
		}
		return nil, err
	}

	return effectiveTagsToMql(runtime, fullResourceName, tags)
}

// stringFields reads the string fields an effective-tag resource name is built
// from, surfacing the first error any of them carries. It reports ok=false when
// a field is empty, since a resource name assembled from a blank segment names
// something other than the resource in hand.
func stringFields(fields ...*plugin.TValue[string]) ([]string, bool, error) {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f.Error != nil {
			return nil, false, f.Error
		}
		if f.Data == "" {
			return nil, false, nil
		}
		out = append(out, f.Data)
	}
	return out, true, nil
}

func (g *mqlGcpProjectSqlServiceInstance) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//sqladmin.googleapis.com/projects/%s/instances/%s", p[0], p[1]))
}

func (g *mqlGcpProjectGkeServiceCluster) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Location, &g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//container.googleapis.com/projects/%s/locations/%s/clusters/%s", p[0], p[1], p[2]))
}

func (g *mqlGcpProjectCloudRunServiceService) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Region, &g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//run.googleapis.com/projects/%s/locations/%s/services/%s", p[0], p[1], p[2]))
}

func (g *mqlGcpProjectBigqueryServiceDataset) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Id)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//bigquery.googleapis.com/projects/%s/datasets/%s", p[0], p[1]))
}

func (g *mqlGcpProjectBigqueryServiceTable) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.DatasetId, &g.Id)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//bigquery.googleapis.com/projects/%s/datasets/%s/tables/%s", p[0], p[1], p[2]))
}

func (g *mqlGcpProjectSecretmanagerServiceSecret) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//secretmanager.googleapis.com/projects/%s/secrets/%s", p[0], p[1]))
}

func (g *mqlGcpProjectDnsServiceManagedzone) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.ProjectId, &g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//dns.googleapis.com/projects/%s/managedZones/%s", p[0], p[1]))
}

// effectiveTags on a bucket uses the projects/_ wildcard, which is the
// documented resource-name form for Cloud Storage.
func (g *mqlGcpProjectStorageServiceBucket) effectiveTags() ([]any, error) {
	p, ok, err := stringFields(&g.Name)
	if err != nil || !ok {
		return []any{}, err
	}
	return effectiveTagsForResource(g.MqlRuntime,
		fmt.Sprintf("//storage.googleapis.com/projects/_/buckets/%s", p[0]))
}

// effectiveTagCacheKey builds the cache key for one effective tag.
//
// The key is qualified by fullResourceName because the same tag value
// legitimately applies to many resources at once, and an inherited value
// applies to every resource beneath its parent. Keying on the tag value alone
// would collapse every resource's copy onto whichever one was created first, so
// a fleet-wide query would report one resource's tags for all of them.
func effectiveTagCacheKey(fullResourceName, tagValue string) string {
	return fullResourceName + "/" + tagValue
}

// effectiveTagsToMql maps the API records onto gcp.effectiveTag resources.
func effectiveTagsToMql(runtime *plugin.Runtime, fullResourceName string, tags []*cloudresourcemanager.EffectiveTag) ([]any, error) {
	res := make([]any, 0, len(tags))
	for _, tag := range tags {
		if tag == nil {
			continue
		}
		mqlTag, err := CreateResource(runtime, "gcp.effectiveTag", map[string]*llx.RawData{
			"__id":               llx.StringData(effectiveTagCacheKey(fullResourceName, tag.TagValue)),
			"tagKey":             llx.StringData(tag.TagKey),
			"tagValue":           llx.StringData(tag.TagValue),
			"namespacedTagKey":   llx.StringData(tag.NamespacedTagKey),
			"namespacedTagValue": llx.StringData(tag.NamespacedTagValue),
			"inherited":          llx.BoolData(tag.Inherited),
			"tagKeyParent":       llx.StringData(tag.TagKeyParentName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTag)
	}
	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	packer_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-packer-service/stable/2023-01-01/client/packer_service"
	packermodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-packer-service/stable/2023-01-01/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlHcpPackerRegistryInternal struct {
	cacheProjectID string
}

type mqlHcpPackerBucketInternal struct {
	cacheOrgID     string
	cacheProjectID string
	cacheName      string
}

// codeError is implemented by the SDK's go-openapi default error responses,
// exposing the HTTP status code.
type codeError interface{ Code() int }

// isServiceUnavailable reports whether an SDK error means the product is simply
// not available or entitled for this organization or project, so the caller can
// degrade to an empty/null result rather than failing the whole scan. This
// covers three shapes seen from live HCP APIs:
//   - a 404 (no such resource, e.g. a project with no Packer registry)
//   - a 403 (not entitled, e.g. a Waypoint namespace that is not activated)
//   - an error body the generated client cannot decode, which surfaces as a
//     go-openapi consumer error rather than a typed response (seen from Consul
//     Dedicated, which is winding down, on organizations without it enabled)
func isServiceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var ce codeError
	if errors.As(err, &ce) {
		return ce.Code() == 404 || ce.Code() == 403
	}
	msg := err.Error()
	return strings.Contains(msg, "GrpcGatewayRuntimeError") ||
		strings.Contains(msg, "is not supported by the TextConsumer")
}

// parseVersionCount converts the API's string-encoded version count to an int,
// yielding 0 for an empty or unparseable value.
func parseVersionCount(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// packerRegistry resolves the project's Packer registry, returning null when the
// project has no registry provisioned.
func (r *mqlHcpProject) packerRegistry() (*mqlHcpPackerRegistry, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conn := hcpConn(r.MqlRuntime)
	client := packer_service.New(conn.Transport(), nil)
	params := packer_service.NewPackerServiceGetRegistryParams()
	params.LocationOrganizationID = oid
	params.LocationProjectID = r.Id.Data
	resp, err := client.PackerServiceGetRegistry(params, nil)
	if err != nil {
		if isServiceUnavailable(err) {
			r.PackerRegistry.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if resp.Payload == nil || resp.Payload.Registry == nil {
		r.PackerRegistry.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlHcpPackerRegistry(r.MqlRuntime, r.Id.Data, resp.Payload.Registry)
}

func newMqlHcpPackerRegistry(runtime *plugin.Runtime, projectID string, reg *packermodels.HashicorpCloudPacker20230101Registry) (*mqlHcpPackerRegistry, error) {
	activated := false
	featureTier := ""
	if reg.Config != nil {
		activated = reg.Config.Activated
		featureTier = enumStr(reg.Config.FeatureTier)
	}
	res, err := CreateResource(runtime, "hcp.packer.registry", map[string]*llx.RawData{
		"__id":        llx.StringData("hcp.packer.registry/" + reg.ID),
		"id":          llx.StringData(reg.ID),
		"activated":   llx.BoolData(activated),
		"featureTier": llx.StringData(featureTier),
		"createdAt":   llx.TimeDataPtr(strfmtTime(reg.CreatedAt)),
		"updatedAt":   llx.TimeDataPtr(strfmtTime(reg.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	registry := res.(*mqlHcpPackerRegistry)
	registry.cacheProjectID = projectID
	return registry, nil
}

// initHcpPackerRegistry hydrates a project's Packer registry from the discovered
// asset the connection is scoped to.
func initHcpPackerRegistry(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	_, projectID, err := scopedResourceIDs(runtime, args)
	if err != nil {
		return nil, nil, err
	}
	if projectID == "" {
		return nil, nil, fmt.Errorf("hcp.packer.registry requires a project id")
	}
	proj, err := fetchMqlHcpProject(runtime, projectID)
	if err != nil {
		return nil, nil, err
	}
	reg, err := proj.packerRegistry()
	if err != nil {
		return nil, nil, err
	}
	if reg == nil {
		return nil, nil, fmt.Errorf("hcp.packer.registry not found in project %q", projectID)
	}
	return nil, reg, nil
}

// project resolves the project the registry belongs to.
func (r *mqlHcpPackerRegistry) project() (*mqlHcpProject, error) {
	return projectRef(r.MqlRuntime, &r.Project, r.cacheProjectID)
}

// buckets lists the image buckets in the registry.
func (r *mqlHcpPackerRegistry) buckets() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conn := hcpConn(r.MqlRuntime)
	client := packer_service.New(conn.Transport(), nil)

	out := []any{}
	var nextToken *string
	for {
		params := packer_service.NewPackerServiceListBucketsParams()
		params.LocationOrganizationID = oid
		params.LocationProjectID = r.cacheProjectID
		params.PaginationNextPageToken = nextToken
		resp, err := client.PackerServiceListBuckets(params, nil)
		if err != nil {
			return nil, err
		}
		if resp.Payload == nil {
			break
		}
		for _, b := range resp.Payload.Buckets {
			res, err := newMqlHcpPackerBucket(r.MqlRuntime, oid, r.cacheProjectID, b)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if resp.Payload.Pagination == nil || resp.Payload.Pagination.NextPageToken == "" {
			break
		}
		token := resp.Payload.Pagination.NextPageToken
		nextToken = &token
	}
	return out, nil
}

func newMqlHcpPackerBucket(runtime *plugin.Runtime, orgID, projectID string, b *packermodels.HashicorpCloudPacker20230101Bucket) (*mqlHcpPackerBucket, error) {
	latestVersion := ""
	if b.LatestVersion != nil {
		latestVersion = b.LatestVersion.Fingerprint
	}
	res, err := CreateResource(runtime, "hcp.packer.bucket", map[string]*llx.RawData{
		"__id":          llx.StringData("hcp.packer.bucket/" + projectID + "/" + b.Name),
		"name":          llx.StringData(b.Name),
		"versionCount":  llx.IntData(parseVersionCount(b.VersionCount)),
		"latestVersion": llx.StringData(latestVersion),
		"platforms":     llx.ArrayData(strSlice(b.Platforms), types.String),
		"createdAt":     llx.TimeDataPtr(strfmtTime(b.CreatedAt)),
		"updatedAt":     llx.TimeDataPtr(strfmtTime(b.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	bucket := res.(*mqlHcpPackerBucket)
	bucket.cacheOrgID = orgID
	bucket.cacheProjectID = projectID
	bucket.cacheName = b.Name
	return bucket, nil
}

// channels resolves the bucket's channel assignments as a map of channel name
// to the version fingerprint the channel currently points at.
func (r *mqlHcpPackerBucket) channels() (map[string]any, error) {
	conn := hcpConn(r.MqlRuntime)
	client := packer_service.New(conn.Transport(), nil)
	params := packer_service.NewPackerServiceListChannelsParams()
	params.LocationOrganizationID = r.cacheOrgID
	params.LocationProjectID = r.cacheProjectID
	params.BucketName = r.cacheName
	resp, err := client.PackerServiceListChannels(params, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if resp.Payload == nil {
		return out, nil
	}
	for _, ch := range resp.Payload.Channels {
		fingerprint := ""
		if ch.Version != nil {
			fingerprint = ch.Version.Fingerprint
		}
		out[ch.Name] = fingerprint
	}
	return out, nil
}

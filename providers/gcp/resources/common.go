// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/gcp/connection"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// protoToDict converts a protobuf message to a map[string]any suitable for use as a dict field.
// Returns nil for nil input.
func protoToDict(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return nil, nil
	}
	data, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (g *mqlGcpRetryConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func newRetryConfigResource(runtime *plugin.Runtime, parentId string, maxAttempts int64, minBackoff, maxBackoff string, maxDoublings int64, maxRetryDuration string) (*mqlGcpRetryConfig, error) {
	res, err := CreateResource(runtime, "gcp.retryConfig", map[string]*llx.RawData{
		"id":               llx.StringData(parentId + "/retryConfig"),
		"maxAttempts":      llx.IntData(maxAttempts),
		"minBackoff":       llx.StringData(minBackoff),
		"maxBackoff":       llx.StringData(maxBackoff),
		"maxDoublings":     llx.IntData(maxDoublings),
		"maxRetryDuration": llx.StringData(maxRetryDuration),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpRetryConfig), nil
}

func RegionNameFromRegionUrl(regionUrl string) string {
	regionUrlSegments := strings.Split(regionUrl, "/")
	return regionUrlSegments[len(regionUrlSegments)-1]
}

func timestampAsTimePtr(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	tm := t.AsTime()
	return &tm
}

// parseResourceName returns the name of a resource from either a full path or just the name.
func parseResourceName(fullPath string) string {
	segments := strings.Split(fullPath, "/")
	return segments[len(segments)-1]
}

// parseLocationFromPath extracts the location/region from a GCP resource path.
// The path format is: projects/{project}/locations/{location}/...
// Returns "global" if no location segment is found.
func parseLocationFromPath(fullPath string) string {
	segments := strings.Split(fullPath, "/")
	for i, s := range segments {
		if s == "locations" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return "global"
}

type assetIdentifier struct {
	name    string
	region  string
	project string
}

func getAssetIdentifier(runtime *plugin.Runtime) *assetIdentifier {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil
	}
	id := conn.Asset().PlatformIds[0]

	if strings.HasPrefix(id, "//platformid.api.mondoo.app/runtime/gcp/") {
		// "//platformid.api.mondoo.app/runtime/gcp/{o.service}/v1/projects/{project}/regions/{region}/{objectType}/{name}"
		segments := strings.Split(id, "/")
		if len(segments) < 12 {
			return nil
		}
		name := segments[len(segments)-1]
		region := segments[10]
		project := segments[8]
		return &assetIdentifier{name: name, region: region, project: project}
	}

	return nil
}

type resourceId struct {
	Project string
	Region  string
	Name    string
}

func getNetworkByUrl(networkUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceNetwork, error) {
	// A reference to a network is not mandatory for this resource
	if networkUrl == "" {
		return nil, nil
	}

	// Format is https://www.googleapis.com/compute/v1/projects/project1/global/networks/net-1
	// or https://compute.googleapis.com/compute/v1/projects/project1/global/networks/net-1
	params := strings.TrimPrefix(networkUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	resId := resourceId{Project: parts[1], Region: parts[2], Name: parts[4]}

	res, err := CreateResource(runtime, "gcp.project.computeService.network", map[string]*llx.RawData{
		"name":      llx.StringData(resId.Name),
		"projectId": llx.StringData(resId.Project),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceNetwork), nil
}

func getSubnetworkByUrl(subnetUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceSubnetwork, error) {
	// A reference to a subnetwork is not mandatory for this resource
	if subnetUrl == "" {
		return nil, nil
	}

	// Format is https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/subnet-1
	// or https://compute.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/subnet-1
	params := strings.TrimPrefix(subnetUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	resId := resourceId{Project: parts[1], Region: parts[3], Name: parts[5]}
	// regionUrl is the full URL up to and including the region segment
	regionUrl := "https://www.googleapis.com/compute/v1/projects/" + resId.Project + "/regions/" + resId.Region

	res, err := CreateResource(runtime, "gcp.project.computeService.subnetwork", map[string]*llx.RawData{
		"name":      llx.StringData(resId.Name),
		"projectId": llx.StringData(resId.Project),
		"regionUrl": llx.StringData(regionUrl),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceSubnetwork), nil
}

func getDiskIdByUrl(diskUrl string) (*resourceId, error) {
	// A reference to a subnetwork is not mandatory for this resource
	if diskUrl == "" {
		return nil, errors.New("diskUrl is empty")
	}

	// Format is https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/disks/disk-1
	// or https://compute.googleapis.com/compute/v1/projects/project1/regions/us-central1/disks/disk-1
	params := strings.TrimPrefix(diskUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	return &resourceId{Project: parts[1], Region: parts[3], Name: parts[5]}, nil
}

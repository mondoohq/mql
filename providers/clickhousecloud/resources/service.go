// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/clickhousecloud/connection"
)

type apiIPAccess struct {
	Source      string `json:"source"`
	Description string `json:"description"`
}

type apiEndpoint struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

type apiService struct {
	ID                           string        `json:"id"`
	Name                         string        `json:"name"`
	Provider                     string        `json:"provider"`
	Region                       string        `json:"region"`
	State                        string        `json:"state"`
	Tier                         string        `json:"tier"`
	IPAccessList                 []apiIPAccess `json:"ipAccessList"`
	Endpoints                    []apiEndpoint `json:"endpoints"`
	HasTransparentDataEncryption bool          `json:"hasTransparentDataEncryption"`
	PrivateEndpointIds           []string      `json:"privateEndpointIds"`
	IsReadonly                   bool          `json:"isReadonly"`
	MinReplicaMemoryGb           int           `json:"minReplicaMemoryGb"`
	MaxReplicaMemoryGb           int           `json:"maxReplicaMemoryGb"`
	NumReplicas                  int           `json:"numReplicas"`
	IdleScaling                  bool          `json:"idleScaling"`
	IdleTimeoutMinutes           int           `json:"idleTimeoutMinutes"`
	ReleaseChannel               string        `json:"releaseChannel"`
}

func (r *mqlClickhousecloudOrganization) services() ([]any, error) {
	conn := clickhousecloudConn(r.MqlRuntime)
	// The ClickHouse Cloud org-scoped list endpoints (/services, /keys, /members)
	// are not paginated: the response envelope is {requestId, result, status}
	// with no cursor, so a single GET returns the full list.
	var services []apiService
	if err := conn.Get(conn.Context(), "/services", &services); err != nil {
		if connection.IsPermissionError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	orgID := conn.OrgID()
	list := []any{}
	for i := range services {
		svc := services[i]

		ipList, openToAll, err := r.buildIPAccessList(orgID, svc)
		if err != nil {
			return nil, err
		}
		endpoints, err := r.buildEndpoints(orgID, svc)
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(r.MqlRuntime, "clickhousecloud.service", map[string]*llx.RawData{
			"__id":                         llx.StringData(orgID + "/service/" + svc.ID),
			"id":                           llx.StringData(svc.ID),
			"name":                         llx.StringData(svc.Name),
			"cloudProvider":                llx.StringData(svc.Provider),
			"region":                       llx.StringData(svc.Region),
			"state":                        llx.StringData(svc.State),
			"tier":                         llx.StringData(svc.Tier),
			"openToAllIps":                 llx.BoolData(openToAll),
			"ipAccessList":                 llx.ArrayData(ipList, "clickhousecloud.service.ipAccess"),
			"endpoints":                    llx.ArrayData(endpoints, "clickhousecloud.service.endpoint"),
			"hasTransparentDataEncryption": llx.BoolData(svc.HasTransparentDataEncryption),
			"hasPrivateEndpoints":          llx.BoolData(len(svc.PrivateEndpointIds) > 0),
			"privateEndpointIds":           llx.ArrayData(toAnySlice(svc.PrivateEndpointIds), "string"),
			"isReadonly":                   llx.BoolData(svc.IsReadonly),
			"minReplicaMemoryGb":           llx.IntData(int64(svc.MinReplicaMemoryGb)),
			"maxReplicaMemoryGb":           llx.IntData(int64(svc.MaxReplicaMemoryGb)),
			"numReplicas":                  llx.IntData(int64(svc.NumReplicas)),
			"idleScaling":                  llx.BoolData(svc.IdleScaling),
			"idleTimeoutMinutes":           llx.IntData(int64(svc.IdleTimeoutMinutes)),
			"releaseChannel":               llx.StringData(svc.ReleaseChannel),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// buildIPAccessList builds the typed ipAccess rows and reports whether any entry
// opens the service to all IPs.
func (r *mqlClickhousecloudOrganization) buildIPAccessList(orgID string, svc apiService) ([]any, bool, error) {
	out := []any{}
	openToAll := false
	for i, ip := range svc.IPAccessList {
		if ip.Source == "0.0.0.0/0" || ip.Source == "::/0" {
			openToAll = true
		}
		// The index keeps the key unique even if the API ever returns duplicate
		// sources.
		res, err := CreateResource(r.MqlRuntime, "clickhousecloud.service.ipAccess", map[string]*llx.RawData{
			"__id":        llx.StringData(orgID + "/service/" + svc.ID + "/ip/" + strconv.Itoa(i) + "/" + ip.Source),
			"source":      llx.StringData(ip.Source),
			"description": llx.StringData(ip.Description),
		})
		if err != nil {
			return nil, false, err
		}
		out = append(out, res)
	}
	return out, openToAll, nil
}

func (r *mqlClickhousecloudOrganization) buildEndpoints(orgID string, svc apiService) ([]any, error) {
	out := []any{}
	for _, ep := range svc.Endpoints {
		// Include host and port so two endpoints sharing a protocol (for example
		// two https endpoints on different ports) get distinct keys.
		res, err := CreateResource(r.MqlRuntime, "clickhousecloud.service.endpoint", map[string]*llx.RawData{
			"__id":     llx.StringData(orgID + "/service/" + svc.ID + "/endpoint/" + ep.Protocol + "/" + ep.Host + ":" + strconv.Itoa(ep.Port)),
			"protocol": llx.StringData(ep.Protocol),
			"host":     llx.StringData(ep.Host),
			"port":     llx.IntData(int64(ep.Port)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

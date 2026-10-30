// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

type mqlOciOkeAddonInternal struct {
	cluster *mqlOciOkeCluster
}

// addons lists the add-ons of the cluster, the essential ones OKE installs on
// every cluster included.
func (o *mqlOciOkeCluster) addons() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.ContainerEngineClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	clusterID := o.Id.Data
	items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]containerengine.AddonSummary, *string, error) {
		resp, err := svc.ListAddons(ctx, containerengine.ListAddonsRequest{
			ClusterId: new(clusterID),
			Page:      page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		a := items[i]
		var errCode, errMessage string
		if a.AddonError != nil {
			errCode = stringValue(a.AddonError.Code)
			errMessage = stringValue(a.AddonError.Message)
		}
		var created *time.Time
		if a.TimeCreated != nil {
			created = &a.TimeCreated.Time
		}
		r, err := CreateResource(o.MqlRuntime, "oci.oke.addon", map[string]*llx.RawData{
			"__id":                    llx.StringData(clusterID + "/addon/" + stringValue(a.Name)),
			"name":                    llx.StringDataPtr(a.Name),
			"version":                 llx.StringData(stringValue(a.Version)),
			"currentInstalledVersion": llx.StringData(stringValue(a.CurrentInstalledVersion)),
			"state":                   llx.StringData(string(a.LifecycleState)),
			"errorCode":               llx.StringData(errCode),
			"errorMessage":            llx.StringData(errMessage),
			"created":                 llx.TimeDataPtr(created),
		})
		if err != nil {
			return nil, err
		}
		addon := r.(*mqlOciOkeAddon)
		addon.cluster = o
		res = append(res, addon)
	}
	return res, nil
}

// fetchAddonOptions lists, once per cluster, the add-on options Oracle offers
// for the cluster's Kubernetes version, keyed by add-on name. Every version is
// requested, deprecated ones and detailed builds included: an installed
// version is reported as a build, which the default listing leaves out.
func (o *mqlOciOkeCluster) fetchAddonOptions() (map[string]containerengine.AddonOptionSummary, error) {
	return o.addonOptions.get(func() (map[string]containerengine.AddonOptionSummary, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.ContainerEngineClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		k8sVersion := o.KubernetesVersion.Data
		items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]containerengine.AddonOptionSummary, *string, error) {
			resp, err := svc.ListAddonOptions(ctx, containerengine.ListAddonOptionsRequest{
				KubernetesVersion:     new(k8sVersion),
				ShouldShowAllVersions: new(true),
				Page:                  page,
			})
			if err != nil {
				return nil, nil, err
			}
			return resp.Items, resp.OpcNextPage, nil
		})
		if err != nil {
			return nil, err
		}
		res := make(map[string]containerengine.AddonOptionSummary, len(items))
		for _, it := range items {
			res[stringValue(it.Name)] = it
		}
		return res, nil
	})
}

func (o *mqlOciOkeAddon) id() (string, error) {
	return "oci.oke.addon/" + o.__id, nil
}

func (o *mqlOciOkeAddon) isEssential() (bool, error) {
	if o.cluster == nil {
		o.IsEssential.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	opts, err := o.cluster.fetchAddonOptions()
	if err != nil {
		return false, err
	}
	opt, ok := opts[o.Name.Data]
	if !ok {
		o.IsEssential.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return boolValue(opt.IsEssential), nil
}

func (o *mqlOciOkeAddon) availableVersions() ([]any, error) {
	if o.cluster == nil {
		return []any{}, nil
	}
	opts, err := o.cluster.fetchAddonOptions()
	if err != nil {
		return nil, err
	}
	opt, ok := opts[o.Name.Data]
	if !ok {
		return []any{}, nil
	}
	versions := okeAddonVersionsFor(opt.Versions, o.cluster.KubernetesVersion.Data)
	res := make([]any, 0, len(versions))
	for _, v := range versions {
		r, err := CreateResource(o.MqlRuntime, "oci.oke.addonVersion", map[string]*llx.RawData{
			"__id":        llx.StringData(o.__id + "/version/" + stringValue(v.VersionNumber)),
			"number":      llx.StringData(stringValue(v.VersionNumber)),
			"status":      llx.StringData(string(v.Status)),
			"description": llx.StringData(stringValue(v.Description)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// okeAddonVersionsFor keeps the add-on versions whose Kubernetes version
// filters admit k8sVersion: one of the exact versions when the filter names
// them, else at least the minimal and at most the maximum version, where set.
// A version without filters is offered for every Kubernetes version.
func okeAddonVersionsFor(versions []containerengine.AddonVersions, k8sVersion string) []containerengine.AddonVersions {
	res := make([]containerengine.AddonVersions, 0, len(versions))
	for _, v := range versions {
		if okeKubernetesVersionAdmitted(v.KubernetesVersionFilters, k8sVersion) {
			res = append(res, v)
		}
	}
	return res
}

func okeKubernetesVersionAdmitted(f *containerengine.KubernetesVersionsFilters, k8sVersion string) bool {
	if f == nil {
		return true
	}
	if len(f.ExactKubernetesVersions) > 0 {
		for _, e := range f.ExactKubernetesVersions {
			if compareOkeVersions(e, k8sVersion) == 0 {
				return true
			}
		}
		return false
	}
	if minVersion := stringValue(f.MinimalVersion); minVersion != "" && compareOkeVersions(k8sVersion, minVersion) < 0 {
		return false
	}
	if maxVersion := stringValue(f.MaximumVersion); maxVersion != "" && compareOkeVersions(k8sVersion, maxVersion) > 0 {
		return false
	}
	return true
}

// compareOkeVersions compares Kubernetes versions such as v1.34.1 by their
// numeric parts, so v1.34.10 is newer than v1.34.2. A part that is not a
// number compares as text.
func compareOkeVersions(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(strings.TrimSpace(a), "v"), ".")
	pb := strings.Split(strings.TrimPrefix(strings.TrimSpace(b), "v"), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		switch {
		case x == y:
			continue
		case ex == nil && ey == nil:
			if nx < ny {
				return -1
			}
			return 1
		case x == "":
			return -1
		case y == "":
			return 1
		default:
			return strings.Compare(x, y)
		}
	}
	return 0
}

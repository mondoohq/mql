// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"time"

	polardb "github.com/alibabacloud-go/polardb-20170801/v10/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// mqlAlicloudPolardbApplicationInternal caches what the application needs to
// make its TLS detail call and to resolve its typed cluster reference.
type mqlAlicloudPolardbApplicationInternal struct {
	polardbApplicationSSLState
	polardbApplicationAttributeState
	region         string
	applicationId  string
	cacheClusterID string
}

// polardbApplicationSSLState memoizes the application's TLS configuration,
// which every certificate field and both TLS switches read.
type polardbApplicationSSLState struct {
	sslOnce sync.Once
	ssl     *polardb.DescribeApplicationSSLResponseBody
}

// applicationSSL reads the application's TLS configuration once. An application
// whose configuration cannot be read yields nil, which sslEnabled reports as
// TLS off and every certificate field reports as null: one unreadable
// application must not fail a query over the whole fleet, and reporting TLS as
// off fails a "TLS is on" check rather than passing it on data nobody read.
func (r *mqlAlicloudPolardbApplication) applicationSSL() *polardb.DescribeApplicationSSLResponseBody {
	r.sslOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.PolarDBClient(r.region)
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach PolarDB to read the application TLS config")
			return
		}
		resp, err := client.DescribeApplicationSSL(&polardb.DescribeApplicationSSLRequest{
			ApplicationId: new(r.applicationId),
		})
		if err != nil {
			log.Debug().Err(err).Str("application", r.applicationId).
				Msg("alicloud> could not read the PolarDB application TLS config")
			return
		}
		if resp == nil {
			return
		}
		r.ssl = resp.Body
	})
	return r.ssl
}

// polardbApplicationEndpointsToDict flattens the application's network
// addresses. Each entry carries the network type, which is what tells a public
// address from a VPC-internal one.
func polardbApplicationEndpointsToDict(endpoints *polardb.DescribeApplicationsResponseBodyItemsApplicationsEndpoints) []any {
	res := []any{}
	if endpoints == nil {
		return res
	}
	for _, e := range endpoints.Endpoint {
		if e == nil {
			continue
		}
		res = append(res, map[string]any{
			"ip":      polardbStr(e.IP),
			"netType": polardbStr(e.NetType),
			"port":    polardbStr(e.Port),
		})
	}
	return res
}

// polardbApplicationTagsToMap flattens the application's tag list.
func polardbApplicationTagsToMap(tags *polardb.DescribeApplicationsResponseBodyItemsApplicationsTags) map[string]any {
	res := map[string]any{}
	if tags == nil {
		return res
	}
	for _, t := range tags.Tag {
		if t == nil || t.Key == nil {
			continue
		}
		res[*t.Key] = polardbStr(t.Value)
	}
	return res
}

// applications lists the applications provisioned on the cluster. A cluster
// running none, or on an account without the PolarDB application feature,
// yields an empty list rather than failing the cluster query.
func (r *mqlAlicloudPolardbCluster) applications() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		pn := pageNumber
		ps := pageSize
		resp, err := client.DescribeApplications(&polardb.DescribeApplicationsRequest{
			RegionId:    new(r.region),
			DBClusterId: new(r.dbClusterId),
			PageNumber:  &pn,
			PageSize:    &ps,
		})
		if err != nil {
			log.Debug().Err(err).Str("cluster", r.dbClusterId).
				Msg("alicloud> could not list PolarDB applications")
			return res, nil
		}
		if resp == nil || resp.Body == nil || resp.Body.Items == nil {
			return res, nil
		}

		apps := resp.Body.Items.Applications
		for _, a := range apps {
			if a == nil || a.ApplicationId == nil {
				continue
			}
			app, err := newPolardbApplication(r.MqlRuntime, r.region, r.dbClusterId, a)
			if err != nil {
				return nil, err
			}
			res = append(res, app)
		}

		// Stop once the final page returns fewer than a full page of
		// applications, matching how the cluster list walks its pages.
		if len(apps) < int(pageSize) {
			break
		}
		pageNumber++
	}

	return res, nil
}

func newPolardbApplication(runtime *plugin.Runtime, region string, clusterID string, a *polardb.DescribeApplicationsResponseBodyItemsApplications) (*mqlAlicloudPolardbApplication, error) {
	applicationID := tea.StringValue(a.ApplicationId)
	resource, err := CreateResource(runtime, "alicloud.polardb.application", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + applicationID),
		"applicationId":     llx.StringDataPtr(a.ApplicationId),
		"applicationType":   llx.StringDataPtr(a.ApplicationType),
		"description":       llx.StringDataPtr(a.Description),
		"engineVersion":     llx.StringDataPtr(a.EngineVersion),
		"status":            llx.StringDataPtr(a.Status),
		"regionId":          llx.StringDataPtr(a.RegionId),
		"zoneId":            llx.StringDataPtr(a.ZoneId),
		"payType":           llx.StringDataPtr(a.PayType),
		"createTime":        llx.TimeDataPtr(polardbParseTime(a.CreationTime)),
		"expireTime":        llx.TimeDataPtr(polardbParseTime(a.ExpireTime)),
		"expired":           llx.StringDataPtr(a.Expired),
		"polarFsInstanceId": llx.StringDataPtr(a.PolarFSInstanceId),
		"endpoints":         llx.ArrayData(polardbApplicationEndpointsToDict(a.Endpoints), types.Dict),
		"tags":              llx.MapData(polardbApplicationTagsToMap(a.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	app := resource.(*mqlAlicloudPolardbApplication)
	app.region = region
	app.applicationId = applicationID
	// The list response repeats the cluster it belongs to, but the application
	// is only ever built from a cluster, so fall back to that cluster's id when
	// the field is absent.
	app.cacheClusterID = polardbStr(a.DBClusterId)
	if app.cacheClusterID == "" {
		app.cacheClusterID = clusterID
	}
	return app, nil
}

func (r *mqlAlicloudPolardbApplication) id() (string, error) {
	return r.region + "/" + r.applicationId, nil
}

func (r *mqlAlicloudPolardbApplication) dbCluster() (*mqlAlicloudPolardbCluster, error) {
	if r.cacheClusterID == "" {
		r.DbCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.polardb.cluster", map[string]*llx.RawData{
		"dbClusterId": llx.StringData(r.cacheClusterID),
		"regionId":    llx.StringData(r.region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudPolardbCluster), nil
}

func (r *mqlAlicloudPolardbApplication) sslEnabled() (bool, error) {
	ssl := r.applicationSSL()
	if ssl == nil || ssl.SSLEnabled == nil {
		return false, nil
	}
	return *ssl.SSLEnabled, nil
}

// sslCertReadable returns the TLS configuration only when a certificate is
// actually present, so every certificate field reports null when TLS is off or
// the configuration could not be read. The API leaves these empty in that case,
// and an empty string would read as a certificate with a blank Common Name
// rather than as "there is no certificate".
func (r *mqlAlicloudPolardbApplication) sslCertReadable() *polardb.DescribeApplicationSSLResponseBody {
	ssl := r.applicationSSL()
	if ssl == nil || ssl.SSLEnabled == nil || !*ssl.SSLEnabled {
		return nil
	}
	return ssl
}

func (r *mqlAlicloudPolardbApplication) sslAutoRotate() (bool, error) {
	ssl := r.sslCertReadable()
	if ssl == nil || ssl.SSLAutoRotate == nil {
		r.SslAutoRotate.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *ssl.SSLAutoRotate, nil
}

func (r *mqlAlicloudPolardbApplication) certCommonName() (string, error) {
	ssl := r.sslCertReadable()
	if ssl == nil || ssl.CertCommonName == nil {
		r.CertCommonName.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *ssl.CertCommonName, nil
}

func (r *mqlAlicloudPolardbApplication) certSource() (string, error) {
	ssl := r.sslCertReadable()
	if ssl == nil || ssl.CertSource == nil {
		r.CertSource.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *ssl.CertSource, nil
}

func (r *mqlAlicloudPolardbApplication) certFingerprintSha256() (string, error) {
	ssl := r.sslCertReadable()
	if ssl == nil || ssl.CertFingerprintSha256Der == nil {
		r.CertFingerprintSha256.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *ssl.CertFingerprintSha256Der, nil
}

func (r *mqlAlicloudPolardbApplication) certExpireTime() (*time.Time, error) {
	ssl := r.sslCertReadable()
	if ssl == nil {
		return nil, nil
	}
	return polardbParseTime(ssl.CertExpiredTime), nil
}

func (r *mqlAlicloudPolardbApplication) certModifiedTime() (*time.Time, error) {
	ssl := r.sslCertReadable()
	if ssl == nil {
		return nil, nil
	}
	return polardbParseTime(ssl.CertModifiedTime), nil
}

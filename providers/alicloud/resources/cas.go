// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"time"

	casclient "github.com/alibabacloud-go/cas-20200407/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// casPageSize is the page size used for ListUserCertificateOrder.
const casPageSize = 100

func (r *mqlAlicloudCas) id() (string, error) {
	return "alicloud.cas", nil
}

// certificates lists the account's SSL certificates. Certificates are held in
// the center that owns the account, which is not knowable in advance, so both
// centers are read and a certificate reported by both is kept once. The
// listing fails only when neither center can be read.
func (r *mqlAlicloudCas) certificates() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)

	res := []any{}
	seen := map[int64]bool{}
	var lastErr error
	answered := false
	for _, center := range alicloudCenterRegions {
		certs, err := casCertificatesIn(conn, center)
		if err != nil {
			lastErr = err
			logSkippedRegion(err, "Certificate Management Service", center)
			continue
		}
		answered = true
		for _, c := range certs {
			id := tea.Int64Value(c.CertificateId)
			if c.CertificateId == nil || seen[id] {
				continue
			}
			seen[id] = true
			cert, err := newCasCertificate(r.MqlRuntime, c)
			if err != nil {
				return nil, err
			}
			res = append(res, cert)
		}
	}
	if !answered && lastErr != nil {
		return nil, classifyAlicloudError(lastErr, "yundun-cert:ListUserCertificateOrder")
	}
	return res, nil
}

// casCertificatesIn walks every page of one center's certificate list. The
// CERT order type returns issued and uploaded certificates, not purchase
// orders.
func casCertificatesIn(conn *connection.AlicloudConnection, center string) ([]*casclient.ListUserCertificateOrderResponseBodyCertificateOrderList, error) {
	client, err := conn.CasClient(center)
	if err != nil {
		return nil, err
	}
	res := []*casclient.ListUserCertificateOrderResponseBodyCertificateOrderList{}
	page := int64(1)
	for {
		resp, err := client.ListUserCertificateOrder(&casclient.ListUserCertificateOrderRequest{
			OrderType:   tea.String("CERT"),
			CurrentPage: tea.Int64(page),
			ShowSize:    tea.Int64(casPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.CertificateOrderList
		res = append(res, items...)
		if casPageDone(len(items), page, casPageSize, resp.Body.TotalCount) {
			break
		}
		page++
	}
	return res, nil
}

// casPageDone reports whether a certificate listing is complete: the page came
// back short or empty, or every certificate the total announces has been read.
func casPageDone(itemCount int, page int64, pageSize int64, total *int64) bool {
	if itemCount == 0 || int64(itemCount) < pageSize {
		return true
	}
	if total != nil && page*pageSize >= *total {
		return true
	}
	return false
}

func newCasCertificate(runtime *plugin.Runtime, c *casclient.ListUserCertificateOrderResponseBodyCertificateOrderList) (plugin.Resource, error) {
	return CreateResource(runtime, "alicloud.cas.certificate", map[string]*llx.RawData{
		"__id":                    llx.StringData("alicloud.cas.certificate/" + strconv.FormatInt(tea.Int64Value(c.CertificateId), 10)),
		"certificateId":           llx.IntDataPtr(c.CertificateId),
		"name":                    llx.StringDataPtr(c.Name),
		"commonName":              llx.StringDataPtr(c.CommonName),
		"subjectAlternativeNames": llx.ArrayData(stringsToAny(splitCommaList(c.Sans)), types.String),
		"issuer":                  llx.StringDataPtr(c.Issuer),
		"algorithm":               llx.StringDataPtr(c.Algorithm),
		"fingerprint":             llx.StringDataPtr(c.Fingerprint),
		"serialNumber":            llx.StringDataPtr(c.SerialNo),
		"notBefore":               llx.TimeDataPtr(casCertificateTime(c.StartDate, c.CertStartTime)),
		"notAfter":                llx.TimeDataPtr(casCertificateTime(c.EndDate, c.CertEndTime)),
		"expired":                 llx.BoolDataPtr(c.Expired),
		"status":                  llx.StringDataPtr(c.Status),
		"uploaded":                llx.BoolDataPtr(c.Upload),
		"resourceGroupId":         llx.StringDataPtr(c.ResourceGroupId),
	})
}

// casCertificateTime reads a certificate validity bound. The CERT listing
// reports it as a YYYY-MM-DD date, while some responses carry only the epoch
// value, so the epoch is the fallback.
func casCertificateTime(date *string, epoch *int64) *time.Time {
	if t := parseAlicloudTime(date); t != nil {
		return t
	}
	return epochAuto(epoch)
}

func (r *mqlAlicloudCasCertificate) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

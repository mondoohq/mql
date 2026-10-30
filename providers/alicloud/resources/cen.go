// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	cbnclient "github.com/alibabacloud-go/cbn-20170912/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// cenPageSize is the per-request item count for the page-numbered CEN APIs.
const cenPageSize int32 = 50

func (r *mqlAlicloudCen) id() (string, error) {
	return "alicloud.cen", nil
}

func (r *mqlAlicloudCen) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CenClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	for {
		resp, err := client.DescribeCens(&cbnclient.DescribeCensRequest{
			PageNumber: new(pageNumber),
			PageSize:   new(cenPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Cens == nil {
			break
		}

		items := resp.Body.Cens.Cen
		for _, c := range items {
			if c == nil || c.CenId == nil {
				continue
			}

			tags := map[string]any{}
			if c.Tags != nil {
				for _, t := range c.Tags.Tag {
					if t == nil || t.Key == nil {
						continue
					}
					tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
				}
			}

			// check the tag filters before building the resource, so a
			// filtered-out CEN is never cached
			if filteredOutByTags(conn, tags) {
				continue
			}

			cen, err := CreateResource(r.MqlRuntime, "alicloud.cen.instance", map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(c.CenId),
				"cenId":           llx.StringDataPtr(c.CenId),
				"name":            llx.StringDataPtr(c.Name),
				"description":     llx.StringDataPtr(c.Description),
				"status":          llx.StringDataPtr(c.Status),
				"protectionLevel": llx.StringDataPtr(c.ProtectionLevel),
				"ipv6Level":       llx.StringDataPtr(c.Ipv6Level),
				"resourceGroupId": llx.StringDataPtr(c.ResourceGroupId),
				"creationTime":    llx.TimeDataPtr(cloudssoParseTime(c.CreationTime)),
				"tags":            llx.MapData(tags, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, cen)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) == 0 || total == 0 || pageNumber*cenPageSize >= total {
			break
		}
		pageNumber++
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.cen.attachment
// ---------------------------------------------------------------------------

func (r *mqlAlicloudCenAttachment) id() (string, error) {
	return r.CenId.Data + "/" + r.ChildInstanceId.Data, nil
}

// mqlAlicloudCenAttachmentInternal caches what the typed VPC reference needs,
// since the attachment listing reports the network's region rather than the
// connection's.
type mqlAlicloudCenAttachmentInternal struct {
	cacheRegion    string
	cacheVpcID     string
	cacheForeignRD bool
}

func (r *mqlAlicloudCenInstance) attachments() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CenClient()
	if err != nil {
		return nil, err
	}

	accountID := conn.AccountID()
	cenID := r.CenId.Data

	res := []any{}
	pageNumber := int32(1)
	for {
		resp, err := client.DescribeCenAttachedChildInstances(&cbnclient.DescribeCenAttachedChildInstancesRequest{
			CenId:      new(cenID),
			PageNumber: new(pageNumber),
			PageSize:   new(cenPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.ChildInstances == nil {
			break
		}

		items := resp.Body.ChildInstances.ChildInstance
		for _, a := range items {
			if a == nil || a.ChildInstanceId == nil {
				continue
			}
			ownerID := tea.Int64Value(a.ChildInstanceOwnerId)
			attachment, err := CreateResource(r.MqlRuntime, "alicloud.cen.attachment", map[string]*llx.RawData{
				"__id":                  llx.StringData(cenID + "/" + tea.StringValue(a.ChildInstanceId)),
				"cenId":                 llx.StringData(cenID),
				"childInstanceId":       llx.StringDataPtr(a.ChildInstanceId),
				"childInstanceType":     llx.StringDataPtr(a.ChildInstanceType),
				"childInstanceRegionId": llx.StringDataPtr(a.ChildInstanceRegionId),
				"childInstanceOwnerId":  llx.IntDataPtr(a.ChildInstanceOwnerId),
				"status":                llx.StringDataPtr(a.Status),
				"attachTime":            llx.TimeDataPtr(cloudssoParseTime(a.ChildInstanceAttachTime)),
			})
			if err != nil {
				return nil, err
			}

			mqlAttachment := attachment.(*mqlAlicloudCenAttachment)
			mqlAttachment.cacheRegion = tea.StringValue(a.ChildInstanceRegionId)
			if tea.StringValue(a.ChildInstanceType) == "VPC" {
				mqlAttachment.cacheVpcID = tea.StringValue(a.ChildInstanceId)
			}
			// an attachment owned by another account cannot be read with this
			// credential, so the typed reference stays null rather than erroring
			mqlAttachment.cacheForeignRD = accountID != "" && ownerID != 0 &&
				strconv.FormatInt(ownerID, 10) != accountID

			res = append(res, mqlAttachment)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) == 0 || total == 0 || pageNumber*cenPageSize >= total {
			break
		}
		pageNumber++
	}
	return res, nil
}

// vpc resolves the VPC behind a VPC attachment.
func (r *mqlAlicloudCenAttachment) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" || r.cacheRegion == "" || r.cacheForeignRD {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	network, err := resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
	if err != nil {
		// a VPC can be detached and deleted while the attachment record lingers
		log.Debug().Err(err).Str("vpc", r.cacheVpcID).
			Msg("alicloud: could not resolve VPC behind CEN attachment")
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return network, nil
}

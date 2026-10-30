// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	crclient "github.com/alibabacloud-go/cr-20181201/v3/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// acrTagPageSize is the page size used when enumerating image tags and their
// scan findings. Both endpoints default to 30.
const acrTagPageSize = 100

// acrVulnerabilityID builds the cache key for a single scan finding. A finding
// is one CVE in one package, not one CVE, so the same CveName legitimately
// appears once per affected package and the CVE alone is not an identity. The
// key therefore carries every dimension a row varies along: the package, its
// installed version, the image layer that introduced it, and the path it was
// found at. Two rows agreeing on all of those are a genuine duplicate and are
// meant to collapse. cveLocation is a path and is placed last so that the one
// segment able to contain a separator cannot shift across a field boundary.
func acrVulnerabilityID(repoID, tag string, v *crclient.ListRepoTagScanResultResponseBodyVulnerabilities) string {
	return strings.Join([]string{
		repoID,
		tag,
		tea.StringValue(v.CveName),
		tea.StringValue(v.Feature),
		tea.StringValue(v.Version),
		tea.StringValue(v.AddedBy),
		tea.StringValue(v.CveLocation),
	}, "/")
}

// acrScanComplete reports whether an image scan finished. Only COMPLETE counts:
// SCANNING and RETRYING are in progress, FAILED produced nothing, and an empty
// status means the registry never scanned the image. All four leave the
// vulnerability list empty, which must not be read as a clean image.
func acrScanComplete(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "COMPLETE")
}

// acrSeverityCounts tallies scan findings by severity. Severity is compared
// case-insensitively, and a finding the scanner could not rate is counted under
// the empty key so it is reported rather than silently dropped.
func acrSeverityCounts(vulnerabilities []any) map[string]int64 {
	counts := map[string]int64{}
	for _, entry := range vulnerabilities {
		vuln, ok := entry.(*mqlAlicloudAcrVulnerability)
		if !ok {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(vuln.Severity.Data))
		if severity == "" {
			severity = "unknown"
		}
		counts[severity]++
	}
	return counts
}

// mqlAlicloudAcrRepositoryTagInternal carries the registry client keys the tag's
// scan lookups need, and memoizes them so the scan status and the seven derived
// count fields share one call each.
type mqlAlicloudAcrRepositoryTagInternal struct {
	region string

	scanStatusOnce  sync.Once
	scanStatusValue string
}

func (r *mqlAlicloudAcrRepositoryTag) id() (string, error) {
	return r.RepoId.Data + "/" + r.Tag.Data, nil
}

// imageTags enumerates the tags in the repository. The registry client is
// region-scoped, so the tags are read through the instance the repository was
// listed from; a repository reached without its instance reports no tags rather
// than guessing a region.
func (r *mqlAlicloudAcrRepository) imageTags() ([]any, error) {
	if r.parentInstance == nil {
		log.Debug().Str("repository", r.RepoId.Data).
			Msg("alicloud> ACR repository reached without its instance, cannot list image tags")
		return []any{}, nil
	}
	region := r.parentInstance.region
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(region)
	if err != nil {
		return nil, err
	}

	instanceID := r.InstanceId.Data
	repoID := r.RepoId.Data

	res := []any{}
	pageNo := int32(1)
	for {
		resp, err := client.ListRepoTag(&crclient.ListRepoTagRequest{
			InstanceId: new(instanceID),
			RepoId:     new(repoID),
			PageNo:     new(pageNo),
			PageSize:   tea.Int32(acrTagPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Images
		for _, img := range items {
			if img == nil || img.Tag == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.acr.repositoryTag", map[string]*llx.RawData{
				"__id":       llx.StringData(repoID + "/" + tea.StringValue(img.Tag)),
				"instanceId": llx.StringData(instanceID),
				"repoId":     llx.StringData(repoID),
				"tag":        llx.StringDataPtr(img.Tag),
				"digest":     llx.StringDataPtr(img.Digest),
				"imageId":    llx.StringDataPtr(img.ImageId),
				"imageSize":  llx.IntData(tea.Int64Value(img.ImageSize)),
				"status":     llx.StringDataPtr(img.Status),
				"createTime": llx.TimeDataPtr(acrEpochMillisString(img.ImageCreate)),
				"updateTime": llx.TimeDataPtr(acrEpochMillisString(img.ImageUpdate)),
			})
			if err != nil {
				return nil, err
			}
			mqlTag := resource.(*mqlAlicloudAcrRepositoryTag)
			mqlTag.region = region
			res = append(res, mqlTag)
		}
		// ListRepoTag reports its total as a string; a short page is the
		// reliable terminator here
		if len(items) < acrTagPageSize {
			break
		}
		pageNo++
	}
	return res, nil
}

// scanStatusText reads the image's scan status once. A registry without image
// scanning switched on answers with an error, which is the answer rather than a
// failure: it yields an empty status, which scanned reports as not scanned.
func (r *mqlAlicloudAcrRepositoryTag) scanStatusText() string {
	r.scanStatusOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.CrClient(r.region)
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach the registry to read a scan status")
			return
		}
		resp, err := client.GetRepoTagScanStatus(&crclient.GetRepoTagScanStatusRequest{
			InstanceId: new(r.InstanceId.Data),
			RepoId:     new(r.RepoId.Data),
			Tag:        new(r.Tag.Data),
		})
		if err != nil {
			log.Debug().Err(err).Str("repository", r.RepoId.Data).Str("tag", r.Tag.Data).
				Msg("alicloud> could not read ACR image scan status")
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.scanStatusValue = tea.StringValue(resp.Body.Status)
	})
	return r.scanStatusValue
}

func (r *mqlAlicloudAcrRepositoryTag) scanStatus() (string, error) {
	return r.scanStatusText(), nil
}

func (r *mqlAlicloudAcrRepositoryTag) scanned() (bool, error) {
	return acrScanComplete(r.scanStatusText()), nil
}

// vulnerabilities lists the scan findings for the image. An image that has not
// been scanned yields an empty list, the same as a clean one, which is why
// scanned exists alongside this.
func (r *mqlAlicloudAcrRepositoryTag) vulnerabilities() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CrClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNo := int32(1)
	collected := 0
	for {
		resp, err := client.ListRepoTagScanResult(&crclient.ListRepoTagScanResultRequest{
			InstanceId: new(r.InstanceId.Data),
			RepoId:     new(r.RepoId.Data),
			Tag:        new(r.Tag.Data),
			Digest:     new(r.Digest.Data),
			PageNo:     new(pageNo),
			PageSize:   tea.Int32(acrTagPageSize),
		})
		if err != nil {
			// image scanning may not be switched on for the registry, which is
			// reported by scanStatus rather than by failing the whole query
			log.Debug().Err(err).Str("repository", r.RepoId.Data).Str("tag", r.Tag.Data).
				Msg("alicloud> could not read ACR image scan results")
			return res, nil
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Vulnerabilities
		for _, v := range items {
			if v == nil || v.CveName == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.acr.vulnerability", map[string]*llx.RawData{
				"__id":          llx.StringData(acrVulnerabilityID(r.RepoId.Data, r.Tag.Data, v)),
				"cveName":       llx.StringDataPtr(v.CveName),
				"aliasName":     llx.StringDataPtr(v.AliasName),
				"severity":      llx.StringDataPtr(v.Severity),
				"description":   llx.StringDataPtr(v.Description),
				"cveLink":       llx.StringDataPtr(v.CveLink),
				"cveLocation":   llx.StringDataPtr(v.CveLocation),
				"feature":       llx.StringDataPtr(v.Feature),
				"version":       llx.StringDataPtr(v.Version),
				"versionFixed":  llx.StringDataPtr(v.VersionFixed),
				"versionFormat": llx.StringDataPtr(v.VersionFormat),
				"addedBy":       llx.StringDataPtr(v.AddedBy),
				"fixCmd":        llx.StringDataPtr(v.FixCmd),
				"scanType":      llx.StringDataPtr(v.ScanType),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		collected += len(items)
		if len(items) == 0 || collected >= int(tea.Int32Value(resp.Body.TotalCount)) {
			break
		}
		pageNo++
	}
	return res, nil
}

// severityCounts reads the tag's findings and tallies them. Every count field
// goes through here, so the findings are fetched once and counted N times
// rather than fetched N times.
func (r *mqlAlicloudAcrRepositoryTag) severityCounts() (map[string]int64, int64, error) {
	vulnerabilities := r.GetVulnerabilities()
	if vulnerabilities.Error != nil {
		return nil, 0, vulnerabilities.Error
	}
	return acrSeverityCounts(vulnerabilities.Data), int64(len(vulnerabilities.Data)), nil
}

func (r *mqlAlicloudAcrRepositoryTag) vulnerabilityCount() (int64, error) {
	_, total, err := r.severityCounts()
	return total, err
}

func (r *mqlAlicloudAcrRepositoryTag) highSeverityCount() (int64, error) {
	counts, _, err := r.severityCounts()
	return counts["high"], err
}

func (r *mqlAlicloudAcrRepositoryTag) mediumSeverityCount() (int64, error) {
	counts, _, err := r.severityCounts()
	return counts["medium"], err
}

func (r *mqlAlicloudAcrRepositoryTag) lowSeverityCount() (int64, error) {
	counts, _, err := r.severityCounts()
	return counts["low"], err
}

func (r *mqlAlicloudAcrRepositoryTag) unknownSeverityCount() (int64, error) {
	counts, _, err := r.severityCounts()
	return counts["unknown"], err
}

func (r *mqlAlicloudAcrRepositoryTag) hasHighSeverityVulnerabilities() (bool, error) {
	counts, _, err := r.severityCounts()
	if err != nil {
		return false, err
	}
	return counts["high"] > 0, nil
}

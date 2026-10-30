// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/mvd"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func (u *mqlProduct) id() (string, error) {
	return "product:" + u.Name.Data + "/" + u.Version.Data, nil
}

func (m *mqlProduct) releaseCycle() (*mqlProductReleaseCycleInformation, error) {
	runtime := m.MqlRuntime
	mcc := runtime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		return nil, resources.MissingUpstreamError{}
	}

	// get new mvd client
	scannerClient, err := mvd.NewAdvisoryScannerClient(mcc.ApiEndpoint, mcc.HttpClient, mcc.Plugins...)
	if err != nil {
		return nil, err
	}

	eolProductReleaseInfo, err := scannerClient.GetProductEol(context.Background(), &mvd.GetProductEolRequest{
		Name:    m.Name.Data,
		Version: m.Version.Data,
	})
	if err != nil {
		return nil, err
	}

	res, err := runtime.CreateResource(runtime, "product.releaseCycleInformation", map[string]*llx.RawData{
		"__id":                 llx.StringData(eolProductReleaseInfo.Release.ReleaseName + "/" + eolProductReleaseInfo.Release.ReleaseCycle),
		"name":                 llx.StringData(eolProductReleaseInfo.Release.ReleaseName),
		"cycle":                llx.StringData(eolProductReleaseInfo.Release.ReleaseCycle),
		"latestVersion":        llx.StringData(eolProductReleaseInfo.Release.LatestVersion),
		"firstReleaseDate":     llx.TimeDataPtr(newTimestamp(eolProductReleaseInfo.Release.FirstReleaseDate)),
		"lastReleaseDate":      llx.TimeDataPtr(newTimestamp(eolProductReleaseInfo.Release.LastReleaseDate)),
		"endOfActiveSupport":   llx.TimeDataPtr(newTimestamp(eolProductReleaseInfo.Release.EndOfActiveSupport)), // "2021-04-01T00:00:00Z
		"endOfLife":            llx.TimeDataPtr(newTimestamp(eolProductReleaseInfo.Release.EndOfLife)),
		"endOfExtendedSupport": llx.TimeDataPtr(newTimestamp(eolProductReleaseInfo.Release.EndOfExtendedSupport)),
		"link":                 llx.StringData(eolProductReleaseInfo.Release.ReleaseLink),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlProductReleaseCycleInformation), nil
}

func newTimestamp(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

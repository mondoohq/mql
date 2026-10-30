// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/mvd"
	"go.mondoo.com/mql/utils/multierr"
	"time"
)

func initAssetEol(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	pkgs, err := CreateResource(runtime, "asset", nil)
	if err != nil {
		return nil, nil, multierr.Wrap(err, "cannot get asset resource")
	}
	asset := pkgs.(*mqlAsset)

	labels := map[string]string{}
	for k, v := range asset.Labels.Data {
		labels[k] = v.(string)
	}

	eolPlatform := &mvd.Platform{
		Name:    asset.Platform.Data,
		Release: asset.Version.Data,
		Build:   asset.Build.Data,
		Arch:    asset.Arch.Data,
		Title:   asset.Title.Data,
		Labels:  labels,
	}

	mcc := runtime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		return nil, nil, resources.MissingUpstreamError{}
	}

	// get new mvd client
	scannerClient, err := mvd.NewAdvisoryScannerClient(mcc.ApiEndpoint, mcc.HttpClient, mcc.Plugins...)
	if err != nil {
		return nil, nil, err
	}

	eolInfo, err := scannerClient.IsEol(context.Background(), eolPlatform)
	if err != nil {
		return nil, nil, err
	}

	log.Debug().Str("name", eolPlatform.Name).Str("release", eolPlatform.Release).Str("title", eolPlatform.Title).Msg("search for eol information")
	if eolInfo == nil {
		return nil, nil, errors.New("no platform eol information available")
	}

	var eolDate *time.Time
	if eolInfo.EolDate != "" {
		parsedEolDate, err := time.Parse(time.RFC3339, eolInfo.EolDate)
		if err != nil {
			return nil, nil, errors.New("could not parse eol date: " + eolInfo.EolDate)
		}
		eolDate = &parsedEolDate
	} else {
		eolDate = &llx.NeverFutureTime
	}

	args["docsUrl"] = llx.StringData(eolInfo.DocsUrl)
	args["productUrl"] = llx.StringData(eolInfo.ProductUrl)
	args["date"] = llx.TimeDataPtr(eolDate)

	return args, nil, nil
}

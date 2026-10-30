// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// blobServiceDataPlane holds the blob service settings that govern browser
// access to blob data and the account's own record of what happened to it.
type blobServiceDataPlane struct {
	corsAllowedOrigins        []any
	defaultServiceVersion     *string
	changeFeedEnabled         *bool
	changeFeedRetentionDays   *int32
	restorePolicyEnabled      *bool
	restorePolicyDays         *int32
	restoreMinRestoreTime     *time.Time
	lastAccessTimeTrackingSet *bool
}

// rawData renders the settings as resource arguments.
//
// The three toggles report null when the blob service properties themselves
// were not returned, because nothing was read in that case and a fabricated
// false would let an assertion over them pass vacuously. Once the properties
// are present, an omitted sub-block does mean the feature is off: Azure drops
// changeFeed, restorePolicy and lastAccessTimeTrackingPolicy from the response
// when they are not configured. The day counts stay null when the feature is
// off, and change-feed retention is also null when the feed is kept forever,
// which is what an absent retentionInDays means.
func (b blobServiceDataPlane) rawData() map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"corsAllowedOrigins":            llx.ArrayData(b.corsAllowedOrigins, types.String),
		"defaultServiceVersion":         llx.StringDataPtr(b.defaultServiceVersion),
		"changeFeedEnabled":             llx.BoolDataPtr(b.changeFeedEnabled),
		"changeFeedRetentionInDays":     llx.IntDataPtr(b.changeFeedRetentionDays),
		"restorePolicyEnabled":          llx.BoolDataPtr(b.restorePolicyEnabled),
		"restorePolicyDays":             llx.IntDataPtr(b.restorePolicyDays),
		"restorePolicyMinRestoreTime":   llx.TimeDataPtr(b.restoreMinRestoreTime),
		"lastAccessTimeTrackingEnabled": llx.BoolDataPtr(b.lastAccessTimeTrackingSet),
	}
}

// blobServiceDataPlaneSettings flattens the blob service properties ARM returns
// for a storage account.
func blobServiceDataPlaneSettings(props *storage.BlobServicePropertiesProperties) blobServiceDataPlane {
	settings := blobServiceDataPlane{corsAllowedOrigins: []any{}}
	if props == nil {
		return settings
	}

	off := false
	settings.changeFeedEnabled = &off
	settings.restorePolicyEnabled = &off
	settings.lastAccessTimeTrackingSet = &off
	settings.defaultServiceVersion = props.DefaultServiceVersion

	if props.Cors != nil {
		for _, rule := range props.Cors.CorsRules {
			if rule == nil {
				continue
			}
			for _, origin := range rule.AllowedOrigins {
				if origin == nil || *origin == "" {
					continue
				}
				settings.corsAllowedOrigins = append(settings.corsAllowedOrigins, *origin)
			}
		}
	}

	if cf := props.ChangeFeed; cf != nil {
		enabled := cf.Enabled != nil && *cf.Enabled
		settings.changeFeedEnabled = &enabled
		if enabled {
			settings.changeFeedRetentionDays = cf.RetentionInDays
		}
	}

	if rp := props.RestorePolicy; rp != nil {
		enabled := rp.Enabled != nil && *rp.Enabled
		settings.restorePolicyEnabled = &enabled
		if enabled {
			settings.restorePolicyDays = rp.Days
			settings.restoreMinRestoreTime = rp.MinRestoreTime
		}
	}

	if la := props.LastAccessTimeTrackingPolicy; la != nil {
		enabled := la.Enable != nil && *la.Enable
		settings.lastAccessTimeTrackingSet = &enabled
	}

	return settings
}

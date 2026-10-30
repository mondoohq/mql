// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	dropboxsdk "github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
)

// dbxTimePtr converts a *dropboxsdk.DBXTime (as returned throughout the SDK)
// into a *time.Time, preserving nil as nil.
func dbxTimePtr(t *dropboxsdk.DBXTime) *time.Time {
	if t == nil {
		return nil
	}
	tt := time.Time(*t)
	return &tt
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"errors"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type Result struct {
	Time *time.Time
	// Timezone is the IANA name of the system's zone.
	Timezone string
	// WindowsTimezone is the zone ID Windows reports, nil on other platforms.
	WindowsTimezone *string
	// UTCOffset is the offset from UTC in seconds east, in effect when the
	// time was read. Nil when it could not be determined.
	UTCOffset *int64
}

type Date interface {
	Name() string
	Get() (*Result, error)
}

func New(conn shared.Connection) (Date, error) {
	pf := conn.Asset().Platform

	switch {
	case pf.IsFamily(inventory.FAMILY_UNIX):
		return &Unix{conn: conn}, nil
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		return &Windows{conn: conn}, nil
	default:
		return nil, errors.New("your platform is not supported by the date resource")
	}
}

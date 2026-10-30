// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
)

func (p *mqlTime) now() (*time.Time, error) {
	// TODO: needs a ticking event where the time gets updated
	res := time.Now()
	return &res, nil
}

var (
	second = llx.DurationToTime(1)
	minute = llx.DurationToTime(60)
	hour   = llx.DurationToTime(60 * 60)
	day    = llx.DurationToTime(24 * 60 * 60)
)

func (x *mqlTime) second() (*time.Time, error) {
	return &second, nil
}

func (x *mqlTime) minute() (*time.Time, error) {
	return &minute, nil
}

func (x *mqlTime) hour() (*time.Time, error) {
	return &hour, nil
}

func (x *mqlTime) day() (*time.Time, error) {
	return &day, nil
}

func (x *mqlTime) today() (*time.Time, error) {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	return &today, nil
}

func (x *mqlTime) tomorrow() (*time.Time, error) {
	cur, _ := x.today()
	res := cur.Add(24 * time.Hour)

	return &res, nil
}

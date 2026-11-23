// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// databaseVersionLifecycle finds the published end-of-life and
// end-of-availability dates for an engine version. A nil date means none is
// published, including when the engine or version is not listed at all.
func databaseVersionLifecycle(opts connection.DatabaseOptions, engine, version string) (eol, eoa *time.Time, err error) {
	engineOpts, ok := opts[engine]
	if !ok {
		return nil, nil, nil
	}
	for _, va := range engineOpts.VersionAvailability {
		if va.Version != version {
			continue
		}
		if eol, err = parseLifecycleDate(va.EndOfLife); err != nil {
			return nil, nil, fmt.Errorf("end_of_life for %s %s: %w", engine, version, err)
		}
		if eoa, err = parseLifecycleDate(va.EndOfAvailability); err != nil {
			return nil, nil, fmt.Errorf("end_of_availability for %s %s: %w", engine, version, err)
		}
		return eol, eoa, nil
	}
	return nil, nil, nil
}

// parseLifecycleDate accepts an RFC 3339 timestamp or a bare date. An empty
// string means no date is published.
func parseLifecycleDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return nil, fmt.Errorf("unrecognized date %q", s)
	}
	return &t, nil
}

func (r *mqlDigitaloceanDatabase) versionLifecycle() (eol, eoa *time.Time, err error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	opts, err := conn.DatabaseOptions()
	if err != nil {
		return nil, nil, classifyDoError(err)
	}
	return databaseVersionLifecycle(opts, r.Engine.Data, r.Version.Data)
}

func (r *mqlDigitaloceanDatabase) versionEndOfLife() (*time.Time, error) {
	eol, _, err := r.versionLifecycle()
	if err != nil {
		return nil, err
	}
	if eol == nil {
		r.VersionEndOfLife.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return eol, nil
}

func (r *mqlDigitaloceanDatabase) versionEndOfAvailability() (*time.Time, error) {
	_, eoa, err := r.versionLifecycle()
	if err != nil {
		return nil, err
	}
	if eoa == nil {
		r.VersionEndOfAvailability.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return eoa, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/shadow"
)

const defaultShadowConfig = "/etc/shadow"

func (s *mqlShadow) id() (string, error) {
	return defaultShadowConfig, nil
}

func parseInt(s string, dflt int64, msg string) (int64, error) {
	if s == "" {
		return dflt, nil
	}

	res, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errors.New("failed to parse " + msg + " as a number, it is '" + s + "'")
	}
	return res, nil
}

func (s *mqlShadow) list() ([]any, error) {
	// TODO: we may want to create a real mondoo file resource
	o, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultShadowConfig),
	})
	if err != nil {
		return nil, err
	}

	file := o.(*mqlFile)
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}

	entries, err := shadow.ParseShadow(strings.NewReader(content.Data))
	if err != nil {
		return nil, err
	}

	// entries is already materialized in memory, but bound the count explicitly
	// before sizing the result slice from this file-derived length.
	if len(entries) > math.MaxInt/2 {
		return nil, errors.New("shadow file has too many entries")
	}
	shadowEntryResources := make([]any, len(entries))
	for i := range entries {
		entry := entries[i]

		maxdays, err := parseInt(entry.MaxDays, math.MaxInt64, "MaxDays")
		if err != nil {
			return nil, err
		}

		mindays, err := parseInt(entry.MinDays, -1, "MinDays")
		if err != nil {
			return nil, err
		}

		warndays, err := parseInt(entry.WarnDays, -1, "WarnDays")
		if err != nil {
			return nil, err
		}

		inactivedays, err := parseInt(entry.InactiveDays, math.MaxInt64, "InactiveDays")
		if err != nil {
			return nil, err
		}

		lastChanged := llx.NilData
		if entry.LastChanged != nil {
			lastChanged = llx.TimeData(*entry.LastChanged)
		}

		o, err := CreateResource(s.MqlRuntime, "shadow.entry", map[string]*llx.RawData{
			"user":         llx.StringData(entry.User),
			"password":     llx.StringData(entry.Password),
			"lastchanged":  lastChanged,
			"mindays":      llx.IntData(mindays),
			"maxdays":      llx.IntData(maxdays),
			"warndays":     llx.IntData(warndays),
			"inactivedays": llx.IntData(inactivedays),
			"expirydates":  llx.StringData(entry.ExpiryDates),
			"reserved":     llx.StringData(entry.Reserved),
		})
		if err != nil {
			log.Error().Err(err).Str("shadow_entry", entry.User).Msg("mql[shadow_entry]> could not create shadow entry resource")
			return nil, err
		}
		shadowEntryResources[i] = o.(*mqlShadowEntry)
	}

	return shadowEntryResources, nil
}

func (se *mqlShadowEntry) id() (string, error) {
	return se.User.Data, nil
}

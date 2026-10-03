// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// systemdUnitsNotListed returns, sorted, the units list-units reported that
// list-unit-files did not. list-unit-files names a template
// (refresh-policy-routes@.timer) but never its instances
// (refresh-policy-routes@ens5.timer), so those are only known from
// list-units. Units that load as not-found (named by another unit's After=)
// and uninstantiated templates are left out. loaded maps each list-units unit
// name to whether it loaded.
func systemdUnitsNotListed(loaded map[string]bool, listed map[string]bool) []string {
	res := []string{}
	for unit, ok := range loaded {
		if ok && !listed[unit] && !isSystemdTemplateUnit(unit) {
			res = append(res, unit)
		}
	}
	sort.Strings(res)
	return res
}

// showSystemdUnitStates reads Id, LoadState, ActiveState, UnitFileState and
// Description of each unit with `systemctl show`, keyed by unit name. A unit
// whose record could not be read is missing from the result.
func showSystemdUnitStates(conn shared.Connection, units []string) map[string]map[string]string {
	res := map[string]map[string]string{}
	for start := 0; start < len(units); start += systemdUnitShowChunk {
		end := min(start+systemdUnitShowChunk, len(units))
		cmd, err := conn.RunCommand(buildSystemdShowCommand(units[start:end]))
		if err == nil && cmd.ExitStatus != 0 {
			err = systemctlError("systemctl show", cmd)
		}
		if err != nil {
			log.Debug().Err(err).Msg("mql[systemd]> could not read the state of units without a unit file")
			continue
		}
		records, err := parseSystemdShowRecords(cmd.Stdout)
		if err != nil {
			log.Debug().Err(err).Msg("mql[systemd]> could not parse the state of units without a unit file")
			continue
		}
		for _, record := range records {
			if id := record["Id"]; id != "" && record["LoadState"] == "loaded" {
				res[id] = record
			}
		}
	}
	return res
}

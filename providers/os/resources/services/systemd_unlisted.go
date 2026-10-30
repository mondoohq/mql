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

// describeUnloadedUnits fills in the description of the unit-file rows that
// list-units did not report. list-units only lists the units systemd has
// loaded, and a disabled unit nothing pulls in is not loaded, so its
// description was left blank (ssh.socket on Debian, any disabled timer).
// `systemctl show` loads the unit file to answer. Templates are left out:
// "systemctl show" on name@.socket yields no record.
func describeUnloadedUnits(conn shared.Connection, rows map[string]*string) {
	units := make([]string, 0, len(rows))
	for unit := range rows {
		if !isSystemdTemplateUnit(unit) {
			units = append(units, unit)
		}
	}
	if len(units) == 0 {
		return
	}
	sort.Strings(units)
	shown := showSystemdUnitStates(conn, units)
	for unit, description := range rows {
		if record, ok := shown[unit]; ok && *description == "" {
			*description = record["Description"]
		}
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// AixLabelSystemModel carries the machine type-model of the system, for
	// example "IBM,9009-42A". It mirrors the "System Model" field of prtconf.
	//
	// This describes the physical machine, so it is the value to decide
	// hardware applicability from.
	AixLabelSystemModel = "aix.mondoo.com/system-model"

	// AixLabelProcessorType carries the processor implementation the partition
	// reports, for example "PowerPC_POWER9". It mirrors the "Processor Type"
	// field of prtconf.
	//
	// This is the partition's processor *compatibility mode*, not the physical
	// chip. An LPAR on POWER9 hardware configured in POWER8 mode reports
	// PowerPC_POWER8, which is routine because Live Partition Mobility to an
	// older host requires it. Anything deciding whether a silicon defect
	// applies must use AixLabelSystemModel, which compatibility mode does not
	// change; treating this value as the silicon would hide such a defect on a
	// machine that genuinely has it.
	AixLabelProcessorType = "aix.mondoo.com/processor-type"
)

// detectAixHardware records the machine type-model and the processor generation
// of an AIX system as platform labels.
//
// Some IBM AIX security advisories are only applicable to a specific POWER
// processor generation or to an explicit list of system models, and cannot be
// evaluated from the installed fileset level alone. Two published examples:
//
//   - CVE-2020-4788 affects POWER9 processors only.
//     https://aix.software.ibm.com/aix/efixes/security/power9_advisory.asc
//   - The follow-up Spectre fix for CVE-2017-5715 is, in IBM's words, "only
//     applicable to the following POWER9 systems: 9040-MR9, 9080-M9S".
//     https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
//
// Both values are also reported by prtconf, but prtconf dumps the entire system
// configuration and is comparatively expensive, so we read just the two fields
// we need via uname and lsattr.
//
// Detection failures are non-fatal — the affected label is simply omitted.
// Consumers must therefore treat a missing label as "unknown", never as
// "does not match", so that an older agent or a restricted environment cannot
// silently suppress a finding.
func detectAixHardware(pf *inventory.Platform, osrd *OSReleaseDetector) {
	// `uname -M` prints the machine type-model, e.g. "IBM,9009-42A".
	if model, err := osrd.command("uname -M"); err != nil {
		log.Debug().Err(err).Msg("could not detect aix system model")
	} else {
		setAixLabel(pf, AixLabelSystemModel, model)
	}

	// `lsattr -El proc0 -a type -F value` prints the processor implementation of
	// the first processor, e.g. "PowerPC_POWER9". proc0 is absent inside a WPAR,
	// in which case lsattr fails and the label stays unset.
	if procType, err := osrd.command("lsattr -El proc0 -a type -F value"); err != nil {
		log.Debug().Err(err).Msg("could not detect aix processor type")
	} else {
		setAixLabel(pf, AixLabelProcessorType, procType)
	}
}

// setAixLabel stores value under key, provided the command actually returned a
// value. Both fields are single whitespace-free tokens, so anything else is a
// usage message or an error that the command printed to stdout rather than a
// value we should record.
func setAixLabel(pf *inventory.Platform, key string, value string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		log.Debug().Str("label", key).Msg("ignoring unexpected aix hardware detection output")
		return
	}

	if pf.Labels == nil {
		pf.Labels = map[string]string{}
	}
	pf.Labels[key] = value
}

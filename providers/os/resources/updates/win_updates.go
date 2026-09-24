// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	WindowsUpdateFormat = "wsus"

	// WindowsUpdateCriteriaSoftware selects installable software updates
	// (drivers excluded). This is what os.update reports.
	WindowsUpdateCriteriaSoftware = "IsInstalled=0 and Type='Software'"
	// WindowsUpdateCriteriaAvailable selects every installable, non-hidden
	// update (drivers included). This is what windows.update.available reports.
	WindowsUpdateCriteriaAvailable = "IsInstalled=0 and IsHidden=0"
)

// windowsUpdateSearchQuery builds a PowerShell snippet that searches the
// Windows Update Agent with the given criteria and emits one rich JSON record
// per update. It is the single source of the WUA "search" used by both
// os.update (via WindowsUpdateManager) and windows.update.available.
//
// IMPORTANT: criteria is concatenated into the script verbatim, so it must be
// a trusted constant (e.g. WindowsUpdateCriteria*), never user input.
//
// online sets IUpdateSearcher.Online on the searcher object BEFORE Search()
// runs (the property has no effect set afterwards: WUA reads it when the
// search starts, not when it returns). os.update always searches online —
// it is what reports current patch state, and answering it from a stale
// cache would under- or over-report what is actually outstanding.
// windows.update.available may search offline instead, answering from the
// cache of the agent's last detection rather than running a new one against
// Windows Update or WSUS, which can take minutes; an offline result is only
// as fresh as that last detection, exposed as
// windows.update.config.lastDetectionSuccess, and callers must use it to
// judge whether the answer is current.
func windowsUpdateSearchQuery(criteria string, online bool) string {
	onlineValue := "$true"
	if !online {
		onlineValue = "$false"
	}
	// $ErrorActionPreference is Stop so a failed search is a terminating error
	// and powershell.exe exits non-zero. Without it the COM failure is a
	// non-terminating error: the exit status stays 0, $result stays null, and
	// $result.Updates iterated still runs once with a null input, so the
	// caller is handed one empty update and reads it as a host with nothing
	// outstanding. A host whose update agent could not be reached must fail
	// the check, not report itself fully patched.
	//
	// The per-update loop is a `foreach` building `[pscustomobject]` records
	// rather than `ForEach-Object` / `New-Object psobject`: the pipeline
	// cmdlets are markedly slower in PowerShell, and both the "installed"
	// and "available" criteria can return large result sets.
	return `
$ErrorActionPreference='Stop';
$ProgressPreference='SilentlyContinue';
$updateSession = new-object -com "Microsoft.Update.Session"
$searcher = $updateSession.CreateupdateSearcher()
$searcher.Online = ` + onlineValue + `
$result = $searcher.Search("` + criteria + `")
$updates = foreach ($update in $result.Updates) {
	[pscustomobject]@{
		"UpdateID" = $update.Identity.UpdateID
		"Title" = $update.Title
		"MsrcSeverity" = $update.MsrcSeverity
		"SupportUrl" = $update.SupportUrl
		"RebootRequired" = [bool]$update.RebootRequired
		"KBArticleIDs" = @($update.KBArticleIDs)
		"CveIDs" = @($update.CveIDs)
		"Categories" = @($update.Categories | ForEach-Object { $_.Name })
	}
}
@($updates) | ConvertTo-Json -Depth 3`
}

// WindowsUpdate is the rich representation of an update returned by a Windows
// Update Agent search. It carries everything both consumers need; each maps it
// to its own output type.
type WindowsUpdate struct {
	UpdateID       string   `json:"UpdateID"`
	Title          string   `json:"Title"`
	MsrcSeverity   string   `json:"MsrcSeverity"`
	SupportUrl     string   `json:"SupportUrl"`
	RebootRequired bool     `json:"RebootRequired"`
	KBArticleIDs   []string `json:"KBArticleIDs"`
	CveIDs         []string `json:"CveIDs"`
	Categories     []string `json:"Categories"`
}

type WindowsUpdateManager struct {
	conn shared.Connection
}

func (um *WindowsUpdateManager) Name() string {
	return "Windows Server Update Services Manager"
}

func (um *WindowsUpdateManager) Format() string {
	return WindowsUpdateFormat
}

func (um *WindowsUpdateManager) List() ([]OperatingSystemUpdate, error) {
	// os.update must stay online: it is what reports current patch state, and
	// this is the only WindowsUpdateManager caller, so there is no offline
	// variant to keep in sync with.
	updates, err := SearchWindowsUpdates(um.conn, WindowsUpdateCriteriaSoftware, true)
	if err != nil {
		return nil, err
	}

	res := make([]OperatingSystemUpdate, 0, len(updates))
	for i := range updates {
		osUpdate, ok := updates[i].toOperatingSystemUpdate()
		if !ok {
			log.Warn().Str("update", updates[i].UpdateID).Msg("ms update has no kb assigned")
			continue
		}
		res = append(res, osUpdate)
	}
	return res, nil
}

// toOperatingSystemUpdate maps a WindowsUpdate to the cross-platform
// OperatingSystemUpdate shape used by os.update. Updates without a KB article
// (ok == false) are skipped, since the KB is the os.update identity.
func (u WindowsUpdate) toOperatingSystemUpdate() (OperatingSystemUpdate, bool) {
	if len(u.KBArticleIDs) == 0 {
		return OperatingSystemUpdate{}, false
	}
	return OperatingSystemUpdate{
		ID:          u.UpdateID,
		Name:        u.KBArticleIDs[0],
		Description: u.Title,
		Severity:    u.MsrcSeverity,
		Format:      "windows/updates",
		Restart:     u.RebootRequired,
	}, true
}

// SearchWindowsUpdates runs a Windows Update Agent search with the given
// criteria and returns the parsed updates. See windowsUpdateSearchQuery for
// what online controls and the trade-off of setting it to false.
func SearchWindowsUpdates(conn shared.Connection, criteria string, online bool) ([]WindowsUpdate, error) {
	cmd := powershell.Encode(windowsUpdateSearchQuery(criteria, online))
	c, err := conn.RunCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("could not search for windows updates: %w", err)
	}
	if c.ExitStatus != 0 {
		stderr, err := io.ReadAll(c.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve updates: " + string(stderr))
	}
	return ParseWindowsUpdates(c.Stdout)
}

func ParseWindowsUpdates(input io.Reader) ([]WindowsUpdate, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// handle case where no updates are available
	if len(strings.TrimSpace(string(data))) == 0 {
		return []WindowsUpdate{}, nil
	}

	// ConvertTo-Json emits a bare object (not a single-element array) when the
	// search returns exactly one update.
	var updates []WindowsUpdate
	arrErr := json.Unmarshal(data, &updates)
	if arrErr == nil {
		return dropEmptyWindowsUpdates(updates), nil
	}

	var single WindowsUpdate
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, arrErr
	}
	return dropEmptyWindowsUpdates([]WindowsUpdate{single}), nil
}

// dropEmptyWindowsUpdates removes records that carry no identity at all.
//
// A record with neither an update ID nor a title is not an update; it is what
// a null decodes to. The script's ErrorActionPreference keeps a failed search
// from producing one, and this keeps any other source of a blank record from
// being counted as an outstanding update.
//
// The common case is that there is nothing to drop, so the input is returned
// as it stands and nothing is allocated until a blank record is actually seen.
func dropEmptyWindowsUpdates(updates []WindowsUpdate) []WindowsUpdate {
	first := -1
	for i := range updates {
		if updates[i].UpdateID == "" && updates[i].Title == "" {
			first = i
			break
		}
	}
	if first < 0 {
		return updates
	}

	res := make([]WindowsUpdate, first, len(updates)-1)
	copy(res, updates[:first])
	for i := first + 1; i < len(updates); i++ {
		if updates[i].UpdateID == "" && updates[i].Title == "" {
			continue
		}
		res = append(res, updates[i])
	}
	return res
}

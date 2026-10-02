// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"encoding/json"
	"io"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Dnf5Binary is where dnf5 installs itself. Its presence is what marks a host
// whose transactions are recorded in dnf5's history database instead of
// dnf's rpm transaction log.
const Dnf5Binary = "/usr/bin/dnf5"

// dnf5HistoryCommand prints every transaction in dnf5's history
// (/usr/lib/sysimage/libdnf5/transaction_history.sqlite) with the packages it
// touched. It reads the database only, needs no root, and touches no
// repository.
const dnf5HistoryCommand = "dnf5 history info --json 1..last"

// dnf5Transaction is one entry of `dnf5 history info --json`.
type dnf5Transaction struct {
	ID       int64  `json:"id"`
	EndTime  int64  `json:"end_time"`
	Status   string `json:"status"`
	Packages []struct {
		Nevra  string `json:"nevra"`
		Action string `json:"action"`
	} `json:"packages"`
}

// Dnf5Present reports whether dnf5 is installed.
func Dnf5Present(fs afero.Fs) bool {
	ok, _ := afero.Exists(fs, Dnf5Binary)
	return ok
}

// LastInstalledDnf5 reads the newest completed vendor package upgrade from
// dnf5's transaction history. A connection that cannot run commands, a dnf5
// that cannot print its history as JSON (older than 5.2), and an empty
// history all read nil: there is no upgrade evidence to report.
func LastInstalledDnf5(conn shared.Connection, isVendorPackage func(name string) bool) (*LastInstalledUpdate, error) {
	if isVendorPackage == nil || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}
	cmd, err := conn.RunCommand(dnf5HistoryCommand)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		log.Debug().Int("exit", cmd.ExitStatus).Str("stderr", string(stderr)).Msg("dnf5 history is not readable, no dnf5 update evidence")
		return nil, nil
	}
	return ParseDnf5History(cmd.Stdout, isVendorPackage)
}

// ParseDnf5History returns the end time of the newest successful transaction
// in `dnf5 history info --json` output that upgraded a package
// isVendorPackage attributes to the operating system vendor.
//
// Only the Upgrade action counts, which names the incoming build. Install is
// an operator adding a package, and Replaced names the outgoing build of an
// upgrade and of a downgrade alike. A transaction that didn't finish ("Error",
// "Started") changed nothing to count. dnf5 records times per transaction,
// not per package, so the transaction's end time is the answer.
func ParseDnf5History(r io.Reader, isVendorPackage func(name string) bool) (*LastInstalledUpdate, error) {
	var transactions []dnf5Transaction
	if err := json.NewDecoder(r).Decode(&transactions); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	var newest int64
	for _, t := range transactions {
		if t.Status != "Ok" || t.EndTime <= newest {
			continue
		}
		for _, pkg := range t.Packages {
			if pkg.Action != "Upgrade" {
				continue
			}
			if name := rpmNevraName(pkg.Nevra); name != "" && isVendorPackage(name) {
				newest = t.EndTime
				break
			}
		}
	}

	if newest == 0 {
		return nil, nil
	}
	return &LastInstalledUpdate{Time: time.Unix(newest, 0).UTC(), Source: LastUpdateSourceDnf5History}, nil
}

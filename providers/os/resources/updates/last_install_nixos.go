// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

const (
	// nixosSystemProfile is the symlink NixOS repoints at the generation it has
	// activated. Its own mtime is when that happened, which on NixOS is what an
	// update is: the whole system is replaced at once rather than a package at
	// a time, so there is no package log to read and no per-package install
	// date to take the newest of.
	nixosSystemProfile = "/nix/var/nix/profiles/system"

	// nixosProfileMtimeCommand reads the symlink's own mtime as epoch seconds.
	//
	// GNU stat does not follow a symlink unless asked, which is what makes this
	// work and what makes the obvious alternative wrong: every path in the nix
	// store has its mtime normalized to 1970-01-01, so following the link
	// reports 1970 and a host reads as unpatched for 56 years rather than as
	// unknown. NixOS ships GNU coreutils and this command only runs there.
	//
	// Epoch seconds rather than `nix-env --list-generations`, which prints the
	// date in the host's local time with no zone on it. Parsing that as UTC
	// moves the answer by the offset, and lastUpdateAge is then wrong by hours
	// on every host outside UTC.
	nixosProfileMtimeCommand = "stat -c %Y " + nixosSystemProfile
)

// lastInstalledNixos reports when the running NixOS generation was activated.
//
// A connection that cannot run commands gets no answer rather than a guess:
// the timestamp lives in a symlink's mtime, and the filesystem abstraction
// stats through a symlink, which would read the normalized 1970 off the store
// path it points at.
func lastInstalledNixos(conn shared.Connection) (*LastInstalledUpdate, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}

	cmd, err := conn.RunCommand(nixosProfileMtimeCommand)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		// No system profile is not a NixOS host that was never updated, it is
		// a host this cannot answer for.
		return nil, nil
	}

	return ParseNixosProfileMtime(cmd.Stdout)
}

// ParseNixosProfileMtime reads the epoch seconds `stat -c %Y` prints.
func ParseNixosProfileMtime(r io.Reader) (*LastInstalledUpdate, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	field := strings.TrimSpace(string(raw))
	if field == "" {
		return nil, nil
	}
	// stat prints one line, but a shell wrapper can add a trailing one.
	if idx := strings.IndexAny(field, "\r\n"); idx >= 0 {
		field = strings.TrimSpace(field[:idx])
	}

	secs, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("could not read the mtime of %s: %q is not epoch seconds", nixosSystemProfile, field)
	}
	// Nix normalizes every mtime in the store to epoch 1, so a reader that
	// followed the symlink lands exactly here. Validation downstream drops a
	// zero time and a future one but has no reason to distrust 1970, which
	// would report the host as unpatched since the epoch rather than as
	// unknown. Reject it where the reason is known.
	if secs <= 1 {
		return nil, nil
	}

	return &LastInstalledUpdate{
		Time:   time.Unix(secs, 0).UTC(),
		Source: LastUpdateSourceNixosGeneration,
	}, nil
}

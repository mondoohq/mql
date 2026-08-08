// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// defaultSelftestTimeout bounds how long the binary health check may run. The
// selftest does no network I/O, so it completes quickly; the ceiling only
// guards against a binary that hangs on startup.
const defaultSelftestTimeout = 30 * time.Second

// healthCheckBinary runs the candidate binary's `selftest` subcommand to prove
// it can start and initialize before we activate it. A non-zero exit (or a
// timeout, or a binary that cannot exec at all) means the binary is not safe to
// activate. Auto-update is disabled for the child so the check cannot recurse.
func healthCheckBinary(binaryPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSelftestTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "selftest")
	cmd.Env = append(os.Environ(), EnvAutoUpdate+"=false")

	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("selftest timed out")
		}
		return errors.Wrapf(err, "selftest exited non-zero: %s", string(out))
	}
	return nil
}

// Crash-loop startup guard
//
// A self-update stages a newer binary in the bin path and execs into it on
// every invocation. If that newer binary starts far enough to pass its health
// check but then crashes under the real workload (most importantly `serve`),
// every restart would re-exec into the same broken binary — a crash loop with
// no escape, because the launcher keeps preferring the newer version.
//
// The guard breaks that loop. It counts how many times a staged version has
// been activated without ever confirming a healthy run. After a few failed
// activations it quarantines the staged binary: the bad binary is renamed
// aside, the version is remembered so it is never re-downloaded, and the
// launcher falls back to the previous (package-installed) binary, which is
// known good.
//
// The healthy binary confirms itself once it has demonstrably worked (a CLI
// command completed, or serve finished its first scan cycle). Confirmation
// stops the counter, so a good update is never quarantined.

const (
	updateStateFile = "update-state.json"

	stateActivationPending   = "pending"
	stateActivationConfirmed = "confirmed"

	// maxActivationAttempts is how many times a not-yet-confirmed staged
	// version may be activated before it is treated as crash-looping and
	// quarantined. Three gives systemd's default restart a couple of chances to
	// be a transient hiccup before we give up on the new binary.
	maxActivationAttempts = 3

	// maxQuarantinedVersions caps how many bad versions we remember, so the
	// state file cannot grow without bound over the lifetime of a host. The
	// most recent entries are kept; older quarantined versions are unlikely to
	// be offered again as "latest".
	maxQuarantinedVersions = 20
)

// updateState is the on-disk guard state, stored next to the staged binary.
type updateState struct {
	// StagedVersion is the version currently staged in the bin path.
	StagedVersion string `json:"staged_version,omitempty"`
	// Activation is stateActivationPending or stateActivationConfirmed.
	Activation string `json:"activation,omitempty"`
	// Attempts counts activations of StagedVersion without a confirmation.
	Attempts int `json:"attempts,omitempty"`
	// Quarantined lists versions proven bad; they are never activated or
	// re-downloaded.
	Quarantined []string `json:"quarantined,omitempty"`
}

func updateStatePath(binPath string) string {
	return filepath.Join(binPath, updateStateFile)
}

func readUpdateState(binPath string) *updateState {
	data, err := os.ReadFile(updateStatePath(binPath))
	if err != nil {
		return &updateState{}
	}
	var st updateState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Debug().Err(err).Msg("self-update: corrupt update-state, resetting")
		return &updateState{}
	}
	return &st
}

func writeUpdateState(binPath string, st *updateState) error {
	if err := os.MkdirAll(binPath, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := updateStatePath(binPath) + ".tmp"

	// Flush the contents before the rename so a crash can't leave the renamed
	// state file referencing unwritten (zeroed) bytes, matching the atomic
	// write in writeCurrentPointerAtomic.
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, updateStatePath(binPath))
}

func (st *updateState) isQuarantined(version string) bool {
	for _, v := range st.Quarantined {
		if v == version {
			return true
		}
	}
	return false
}

// quarantine records version as bad, keeping the list bounded to the most
// recent maxQuarantinedVersions entries so the state file cannot grow forever.
func (st *updateState) quarantine(version string) {
	if st.isQuarantined(version) {
		return
	}
	st.Quarantined = append(st.Quarantined, version)
	if n := len(st.Quarantined); n > maxQuarantinedVersions {
		st.Quarantined = st.Quarantined[n-maxQuarantinedVersions:]
	}
}

// isVersionQuarantined reports whether a version has been marked bad and must
// not be downloaded or activated.
func isVersionQuarantined(binPath, version string) bool {
	return readUpdateState(binPath).isQuarantined(version)
}

// recordActivationAttempt is called just before the launcher execs into a
// staged newer binary. It returns proceed=false when the staged version has
// exceeded its activation budget (crash-looping) or is already quarantined; in
// that case the caller must not activate it and should fall back to the current
// binary. It transparently resets the counter when a different version is
// staged, and never counts a version that has already confirmed healthy.
func recordActivationAttempt(binPath, version string) (proceed bool) {
	st := readUpdateState(binPath)

	if st.isQuarantined(version) {
		return false
	}

	// A newly staged version resets the counter.
	if st.StagedVersion != version {
		st.StagedVersion = version
		st.Activation = stateActivationPending
		st.Attempts = 0
	}

	// A version that already proved healthy is always fine to activate.
	if st.Activation == stateActivationConfirmed {
		return true
	}

	st.Attempts++
	if st.Attempts > maxActivationAttempts {
		log.Warn().
			Str("version", version).
			Int("attempts", st.Attempts-1).
			Msg("self-update: staged version failed to confirm healthy; quarantining and falling back")
		st.quarantine(version)
		st.StagedVersion = ""
		st.Activation = ""
		st.Attempts = 0
		if err := writeUpdateState(binPath, st); err != nil {
			log.Debug().Err(err).Msg("self-update: failed to persist quarantine state")
		}
		return false
	}

	if err := writeUpdateState(binPath, st); err != nil {
		log.Debug().Err(err).Msg("self-update: failed to persist activation attempt")
	}
	return true
}

// confirmActivation marks the staged version as healthy so it is never
// quarantined and future activations skip the crash-loop counter. It is a
// no-op unless the running version matches the staged, pending version.
func confirmActivation(binPath, version string) {
	st := readUpdateState(binPath)
	if st.StagedVersion != version || st.Activation == stateActivationConfirmed {
		return
	}
	st.Activation = stateActivationConfirmed
	st.Attempts = 0
	if err := writeUpdateState(binPath, st); err != nil {
		log.Debug().Err(err).Msg("self-update: failed to persist activation confirmation")
	}
	log.Debug().Str("version", version).Msg("self-update: confirmed staged version healthy")
}

// quarantineVersion records a version as bad so it is never activated or
// re-downloaded. Used when a health check proves a binary is broken up front,
// short-circuiting the attempt counter.
func quarantineVersion(binPath, version string) {
	st := readUpdateState(binPath)
	if st.isQuarantined(version) {
		return
	}
	st.quarantine(version)
	if st.StagedVersion == version {
		st.StagedVersion = ""
		st.Activation = ""
		st.Attempts = 0
	}
	if err := writeUpdateState(binPath, st); err != nil {
		log.Debug().Err(err).Msg("self-update: failed to persist quarantine")
	}
}

// quarantineStagedBinary renames a crash-looping staged binary aside so the
// launcher falls back to the previous binary. Best-effort.
func quarantineStagedBinary(binPath, binName, version string) {
	staged := filepath.Join(binPath, binName)
	aside := filepath.Join(binPath, binName+"."+version+".bad")
	if err := os.Rename(staged, aside); err != nil {
		log.Debug().Err(err).Str("path", staged).Msg("self-update: failed to move quarantined binary aside")
	} else {
		log.Warn().Str("from", staged).Str("to", aside).Msg("self-update: quarantined crash-looping binary")
	}
}

// ConfirmRunningVersion records that the currently running binary version has
// operated successfully, so a staged update is not mistaken for a crash loop.
// Callers invoke it once real work has succeeded: a CLI command completed, or
// serve finished a healthy scan cycle. It is safe to call repeatedly and does
// nothing when there is no bin path or no pending staged version.
func ConfirmRunningVersion(version string) {
	binPath, err := getBinPath()
	if err != nil {
		return
	}
	confirmActivation(binPath, version)
}

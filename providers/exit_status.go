// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/hashicorp/go-plugin"
)

// processTracker pairs the plugin subprocess command with the go-plugin
// client supervising it, so crash diagnostics can read the subprocess's exit
// disposition (exit code vs. signal, peak RSS) after it dies.
//
// go-plugin's exit-watcher goroutine calls cmd.Wait() — which populates
// exec.Cmd.ProcessState — and only afterwards marks Client.Exited() under the
// client's mutex. Reading ProcessState is therefore only safe once Exited()
// reports true for the client that owns this exact cmd; exitState enforces
// that pairing. The tracker is updated in lock-step by the coordinator's
// connect function, including across RestartableProvider restarts.
type processTracker struct {
	lock   sync.Mutex
	client *plugin.Client
	cmd    *exec.Cmd
}

func (t *processTracker) track(client *plugin.Client, cmd *exec.Cmd) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.client = client
	t.cmd = cmd
}

// exitInfo reports whether the tracked plugin subprocess has been reaped
// and, if so, its exit state. Exited() == true means go-plugin's Wait on
// this exact cmd returned, so reading ProcessState is race-free. The tracker
// is the single source of truth for crash diagnostics: unlike
// RestartableProvider's client accessor, its lock is only ever held for a
// field copy, so this never blocks behind an in-flight Reconnect.
func (t *processTracker) exitInfo() (bool, *os.ProcessState) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.client == nil || t.cmd == nil {
		return false, nil
	}
	if !t.client.Exited() {
		return false, nil
	}
	return true, t.cmd.ProcessState
}

// formatExitStatus renders a process's exit disposition for the crash
// diagnostics meta block: "code:<n>" for a regular exit, "signal:<SIG>" when
// the process was killed by a signal (e.g. "signal:SIGKILL", the typical OOM
// killer fingerprint), or "unknown" if the state carries neither.
func formatExitStatus(ps *os.ProcessState) string {
	if ps == nil {
		return "unknown"
	}
	// syscall.WaitStatus exists on every port, including Windows, where
	// Signaled() is hardwired to false and we fall through to ExitCode().
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return "signal:" + signalName(ws.Signal())
	}
	if code := ps.ExitCode(); code >= 0 {
		return "code:" + strconv.Itoa(code)
	}
	return "unknown"
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package local

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

func (c *LocalConnection) fileowner(stat os.FileInfo) (int64, int64) {
	uid := int64(-1)
	gid := int64(-1)
	if stat, ok := stat.Sys().(*shared.FileInfo); ok {
		uid = stat.Uid
		gid = stat.Gid
	}
	if stat, ok := stat.Sys().(*syscall.Stat_t); ok {
		uid = int64(stat.Uid)
		gid = int64(stat.Gid)
	}
	return uid, gid
}

// Each command owns a process group so cancellation also stops descendants
// holding stdout/stderr open. Never signal the scanner's process group.
type commandProcess struct{ cmd *exec.Cmd }

func newCommandProcess(cmd *exec.Cmd) (*commandProcess, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	p := &commandProcess{cmd: cmd}
	cmd.Cancel = p.kill
	return p, nil
}

func (p *commandProcess) started() error { return nil }
func (p *commandProcess) kill() error {
	if p.cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
func (p *commandProcess) close() { _ = p.kill() }

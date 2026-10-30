// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package local

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (c *LocalConnection) fileowner(stat os.FileInfo) (int64, int64) {
	uid := int64(-1)
	gid := int64(-1)

	return uid, gid
}

// A job object keeps descendants in the command's cancellation boundary.
type commandProcess struct {
	cmd *exec.Cmd
	job windows.Handle
	mu  sync.Mutex
}

func newCommandProcess(cmd *exec.Cmd) (*commandProcess, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// SetInformationJobObject accepts uintptr; pin the typed input so it
	// stays alive at a fixed address throughout the call.
	var pinned runtime.Pinner
	pinned.Pin(&limits)
	defer pinned.Unpin()
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	// Go closes the initial thread handle before Start returns. Keep that
	// thread suspended until the process belongs to its cancellation job,
	// so even a fast launcher cannot create children outside the job.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	p := &commandProcess{cmd: cmd, job: job}
	cmd.Cancel = p.kill
	return p, nil
}
func (p *commandProcess) started() error {
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := windows.AssignProcessToJobObject(p.job, handle); err != nil {
		return err
	}
	return resumeCommandThread(uint32(p.cmd.Process.Pid))
}
func (p *commandProcess) kill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := windows.TerminateJobObject(p.job, 1)
	// Also cover cancellation racing the initial job assignment.
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	return err
}
func (p *commandProcess) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = windows.CloseHandle(p.job)
}

func resumeCommandThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	thread := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err := windows.Thread32First(snapshot, &thread); err == nil; err = windows.Thread32Next(snapshot, &thread) {
		if thread.OwnerProcessID != pid {
			continue
		}
		handle, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, thread.ThreadID)
		if err != nil {
			return err
		}
		suspended, err := windows.ResumeThread(handle)
		_ = windows.CloseHandle(handle)
		if err != nil {
			return err
		}
		if suspended > 0 {
			return nil
		}
	}
	return fmt.Errorf("no suspended initial thread found for command process %d", pid)
}

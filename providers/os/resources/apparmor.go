// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	processmgr "go.mondoo.com/mql/v13/providers/os/resources/processes"
)

type mqlApparmorInternal struct {
	status  *apparmorStatus
	fetched bool
	lock    sync.Mutex
}

const apparmorProfilesPath = "/sys/kernel/security/apparmor/profiles"

// errApparmorNotPresent reports that this host does not have AppArmor, as
// distinct from having it and refusing to describe it.
//
// The two must not collapse into one answer. A host without AppArmor confines
// nothing and can say so, which is what lets a policy ask about AppArmor on a
// fleet that also runs SELinux or neither. A profile list that exists and
// cannot be read is unknown, and reporting zero profiles for it would pass an
// audit for unconfined or complain-mode ones.
var errApparmorNotPresent = errors.New("AppArmor is not present on this system")

var apparmorJSONCommands = []string{
	"apparmor_status --json",
	"aa-status --json",
}

func (a *mqlApparmor) id() (string, error) {
	return "apparmor", nil
}

// apparmorStatus represents the JSON output of apparmor_status --json
type apparmorStatus struct {
	Version   string                        `json:"version"`
	Profiles  map[string]string             `json:"profiles"`
	Processes map[string][]apparmorProcInfo `json:"processes"`
}

type apparmorProcInfo struct {
	Profile string `json:"profile"`
	PID     string `json:"pid"`
	Status  string `json:"status"`
}

func (a *mqlApparmor) fetchStatus() (*apparmorStatus, error) {
	if a.fetched {
		return a.status, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.status, nil
	}

	status, err := a.fetchStatusFromJSON()
	if err != nil {
		status, kernelErr := a.fetchStatusFromKernel()
		if kernelErr != nil {
			// Neither the userspace tools nor the kernel interfaces answered,
			// and the kernel is what decides whether AppArmor is here at all.
			// Keep the sentinel rather than wrapping it into a generic
			// failure, so the accessors can report absence instead of it.
			if errors.Is(kernelErr, errApparmorNotPresent) {
				return nil, kernelErr
			}
			return nil, fmt.Errorf("could not retrieve apparmor status via json or kernel interfaces: %w; fallback failed: %v", err, kernelErr)
		}
		a.status = status
		a.fetched = true
		return a.status, nil
	}

	a.status = status
	a.fetched = true
	return a.status, nil
}

func (a *mqlApparmor) fetchStatusFromJSON() (*apparmorStatus, error) {
	var attempts []string

	for _, command := range apparmorJSONCommands {
		o, err := CreateResource(a.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(command),
		})
		if err != nil {
			attempts = append(attempts, command+": "+err.Error())
			continue
		}

		cmd := o.(*mqlCommand)
		exit := cmd.GetExitcode()
		if exit.Error != nil {
			attempts = append(attempts, command+": "+exit.Error.Error())
			continue
		}
		if exit.Data != 0 {
			msg := strings.TrimSpace(cmd.Stderr.Data)
			if msg == "" {
				msg = "exit code " + strconv.FormatInt(exit.Data, 10)
			}
			attempts = append(attempts, command+": "+msg)
			continue
		}

		var status apparmorStatus
		if err := json.Unmarshal([]byte(cmd.Stdout.Data), &status); err != nil {
			attempts = append(attempts, command+": "+err.Error())
			continue
		}

		return &status, nil
	}

	if len(attempts) == 0 {
		return nil, errors.New("could not retrieve apparmor status")
	}
	return nil, errors.New(strings.Join(attempts, "; "))
}

func (a *mqlApparmor) fetchStatusFromKernel() (*apparmorStatus, error) {
	conn, ok := a.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("connection does not support filesystem access")
	}

	// securityfs is what decides whether this host has AppArmor, and it is
	// checked before anything else is read. Listing processes used to come
	// first, which meant a host where the process list could not be read --
	// and every host without a `ps`, including a scanned image -- failed the
	// whole resource with a message about processes, rather than reporting the
	// plain fact that there is no AppArmor here.
	//
	// A container is the one place this can understate: with securityfs
	// unmounted inside it, a host profile confining the container is not
	// visible and AppArmor reads as absent. selinux answers the same way
	// without /sys/fs/selinux.
	profilesAvailable, err := afero.Exists(conn.FileSystem(), apparmorProfilesPath)
	if err != nil {
		return nil, err
	}
	if !profilesAvailable {
		return nil, errApparmorNotPresent
	}

	// The list exists but we could not read it. securityfs enforces
	// CAP_MAC_ADMIN regardless of the mode bits, so an unprivileged scan gets
	// EACCES on a world-readable path. Reporting zero profiles there states as
	// fact something that was never read, and an audit for unconfined or
	// complain-mode profiles would pass on it.
	profiles, profilesErr := readApparmorProfilesFromFS(conn.FileSystem())
	if profilesErr != nil {
		return nil, fmt.Errorf("apparmor profiles at %s could not be read: %w", apparmorProfilesPath, profilesErr)
	}

	// AppArmor is here, so the confined processes are part of the answer and a
	// failure to enumerate them is a failure to report.
	processManager, err := processmgr.ResolveManager(conn)
	if err != nil {
		return nil, err
	}
	procs, err := processManager.List()
	if err != nil {
		return nil, err
	}

	status := &apparmorStatus{
		Profiles:  profiles,
		Processes: readApparmorProcessesFromFS(conn.FileSystem(), procs),
	}

	return status, nil
}

// readApparmorProfilesFromFS reads the kernel's loaded-profile list. The error
// is returned rather than swallowed: on a host where the path exists but cannot
// be opened, an empty map is not the same answer as "no profiles are loaded".
func readApparmorProfilesFromFS(fs afero.Fs) (map[string]string, error) {
	f, err := fs.Open(apparmorProfilesPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	profiles := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name, mode, ok := parseApparmorProfileLine(scanner.Text())
		if ok {
			profiles[name] = mode
		}
	}
	return profiles, nil
}

func readApparmorProcessesFromFS(fs afero.Fs, procs []*processmgr.OSProcess) map[string][]apparmorProcInfo {
	processes := map[string][]apparmorProcInfo{}
	for _, proc := range procs {
		profile, status, ok := readApparmorCurrentForProcess(fs, proc.Pid)
		if !ok {
			continue
		}

		executable := apparmorProcessExecutable(proc)

		processes[executable] = append(processes[executable], apparmorProcInfo{
			Profile: profile,
			PID:     strconv.FormatInt(proc.Pid, 10),
			Status:  status,
		})
	}
	return processes
}

func readApparmorCurrentForProcess(fs afero.Fs, pid int64) (profile string, status string, ok bool) {
	pidStr := strconv.FormatInt(pid, 10)
	paths := []string{
		path.Join("/proc", pidStr, "attr/apparmor/current"),
		path.Join("/proc", pidStr, "attr/current"),
	}

	for _, path := range paths {
		data, err := afero.ReadFile(fs, path)
		if err != nil {
			continue
		}

		profile, status, ok = parseApparmorCurrentLabel(string(data))
		if ok {
			return profile, status, true
		}
	}

	return "", "", false
}

func apparmorProcessExecutable(proc *processmgr.OSProcess) string {
	if proc.Command != "" {
		fields := strings.Fields(proc.Command)
		if len(fields) > 0 && strings.Contains(fields[0], "/") {
			return fields[0]
		}
	}

	if proc.Executable != "" {
		return proc.Executable
	}
	if proc.Command != "" {
		return proc.Command
	}
	return strconv.FormatInt(proc.Pid, 10)
}

func parseApparmorProfileLine(line string) (name string, mode string, ok bool) {
	return parseApparmorModeLine(line)
}

func parseApparmorCurrentLabel(content string) (profile string, status string, ok bool) {
	line := strings.TrimSpace(strings.TrimRight(content, "\x00"))
	if line == "unconfined" {
		return "unconfined", "unconfined", true
	}
	return parseApparmorModeLine(line)
}

func parseApparmorModeLine(line string) (name string, mode string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasSuffix(line, ")") {
		return "", "", false
	}

	idx := strings.LastIndex(line, " (")
	if idx <= 0 {
		return "", "", false
	}

	name = strings.TrimSpace(line[:idx])
	mode = strings.TrimSpace(line[idx+2 : len(line)-1])
	if name == "" || mode == "" {
		return "", "", false
	}

	return name, mode, true
}

// installed reports whether this host has AppArmor, the way selinux.installed
// reports it for SELinux. It is the field a policy gates on: the ones below
// describe a host that has AppArmor, and answer for absence rather than
// failing so that gate can be evaluated at all.
func (a *mqlApparmor) installed() (bool, error) {
	if _, err := a.fetchStatus(); err != nil {
		if errors.Is(err, errApparmorNotPresent) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (a *mqlApparmor) version() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		// A host without AppArmor has no version, which is not the same as an
		// empty one, so the field resolves to null.
		if errors.Is(err, errApparmorNotPresent) {
			a.Version.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}
	return status.Version, nil
}

func (a *mqlApparmor) profiles() ([]any, error) {
	status, err := a.fetchStatus()
	if err != nil {
		// A host without AppArmor loads no profiles. That is a measured zero
		// rather than an unread list, so it is an empty list and not null.
		if errors.Is(err, errApparmorNotPresent) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(status.Profiles))
	for name, mode := range status.Profiles {
		r, err := CreateResource(a.MqlRuntime, "apparmor.profile", map[string]*llx.RawData{
			"name": llx.StringData(name),
			"mode": llx.StringData(mode),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlApparmor) processes() ([]any, error) {
	status, err := a.fetchStatus()
	if err != nil {
		// Likewise: a host without AppArmor confines no process.
		if errors.Is(err, errApparmorNotPresent) {
			return []any{}, nil
		}
		return nil, err
	}

	var res []any
	for executable, procs := range status.Processes {
		for _, p := range procs {
			pid, err := strconv.Atoi(p.PID)
			if err != nil {
				return nil, errors.New("invalid pid " + p.PID)
			}
			r, err := CreateResource(a.MqlRuntime, "apparmor.process", map[string]*llx.RawData{
				"executable": llx.StringData(executable),
				"profile":    llx.StringData(p.Profile),
				"pid":        llx.IntData(int64(pid)),
				"status":     llx.StringData(p.Status),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

func (a *mqlApparmorProfile) id() (string, error) {
	return "apparmor.profile:" + a.Name.Data, nil
}

func (a *mqlApparmorProcess) id() (string, error) {
	return "apparmor.process:" + a.Executable.Data + ":" + strconv.FormatInt(a.Pid.Data, 10), nil
}

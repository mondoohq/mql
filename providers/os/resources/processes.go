// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/processes"
	"go.mondoo.com/mql/providers/os/resources/procfs"
)

type mqlProcessInternal struct {
	SocketInodesError error
	SocketInodes      plugin.TValue[[]int64]
	processInfoError  error
	// argv is the kernel's argv when the process manager read it, nil when
	// it only has the space-joined command
	argv []string
	lock sync.Mutex
}

// processesError attaches the refusal kind to a hidepid refusal when
// structured errors are on. Without them it stays a plain error: v13 returned
// the scanner's own processes as if they were the full list, which is the
// fail-open this error replaces.
func processesError(err error) error {
	var hidden *processes.HiddenProcessesError
	if errors.As(err, &hidden) && plugin.StructuredErrors() {
		return llx.Forbidden(err)
	}
	return err
}

func initProcess(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// do not try to resolve the process if we already go all parameters
	// NOTE: this happens for a call like processes.list
	if len(args) > 2 {
		return args, nil, nil
	}

	pidValue, ok := args["pid"]
	if ok {
		pid, ok := pidValue.Value.(int64)
		if !ok {
			return nil, nil, errors.New("pid has invalid type")
		}

		// lets do minimal IO in initialize
		conn := runtime.Connection.(shared.Connection)
		opm, err := processes.ResolveManager(conn)
		if err != nil {
			return nil, nil, errors.New("cannot find process manager")
		}

		// check that the PID exists
		exists, err := opm.Exists(pid)
		var hidden *processes.HiddenProcessesError
		if errors.As(err, &hidden) {
			return nil, nil, processesError(err)
		}
		if err != nil || !exists {
			return nil, nil, errors.New("process " + strconv.FormatInt(pid, 10) + " does not exist")
		}
	}
	return args, nil, nil
}

func (p *mqlProcess) id() (string, error) {
	return strconv.FormatInt(p.Pid.Data, 10), nil
}

func (p *mqlProcess) state() (string, error) {
	return "", p.gatherProcessInfo()
}

func (p *mqlProcess) executable() (string, error) {
	return "", p.gatherProcessInfo()
}

func (p *mqlProcess) command() (string, error) {
	return "", p.gatherProcessInfo()
}

func (p *mqlProcess) flags() (map[string]any, error) {
	cmd := p.GetCommand()
	if cmd.Error != nil {
		return nil, cmd.Error
	}

	p.lock.Lock()
	argv := p.argv
	p.lock.Unlock()

	conn := p.MqlRuntime.Connection.(shared.Connection)
	if argv == nil && isLinuxAsset(conn) {
		argv = readProcArgv(conn, p.Pid.Data, cmd.Data)
	}

	fs := processes.FlagSet{}
	var err error
	if argv != nil {
		err = fs.ParseArgv(argv)
	} else if isWindowsAsset(conn) {
		// executable is only a hint for finding the end of an unquoted
		// program path, so a failure to read it is not a failure of flags
		exe := p.GetExecutable()
		if exe.Error != nil {
			log.Debug().Err(exe.Error).Msg("process executable unavailable, splitting argv[0] without it")
		}
		err = fs.ParseWindowsCommand(cmd.Data, exe.Data)
	} else {
		err = fs.ParseCommand(cmd.Data)
	}
	if err != nil {
		return nil, err
	}
	flags := fs.Map()

	res := map[string]any{}
	for k := range flags {
		res[k] = flags[k]
	}
	return res, nil
}

// readProcArgv reads a process's argv from /proc/<pid>/cmdline, for process
// managers that only have the space-joined command from ps (SSH). It runs cat
// rather than going through the file system, whose stat of a /proc file
// fails over SSH on some targets (RHEL 9). It returns nil when the file
// cannot be read.
func readProcArgv(conn shared.Connection, pid int64, command string) []string {
	c, err := conn.RunCommand("cat /proc/" + strconv.FormatInt(pid, 10) + "/cmdline")
	if err != nil || c == nil || c.ExitStatus != 0 {
		return nil
	}
	data, err := io.ReadAll(c.Stdout)
	if err != nil {
		return nil
	}
	return argvForCommand(data, command)
}

// argvForCommand splits a /proc/<pid>/cmdline into argv, or returns nil when
// it is empty or no longer belongs to the process whose command was listed
// (the pid was reused).
func argvForCommand(data []byte, command string) []string {
	if len(data) == 0 {
		return nil
	}
	joined, err := procfs.ParseProcessCmdline(bytes.NewReader(data))
	if err != nil || joined != command {
		return nil
	}
	return procfs.ParseProcessArgv(data)
}

func isLinuxAsset(conn shared.Connection) bool {
	asset := conn.Asset()
	return asset != nil && asset.Platform != nil && asset.Platform.IsFamily("linux")
}

func isWindowsAsset(conn shared.Connection) bool {
	asset := conn.Asset()
	return asset != nil && asset.Platform != nil && asset.Platform.IsFamily("windows")
}

type ProcessCallbackTrigger func()

func (p *mqlProcess) gatherProcessInfo() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.processInfoError != nil {
		return p.processInfoError
	}

	conn := p.MqlRuntime.Connection.(shared.Connection)
	opm, err := processes.ResolveManager(conn)
	if err != nil {
		p.processInfoError = fmt.Errorf("cannot find process manager: %w", err)
		return p.processInfoError
	}

	process, err := opm.Process(p.Pid.Data)
	if err != nil {
		p.processInfoError = processesError(fmt.Errorf("cannot gather process details: %w", err))
		return p.processInfoError
	}
	// A manager may report a pid it cannot find without an error. Guard the
	// dereference so an unresolvable process surfaces as an error rather than
	// taking down the provider.
	if process == nil {
		p.processInfoError = fmt.Errorf("cannot gather process details: process %d does not exist", p.Pid.Data)
		return p.processInfoError
	}

	p.State = plugin.TValue[string]{Data: process.State, State: plugin.StateIsSet}
	p.Executable = plugin.TValue[string]{Data: process.Executable, State: plugin.StateIsSet}
	p.Command = plugin.TValue[string]{Data: process.Command, State: plugin.StateIsSet}
	p.SocketInodes = plugin.TValue[[]int64]{Data: process.SocketInodes, State: plugin.StateIsSet}
	p.argv = process.Argv

	return nil
}

type mqlProcessesInternal struct {
	ByPID      map[int64]*mqlProcess
	BySocketID map[int64]*mqlProcess
}

func (p *mqlProcesses) list() ([]any, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	opm, err := processes.ResolveManager(conn)
	if opm == nil || err != nil {
		log.Debug().Err(err).Msg("mql[processes]> could not retrieve process resolver")
		return nil, errors.New("cannot find process manager")
	}

	// retrieve all system processes
	procs, err := opm.List()
	if err != nil {
		log.Warn().Err(err).Msg("mql[processes]> could not retrieve process list")
		var hidden *processes.HiddenProcessesError
		if errors.As(err, &hidden) {
			return nil, processesError(err)
		}
		return nil, fmt.Errorf("could not retrieve process list")
	}
	log.Debug().Int("processes", len(procs)).Msg("mql[processes]> running processes")

	processesInodesByPid, err := opm.ListSocketInodesByProcess()
	if err != nil {
		log.Warn().Err(err).Msg("mql[processes]> could not retrieve processes socket inodes")
		return nil, fmt.Errorf("could not retrieve processes socket inodes")
	}

	result := make([]any, len(procs))

	for i := range procs {
		proc := procs[i]

		o, err := CreateResource(p.MqlRuntime, "process", map[string]*llx.RawData{
			"pid":        llx.IntData(proc.Pid),
			"executable": llx.StringData(proc.Executable),
			"command":    llx.StringData(proc.Command),
			"state":      llx.StringData(proc.State),
		})
		if err != nil {
			return nil, err
		}

		socketInodes := []int64{}
		var socketInodesErr error
		if _, ok := processesInodesByPid[proc.Pid]; ok {
			socketInodes = processesInodesByPid[proc.Pid].Data
			socketInodesErr = processesInodesByPid[proc.Pid].Error
		} else {
			if len(proc.SocketInodes) > 0 {
				socketInodes = proc.SocketInodes
				socketInodesErr = proc.SocketInodesError
			}
		}
		process := o.(*mqlProcess)
		process.argv = proc.Argv
		process.SocketInodes = plugin.TValue[[]int64]{
			Data:  socketInodes,
			Error: socketInodesErr,
			State: plugin.StateIsSet,
		}

		result[i] = o
	}

	return result, p.refreshCache(result)
}

func (p *mqlProcesses) refreshCache(all []any) error {
	if all == nil {
		raw := p.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	processesMap := make(map[int64]*mqlProcess, len(all))
	socketsMap := map[int64]*mqlProcess{}

	for i := range all {
		process := all[i].(*mqlProcess)
		processesMap[process.Pid.Data] = process
		for i := range process.SocketInodes.Data {
			socketsMap[process.SocketInodes.Data[i]] = process
		}
	}

	p.ByPID = processesMap
	p.BySocketID = socketsMap
	return nil
}

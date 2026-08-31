// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

type mqlProcessInternal struct {
	SocketInodesError error
	SocketInodes      plugin.TValue[[]int64]
	processInfoError  error
	lock              sync.Mutex
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

	fs := processes.FlagSet{}
	err := fs.ParseCommand(cmd.Data)
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
		p.processInfoError = fmt.Errorf("cannot gather process details: %w", err)
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
		return nil, fmt.Errorf("could not retrieve process list")
	}
	log.Debug().Int("processes", len(procs)).Msg("mql[processes]> running processes")

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

		process := o.(*mqlProcess)
		process.SocketInodes = plugin.TValue[[]int64]{
			Data:  proc.SocketInodes,
			Error: proc.SocketInodesError,
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

func (p *mqlProcesses) refreshCacheForSocketLookup(all []any) error {
	if all == nil {
		raw := p.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	if err := p.collectSocketInodes(all); err != nil {
		return err
	}

	return p.refreshCache(all)
}

func (p *mqlProcesses) collectSocketInodes(all []any) error {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	opm, err := processes.ResolveManager(conn)
	if opm == nil || err != nil {
		log.Debug().Err(err).Msg("mql[processes]> could not retrieve process resolver")
		return errors.New("cannot find process manager")
	}

	processesInodesByPid, err := opm.ListSocketInodesByProcess()
	if err != nil {
		log.Warn().Err(err).Msg("mql[processes]> could not retrieve processes socket inodes")
		return fmt.Errorf("could not retrieve processes socket inodes")
	}

	for i := range all {
		process := all[i].(*mqlProcess)

		socketInodes := process.SocketInodes.Data
		socketInodesErr := process.SocketInodes.Error
		if socketInodes == nil {
			socketInodes = []int64{}
		}

		if inodeInfo, ok := processesInodesByPid[process.Pid.Data]; ok {
			socketInodes = inodeInfo.Data
			socketInodesErr = inodeInfo.Error
		}

		process.SocketInodes = plugin.TValue[[]int64]{
			Data:  socketInodes,
			Error: socketInodesErr,
			State: plugin.StateIsSet,
		}
	}

	return nil
}

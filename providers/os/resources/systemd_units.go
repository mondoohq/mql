// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/services"
)

// =============================================================================
// systemd.timer
// =============================================================================

type mqlSystemdTimerInternal struct {
	lock    sync.Mutex
	fetched bool
	props   map[string]string
}

func (t *mqlSystemdTimer) id() (string, error) {
	return "systemd.timer:" + t.Name.Data, nil
}

func initSystemdTimer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("cannot initialize systemd.timer, need at least a name")
	}

	name := x.Value.(string)
	if name == "" {
		return nil, nil, errors.New("cannot look for a timer with an empty name")
	}

	conn := runtime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdTimerManager(conn)
	timer, err := mgr.Get(name)
	if err != nil {
		if errors.Is(err, services.ErrServiceNotFound) {
			return nil, missingSystemdTimerResource(runtime, name), nil
		}
		return nil, nil, err
	}

	res, err := createSystemdTimerResource(runtime, timer)
	if err != nil {
		return nil, nil, err
	}

	return nil, res, nil
}

func createSystemdTimerResource(runtime *plugin.Runtime, timer *services.SystemdTimer) (plugin.Resource, error) {
	return CreateResource(runtime, "systemd.timer", map[string]*llx.RawData{
		"name":        llx.StringData(timer.Name),
		"description": llx.StringData(timer.Description),
		"installed":   llx.BoolData(timer.Installed),
		"enabled":     llx.BoolData(timer.Enabled),
		"masked":      llx.BoolData(timer.Masked),
		"running":     llx.BoolData(timer.Running),
		"static":      llx.BoolData(timer.Static),
	})
}

func normalizeSystemdUnitLookupName(name string, suffix string) string {
	return strings.TrimSuffix(name, suffix)
}

func missingSystemdTimerResource(runtime *plugin.Runtime, name string) plugin.Resource {
	res := &mqlSystemdTimer{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: normalizeSystemdUnitLookupName(name, ".timer"), State: plugin.StateIsSet}
	res.Description.State = plugin.StateIsSet | plugin.StateIsNull
	res.Installed = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Running = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Enabled = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Masked = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Static = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Activates.State = plugin.StateIsSet | plugin.StateIsNull
	res.OnCalendar.State = plugin.StateIsSet | plugin.StateIsNull
	res.Persistent = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.__id, _ = res.id()
	return res
}

func (t *mqlSystemdTimer) fetchProperties() (map[string]string, error) {
	if t.fetched {
		return t.props, nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.fetched {
		return t.props, nil
	}

	conn := t.MqlRuntime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdTimerManager(conn)
	props, err := mgr.ShowTimerProperties(t.Name.Data)
	if err != nil {
		return nil, err
	}
	t.props = props
	t.fetched = true
	return t.props, nil
}

func (t *mqlSystemdTimer) activates() (string, error) {
	props, err := t.fetchProperties()
	if err != nil {
		return "", err
	}
	return props["Unit"], nil
}

func (t *mqlSystemdTimer) onCalendar() (string, error) {
	props, err := t.fetchProperties()
	if err != nil {
		return "", err
	}
	return props["OnCalendar"], nil
}

func (t *mqlSystemdTimer) persistent() (bool, error) {
	props, err := t.fetchProperties()
	if err != nil {
		return false, err
	}
	// `systemctl show` normalizes booleans to yes/no, but the filesystem-based
	// path passes the unit file's raw value through, which may be true/1/on.
	return parseYesNo(props["Persistent"], false), nil
}

// =============================================================================
// systemd.timers
// =============================================================================

func (x *mqlSystemdTimers) id() (string, error) {
	return "systemd.timers", nil
}

func (x *mqlSystemdTimers) list() ([]any, error) {
	conn := x.MqlRuntime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdTimerManager(conn)
	timers, err := mgr.List()
	if err != nil {
		log.Debug().Err(err).Msg("mql[systemd.timers]> could not retrieve timer list")
		return nil, errors.New("could not retrieve systemd timer list")
	}
	log.Debug().Int("timers", len(timers)).Msg("mql[systemd.timers]> found timers")

	var result []any
	for _, timer := range timers {
		r, err := createSystemdTimerResource(x.MqlRuntime, timer)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return result, nil
}

// =============================================================================
// systemd.socket
// =============================================================================

type mqlSystemdSocketInternal struct {
	lock    sync.Mutex
	fetched bool
	props   map[string]string
}

func (s *mqlSystemdSocket) id() (string, error) {
	return "systemd.socket:" + s.Name.Data, nil
}

func initSystemdSocket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("cannot initialize systemd.socket, need at least a name")
	}

	name := x.Value.(string)
	if name == "" {
		return nil, nil, errors.New("cannot look for a socket with an empty name")
	}

	conn := runtime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdSocketManager(conn)
	socket, err := mgr.Get(name)
	if err != nil {
		if errors.Is(err, services.ErrServiceNotFound) {
			return nil, missingSystemdSocketResource(runtime, name), nil
		}
		return nil, nil, err
	}

	res, err := createSystemdSocketResource(runtime, socket)
	if err != nil {
		return nil, nil, err
	}

	return nil, res, nil
}

func createSystemdSocketResource(runtime *plugin.Runtime, socket *services.SystemdSocket) (plugin.Resource, error) {
	return CreateResource(runtime, "systemd.socket", map[string]*llx.RawData{
		"name":        llx.StringData(socket.Name),
		"description": llx.StringData(socket.Description),
		"installed":   llx.BoolData(socket.Installed),
		"enabled":     llx.BoolData(socket.Enabled),
		"masked":      llx.BoolData(socket.Masked),
		"running":     llx.BoolData(socket.Running),
		"static":      llx.BoolData(socket.Static),
	})
}

func missingSystemdSocketResource(runtime *plugin.Runtime, name string) plugin.Resource {
	res := &mqlSystemdSocket{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: normalizeSystemdUnitLookupName(name, ".socket"), State: plugin.StateIsSet}
	res.Description.State = plugin.StateIsSet | plugin.StateIsNull
	res.Installed = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Running = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Enabled = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Masked = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Static = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Activates.State = plugin.StateIsSet | plugin.StateIsNull
	res.ListenAddresses.State = plugin.StateIsSet | plugin.StateIsNull
	res.Accept = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.__id, _ = res.id()
	return res
}

func (s *mqlSystemdSocket) fetchProperties() (map[string]string, error) {
	if s.fetched {
		return s.props, nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return s.props, nil
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdSocketManager(conn)
	props, err := mgr.ShowSocketProperties(s.Name.Data)
	if err != nil {
		return nil, err
	}
	s.props = props
	s.fetched = true
	return s.props, nil
}

func (s *mqlSystemdSocket) activates() (string, error) {
	props, err := s.fetchProperties()
	if err != nil {
		return "", err
	}
	return props["Triggers"], nil
}

func (s *mqlSystemdSocket) accept() (bool, error) {
	props, err := s.fetchProperties()
	if err != nil {
		return false, err
	}
	// `systemctl show` normalizes booleans to yes/no, but the filesystem-based
	// path passes the unit file's raw value through, which may be true/1/on.
	return parseYesNo(props["Accept"], false), nil
}

func (s *mqlSystemdSocket) listenAddresses() ([]any, error) {
	props, err := s.fetchProperties()
	if err != nil {
		return nil, err
	}

	addrs := services.ParseListenProperty(props["Listen"])
	result := make([]any, len(addrs))
	for i, addr := range addrs {
		result[i] = addr
	}
	return result, nil
}

// =============================================================================
// systemd.sockets
// =============================================================================

func (x *mqlSystemdSockets) id() (string, error) {
	return "systemd.sockets", nil
}

func (x *mqlSystemdSockets) list() ([]any, error) {
	conn := x.MqlRuntime.Connection.(shared.Connection)
	mgr := services.ResolveSystemdSocketManager(conn)
	sockets, err := mgr.List()
	if err != nil {
		log.Debug().Err(err).Msg("mql[systemd.sockets]> could not retrieve socket list")
		return nil, errors.New("could not retrieve systemd socket list")
	}
	log.Debug().Int("sockets", len(sockets)).Msg("mql[systemd.sockets]> found sockets")

	var result []any
	for _, socket := range sockets {
		r, err := createSystemdSocketResource(x.MqlRuntime, socket)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return result, nil
}

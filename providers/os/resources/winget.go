// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

type mqlWingetInternal struct {
	lock    sync.Mutex
	fetched bool
}

func (w *mqlWinget) id() (string, error) {
	return "winget", nil
}

func (s *mqlWingetSource) id() (string, error) {
	return "winget.source/" + s.Origin.Data + "/" + s.Name.Data, nil
}

// wingetResult is the computed state of winget on one host. Pointers and nil
// slices are null in MQL.
type wingetResult struct {
	installed           bool
	version             *string
	architecture        *string
	packageFullName     *string
	path                *string
	enabledByPolicy     *bool
	missingDependencies []string
	systemUsable        *bool
	sources             []windows.WingetSource
}

// computeWinget turns the collected state into the resource's answer.
//
// systemUsable is a read-only heuristic for whether winget can run as the
// SYSTEM account. It is true when all of these hold:
//   - an App Installer package ships winget.exe for an architecture the
//     machine can run (the newest version wins, native architecture on a tie)
//   - every PackageDependency in that package's AppxManifest.xml is satisfied
//     by a package on the machine with a matching or neutral architecture and
//     at least the required version (SYSTEM has no per-user package
//     registration, so it relies on these frameworks being staged machine-wide)
//   - Group Policy does not disable winget or its command line
//
// It is null when the manifest cannot be read, since the dependencies are then
// unknown.
func computeWinget(s *windows.WingetState) wingetResult {
	enabled := s.Policy.Enabled()
	res := wingetResult{
		enabledByPolicy: &enabled,
		sources:         windows.ResolveWingetSources(s.Policy, s.UserSources),
	}

	cand, id, ok := windows.SelectWingetCandidate(s.Candidates, s.MachineArch)
	if !ok {
		f := false
		res.systemUsable = &f
		return res
	}

	res.installed = true
	res.version = &id.Version
	res.architecture = &id.Architecture
	res.packageFullName = &cand.FullName
	exe := strings.TrimRight(cand.Root, `\`) + `\winget.exe`
	res.path = &exe

	if strings.TrimSpace(cand.Manifest) == "" {
		return res
	}
	deps, err := windows.ParseAppxDependencies(cand.Manifest)
	if err != nil {
		return res
	}
	res.missingDependencies = windows.MissingDependencies(deps, s.Packages, id.Architecture)
	usable := len(res.missingDependencies) == 0 && enabled
	res.systemUsable = &usable
	return res
}

func stringPtrField(v *string) plugin.TValue[string] {
	if v == nil {
		return plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[string]{Data: *v, State: plugin.StateIsSet}
}

func (r wingetResult) set(w *mqlWinget) error {
	w.Installed = plugin.TValue[bool]{Data: r.installed, State: plugin.StateIsSet}
	w.Version = stringPtrField(r.version)
	w.Architecture = stringPtrField(r.architecture)
	w.PackageFullName = stringPtrField(r.packageFullName)
	w.Path = stringPtrField(r.path)
	w.EnabledByPolicy = boolFieldPtr(r.enabledByPolicy)
	w.SystemUsable = boolFieldPtr(r.systemUsable)

	if r.missingDependencies == nil {
		w.MissingDependencies = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	} else {
		deps := make([]any, len(r.missingDependencies))
		for i, d := range r.missingDependencies {
			deps[i] = d
		}
		w.MissingDependencies = plugin.TValue[[]any]{Data: deps, State: plugin.StateIsSet}
	}

	if r.sources == nil {
		w.Sources = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil
	}
	sources := make([]any, 0, len(r.sources))
	for _, s := range r.sources {
		o, err := CreateResource(w.MqlRuntime, "winget.source", map[string]*llx.RawData{
			"name":     llx.StringData(s.Name),
			"url":      llx.StringData(s.URL),
			"type":     llx.StringData(s.Type),
			"origin":   llx.StringData(s.Origin),
			"explicit": llx.BoolData(s.Explicit),
		})
		if err != nil {
			return err
		}
		sources = append(sources, o)
	}
	w.Sources = plugin.TValue[[]any]{Data: sources, State: plugin.StateIsSet}
	return nil
}

// populate reads winget's state once and sets every field, so every accessor
// shares one command and one error path.
func (w *mqlWinget) populate() error {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.fetched {
		return nil
	}

	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("winget is not supported on this connection")
	}

	var res wingetResult
	platform := conn.Asset().Platform
	if platform != nil && platform.IsFamily(inventory.FAMILY_WINDOWS) {
		s, err := readWingetState(conn)
		if err != nil {
			return err
		}
		res = computeWinget(s)
	}

	if err := res.set(w); err != nil {
		return err
	}
	w.fetched = true
	return nil
}

func readWingetState(conn shared.Connection) (*windows.WingetState, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("winget requires a connection that can run commands")
	}
	executed, err := conn.RunCommand(powershell.Encode(windows.PSGetWingetState))
	if err != nil {
		return nil, err
	}
	if executed.ExitStatus != 0 {
		stderr, err := io.ReadAll(executed.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to read winget state: " + string(stderr))
	}
	return windows.ParseWingetState(executed.Stdout)
}

func (w *mqlWinget) installed() (bool, error)            { return false, w.populate() }
func (w *mqlWinget) version() (string, error)            { return "", w.populate() }
func (w *mqlWinget) architecture() (string, error)       { return "", w.populate() }
func (w *mqlWinget) packageFullName() (string, error)    { return "", w.populate() }
func (w *mqlWinget) path() (string, error)               { return "", w.populate() }
func (w *mqlWinget) enabledByPolicy() (bool, error)      { return false, w.populate() }
func (w *mqlWinget) missingDependencies() ([]any, error) { return nil, w.populate() }
func (w *mqlWinget) systemUsable() (bool, error)         { return false, w.populate() }
func (w *mqlWinget) sources() ([]any, error)             { return nil, w.populate() }

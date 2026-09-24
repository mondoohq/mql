// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// runWindowsPowerShell runs a PowerShell script on the target and returns its
// standard output.
//
// A non-zero exit is an error carrying the script's own stderr, never an empty
// result. Every caller reads a security setting, and a setting that could not
// be read has to fail the check rather than resolve to whatever value the zero
// value happens to be: "no listener is configured" and "the listener
// configuration could not be read" satisfy an audit identically, and only one
// of them should.
func runWindowsPowerShell(runtime *plugin.Runtime, script, what string) (io.Reader, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("failed to " + what + ": this connection type is not supported")
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("failed to " + what + ": this connection cannot run commands")
	}

	executedCmd, err := conn.RunCommand(powershell.Encode(script))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to " + what + ": " + strings.TrimSpace(string(stderr)))
	}
	return executedCmd.Stdout, nil
}

// initWindowsSingletonChild fills in a singleton sub-resource that is reached
// by a dotted path which is also its own registered resource name.
//
// The field `config` on `windows.update` and the resource
// `windows.update.config` occupy the same path. The compiler resolves the
// longest matching resource name before it considers a field, so the dotted
// path instantiates the sub-resource directly and the parent's accessor never
// runs. Its plain schema fields are populated only by the parent, so every one
// stays unset and reports "provider returned no data and no error".
//
// Worse, the husk is created with the same __id the parent would use, so it
// also occupies the runtime cache entry for the real resource: a query that
// mixes the dotted and the block form resolves the husk first and the block
// form then reads the husk's unset fields as null.
//
// Delegating to the parent's accessor fills the resource in. The block form
// `windows.update { config { ... } }` binds the field instead of resolving a
// resource name and was never affected. When the resource is created normally
// by the parent it carries an __id, and this is a no-op.
func initWindowsSingletonChild[T plugin.Resource](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	parentName string,
	get func(plugin.Resource) *plugin.TValue[T],
) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, parentName, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := get(parent)
	if v.Error != nil {
		return nil, nil, v.Error
	}
	return args, v.Data, nil
}

func (s *mqlWindows) computerInfo() (map[string]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	cmd := windows.PSGetComputerInfo

	// encode the powershell command
	encodedCmd := powershell.Encode(cmd)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	// If the exit code is not 0, then we got an error and we should read stderr for details
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve computer info: " + string(stderr))
	}

	parsedInfo, err := windows.ParseComputerInfo(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	// If we have no error but OsProductType is nil, we need to run a custom command to get the info
	// For reference, see https://github.com/mondoohq/mql/pull/4520
	if parsedInfo["OsProductType"] == nil {
		executedCmd, err := conn.RunCommand(powershell.Encode(windows.PSGetComputerInfoCustom))
		if err != nil {
			return nil, err
		}
		if executedCmd.ExitStatus != 0 {
			stderr, err := io.ReadAll(executedCmd.Stderr)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("failed to retrieve computer info: " + string(stderr))
		}
		parsedInfo, err = windows.ParseCustomComputerInfo(executedCmd.Stdout)
		if err != nil {
			return nil, err
		}
	}

	return parsedInfo, nil
}

func (wh *mqlWindowsHotfix) id() (string, error) {
	return wh.HotfixId.Data, nil
}

func initWindowsHotfix(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	nameRaw := args["hotfixId"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	obj, err := NewResource(runtime, "windows", nil)
	if err != nil {
		return nil, nil, err
	}
	winResource := obj.(*mqlWindows)

	hotfixes := winResource.GetHotfixes()
	if hotfixes.Error != nil {
		return nil, nil, hotfixes.Error
	}

	for i := range hotfixes.Data {
		hf := hotfixes.Data[i].(*mqlWindowsHotfix)
		if hf.HotfixId.Data == name {
			return nil, hf, nil
		}
	}

	// if the hotfix cannot be found we return an error
	return nil, nil, errors.New("could not find hotfix " + name)
}

// mqlWindowsInternal backs the windows resource's Go-only state: nothing
// here is an MQL field, so it never appears in the .lr schema.
type mqlWindowsInternal struct {
	lock sync.Mutex

	// hotfixesRaw is the same Get-HotFix outcome hotfixes() below parses,
	// kept here (alongside the windows.hotfix resources hotfixes() returns)
	// so packages.list (WinPkgManager.List, via packages.go's
	// injectWindowsHotfixes) can reuse it directly instead of running
	// Get-HotFix a second time. It is read raw, never by converting the
	// windows.hotfix resources: those set installedOn from
	// hf.InstalledOnTime() alone, the unadjusted epoch instant, while
	// packages.list needs installedOnDate's local-midnight adjustment
	// (windows_packages.go) to keep a package's install date from shifting a
	// day on any host east of UTC.
	//
	// hotfixesRawSet distinguishes "hotfixes() has not run on this runtime"
	// from "hotfixes() ran and found zero hotfixes": GetHotfixes()'s field
	// cache can be answered from a recording without hotfixes() ever running
	// (see createWindows's early return when runtime.HasRecording), and an
	// unpopulated slice must not be mistaken for a genuine empty result.
	hotfixesRaw    []packages.PowershellWinHotFix
	hotfixesRawSet bool
}

func (w *mqlWindows) hotfixes() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query hotfixes
	encodedCmd := powershell.Encode(packages.WINDOWS_QUERY_HOTFIXES)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve hotfixes: " + string(stderr))
	}

	hotfixes, err := packages.ParseWindowsHotfixes(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	// Stash the raw parsed slice for packages.list to reuse (see
	// mqlWindowsInternal.hotfixesRaw), before any MQL conversion below.
	w.lock.Lock()
	w.hotfixesRaw = hotfixes
	w.hotfixesRawSet = true
	w.lock.Unlock()

	// convert hotfixes to MQL resource
	mqlHotFixes := make([]any, len(hotfixes))
	for i, hf := range hotfixes {
		mqlHotfix, err := CreateResource(w.MqlRuntime, "windows.hotfix", map[string]*llx.RawData{
			"hotfixId":    llx.StringData(hf.HotFixId),
			"caption":     llx.StringData(hf.Caption),
			"description": llx.StringData(hf.Description),
			"installedOn": llx.TimeDataPtr(hf.InstalledOnTime()),
			"installedBy": llx.StringData(hf.InstalledBy),
		})
		if err != nil {
			return nil, err
		}

		mqlHotFixes[i] = mqlHotfix
	}

	return mqlHotFixes, nil
}

// rawHotfixes returns the Get-HotFix outcome hotfixes() last parsed on this
// runtime, and whether hotfixes() has actually run here. See
// mqlWindowsInternal.hotfixesRawSet for why the two are distinguished: a
// caller (packages.go's injectWindowsHotfixes) must treat "not set" as "go
// run the query yourself," never as "this host has no hotfixes."
func (w *mqlWindows) rawHotfixes() ([]packages.PowershellWinHotFix, bool) {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.hotfixesRaw, w.hotfixesRawSet
}

func (wh *mqlWindowsServerFeature) id() (string, error) {
	return wh.Path.Data, nil
}

func initWindowsServerFeature(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	obj, err := NewResource(runtime, "windows", nil)
	if err != nil {
		return nil, nil, err
	}
	winResource := obj.(*mqlWindows)

	features := winResource.GetServerFeatures()
	if features.Error != nil {
		return nil, nil, features.Error
	}

	for i := range features.Data {
		hf := features.Data[i].(*mqlWindowsServerFeature)
		if hf.Name.Data == name {
			return nil, hf, nil
		}
	}

	// if the feature cannot be found we return an error
	return nil, nil, errors.New("could not find feature " + name)
}

func (w *mqlWindows) serverFeatures() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query features
	encodedCmd := powershell.Encode(windows.QUERY_FEATURES)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve features: " + string(stderr))
	}

	features, err := windows.ParseWindowsFeatures(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	// convert features to MQL resource
	mqlFeatures := make([]any, len(features))
	for i, feature := range features {

		mqlFeature, err := CreateResource(w.MqlRuntime, "windows.serverFeature", map[string]*llx.RawData{
			"path":         llx.StringData(feature.Path),
			"name":         llx.StringData(feature.Name),
			"displayName":  llx.StringData(feature.DisplayName),
			"description":  llx.StringData(feature.Description),
			"installed":    llx.BoolData(feature.Installed),
			"installState": llx.IntData(feature.InstallState),
		})
		if err != nil {
			return nil, err
		}

		mqlFeatures[i] = mqlFeature
	}

	return mqlFeatures, nil
}

func (wh *mqlWindowsOptionalFeature) id() (string, error) {
	return wh.Name.Data, nil
}

func initWindowsOptionalFeature(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return args, nil, nil
	}

	encodedCmd := powershell.Encode(windows.OptionalFeatureQuery(name))
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, nil, err
	}

	// a non-zero exit means the feature name is unknown
	if executedCmd.ExitStatus != 0 {
		return nil, nil, errors.New("could not find feature " + name)
	}

	features, err := windows.ParseWindowsOptionalFeatures(executedCmd.Stdout)
	if err != nil {
		return nil, nil, err
	}

	// DISM treats `*`/`?` in -FeatureName as wildcards, so a wildcard-ish name
	// can return more than one feature (or none matching exactly); require an
	// exact name match to keep the historic "could not find feature" behavior.
	for i := range features {
		feature := features[i]
		if feature.Name != name {
			continue
		}
		return map[string]*llx.RawData{
			"name":        llx.StringData(feature.Name),
			"displayName": llx.StringData(feature.DisplayName),
			"description": llx.StringData(feature.Description),
			"enabled":     llx.BoolData(feature.Enabled),
			"state":       llx.IntData(feature.State),
		}, nil, nil
	}

	// if the feature cannot be found we return an error
	return nil, nil, errors.New("could not find feature " + name)
}

// optionalFeatureDetails carries the display name and description of every
// feature in one enumeration. DISM only reports those for a named feature, so
// they cost an extra image query — one for the whole enumeration, taken the
// first time a query actually asks for them.
type optionalFeatureDetails struct {
	lock   sync.Mutex
	loaded bool
	byName map[string]windows.WindowsOptionalFeature
}

// mqlWindowsOptionalFeatureInternal shares the lazily loaded details with the
// other features from the same windows.optionalFeatures enumeration. It is nil
// for a feature looked up by name, where the init function has already filled
// every field in from its single-feature query.
type mqlWindowsOptionalFeatureInternal struct {
	details *optionalFeatureDetails
}

func (w *mqlWindows) optionalFeatures() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query features
	encodedCmd := powershell.Encode(windows.QUERY_OPTIONAL_FEATURES)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve optional features: " + string(stderr))
	}

	features, err := windows.ParseWindowsOptionalFeatures(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	// convert features to MQL resource
	details := &optionalFeatureDetails{}
	mqlFeatures := make([]any, len(features))
	for i, feature := range features {

		mqlFeature, err := CreateResource(w.MqlRuntime, "windows.optionalFeature", map[string]*llx.RawData{
			"name":    llx.StringData(feature.Name),
			"enabled": llx.BoolData(feature.Enabled),
			"state":   llx.IntData(feature.State),
		})
		if err != nil {
			return nil, err
		}

		mqlFeature.(*mqlWindowsOptionalFeature).details = details
		mqlFeatures[i] = mqlFeature
	}

	return mqlFeatures, nil
}

func (f *mqlWindowsOptionalFeature) displayName() (string, error) {
	feature, err := f.fetchDetails()
	if err != nil {
		return "", err
	}
	return feature.DisplayName, nil
}

func (f *mqlWindowsOptionalFeature) description() (string, error) {
	feature, err := f.fetchDetails()
	if err != nil {
		return "", err
	}
	return feature.Description, nil
}

// fetchDetails loads the fields that DISM only reports for a named feature. For
// a feature that came from an enumeration this is one query for all of them,
// shared with its siblings; for a standalone feature it is a single-feature
// query.
func (f *mqlWindowsOptionalFeature) fetchDetails() (windows.WindowsOptionalFeature, error) {
	var empty windows.WindowsOptionalFeature

	name := f.GetName()
	if name.Error != nil {
		return empty, name.Error
	}

	if f.details == nil {
		features, err := f.queryFeatures(windows.OptionalFeatureQuery(name.Data))
		if err != nil {
			return empty, err
		}
		for i := range features {
			// DISM treats `*`/`?` in -FeatureName as wildcards, so require an
			// exact match
			if features[i].Name == name.Data {
				return features[i], nil
			}
		}
		return empty, errors.New("could not find feature " + name.Data)
	}

	f.details.lock.Lock()
	defer f.details.lock.Unlock()

	if !f.details.loaded {
		features, err := f.queryFeatures(windows.QUERY_OPTIONAL_FEATURE_DETAILS)
		if err != nil {
			return empty, err
		}
		f.details.byName = make(map[string]windows.WindowsOptionalFeature, len(features))
		for i := range features {
			f.details.byName[features[i].Name] = features[i]
		}
		f.details.loaded = true
	}

	feature, ok := f.details.byName[name.Data]
	if !ok {
		return empty, errors.New("could not find feature " + name.Data)
	}
	return feature, nil
}

func (f *mqlWindowsOptionalFeature) queryFeatures(query string) ([]windows.WindowsOptionalFeature, error) {
	conn := f.MqlRuntime.Connection.(shared.Connection)

	executedCmd, err := conn.RunCommand(powershell.Encode(query))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve optional feature details: " + string(stderr))
	}

	return windows.ParseWindowsOptionalFeatures(executedCmd.Stdout)
}

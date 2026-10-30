// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// =============================================================================
// kernel.livepatch — /sys/kernel/livepatch and the Canonical Livepatch client
// =============================================================================

const (
	sysKernelDir       = "/sys/kernel"
	sysKernelLivepatch = "/sys/kernel/livepatch"

	// The Canonical Livepatch client ships only as a snap. It is called by its
	// full path because /snap/bin is not on the PATH of a non-login shell.
	canonicalLivepatchClient   = "/snap/bin/canonical-livepatch"
	canonicalLivepatchPrefix   = "lkp_Ubuntu_"
	livepatchProviderCanonical = "canonical-livepatch"
	livepatchProviderKlp       = "klp"
)

type mqlKernelLivepatchInternal struct {
	lock         sync.Mutex
	clientLoaded bool
	client       *canonicalLivepatchReport
	clientErr    error
}

// kernelLivepatch is one patch directory under /sys/kernel/livepatch.
type kernelLivepatch struct {
	name       string
	enabled    bool
	transition bool
	objects    []string
}

func (k *mqlKernel) livepatch() (*mqlKernelLivepatch, error) {
	conn, ok := k.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("kernel.livepatch requires a connection with a file system")
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	patches, ok, err := readKernelLivepatches(afs)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"__id":     llx.StringData("kernel.livepatch"),
		"active":   llx.NilData,
		"provider": llx.NilData,
		"patches":  llx.NilData,
	}
	if ok {
		clientInstalled, _ := afs.Exists(canonicalLivepatchClient)

		list := make([]any, 0, len(patches))
		active := false
		for _, p := range patches {
			active = active || p.enabled
			r, err := CreateResource(k.MqlRuntime, "kernel.livepatch.patch", map[string]*llx.RawData{
				"__id":       llx.StringData("kernel.livepatch.patch/" + p.name),
				"name":       llx.StringData(p.name),
				"enabled":    llx.BoolData(p.enabled),
				"transition": llx.BoolData(p.transition),
				"objects":    llx.ArrayData(stringsAsAnySlice(p.objects), types.String),
			})
			if err != nil {
				return nil, err
			}
			list = append(list, r)
		}
		args["active"] = llx.BoolData(active)
		args["provider"] = llx.StringData(livepatchProvider(patches, clientInstalled))
		args["patches"] = llx.ArrayData(list, types.Resource("kernel.livepatch.patch"))
	}

	r, err := CreateResource(k.MqlRuntime, "kernel.livepatch", args)
	if err != nil {
		return nil, err
	}
	return r.(*mqlKernelLivepatch), nil
}

// readKernelLivepatches lists the patches in /sys/kernel/livepatch. ok is false
// when /sys/kernel itself cannot be read, as in an image or filesystem scan,
// where the running kernel's state is unknown. A kernel without live patch
// support has /sys/kernel but no livepatch directory: ok, and no patches.
func readKernelLivepatches(afs *afero.Afero) ([]kernelLivepatch, bool, error) {
	if exists, err := afs.DirExists(sysKernelDir); err != nil || !exists {
		return nil, false, nil
	}

	entries, err := afs.ReadDir(sysKernelLivepatch)
	if err != nil {
		// the connection's virtual filesystem may not return *os.PathError,
		// so match the wrapped sentinel rather than using os.IsNotExist
		if errors.Is(err, fs.ErrNotExist) {
			return []kernelLivepatch{}, true, nil
		}
		return nil, false, err
	}

	patches := []kernelLivepatch{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := path.Join(sysKernelLivepatch, e.Name())
		p := kernelLivepatch{name: e.Name(), objects: []string{}}

		enabled, err := readSysfsBool(afs, path.Join(dir, "enabled"))
		if err != nil {
			return nil, false, err
		}
		p.enabled = enabled
		transition, err := readSysfsBool(afs, path.Join(dir, "transition"))
		if err != nil {
			return nil, false, err
		}
		p.transition = transition

		// Each patched object (vmlinux or a module) is a subdirectory; the
		// patch's own attributes are files.
		objects, err := afs.ReadDir(dir)
		if err != nil {
			return nil, false, err
		}
		for _, o := range objects {
			if o.IsDir() {
				p.objects = append(p.objects, o.Name())
			}
		}
		sort.Strings(p.objects)
		patches = append(patches, p)
	}
	sort.Slice(patches, func(i, j int) bool { return patches[i].name < patches[j].name })
	return patches, true, nil
}

// readSysfsBool reads a sysfs attribute holding 0 or 1.
func readSysfsBool(afs *afero.Afero, p string) (bool, error) {
	data, err := afs.ReadFile(p)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected value %q in %s", strings.TrimSpace(string(data)), p)
	}
}

// livepatchProvider names the tool behind the live patches. Canonical's patch
// modules are named lkp_Ubuntu_<kernel>_<patch version>, for example
// lkp_Ubuntu_6_8_0_1047_50_aws_121.
func livepatchProvider(patches []kernelLivepatch, canonicalClientInstalled bool) string {
	if canonicalClientInstalled {
		return livepatchProviderCanonical
	}
	for _, p := range patches {
		if strings.HasPrefix(p.name, canonicalLivepatchPrefix) {
			return livepatchProviderCanonical
		}
	}
	if len(patches) > 0 {
		return livepatchProviderKlp
	}
	return ""
}

// initKernelLivepatch makes `kernel.livepatch` queried by its own path resolve
// to the resource kernel.livepatch() builds, instead of an empty one.
func initKernelLivepatch(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	k, err := CreateResource(runtime, "kernel", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	lp := k.(*mqlKernel).GetLivepatch()
	if lp.Error != nil {
		return nil, nil, lp.Error
	}
	return args, lp.Data, nil
}

func (l *mqlKernelLivepatch) id() (string, error) {
	return "kernel.livepatch", nil
}

func (p *mqlKernelLivepatchPatch) id() (string, error) {
	return "kernel.livepatch.patch/" + p.Name.Data, nil
}

// canonicalLivepatchReport is what the Canonical Livepatch client reports on
// the running kernel.
type canonicalLivepatchReport struct {
	version string
	state   string
	cves    []string
}

// canonicalLivepatchStatus mirrors `canonical-livepatch status --format json`.
type canonicalLivepatchStatus struct {
	Status []struct {
		Kernel    string `json:"Kernel"`
		Running   bool   `json:"Running"`
		Livepatch struct {
			State   string `json:"State"`
			Version string `json:"Version"`
			Fixes   []struct {
				Name    string `json:"Name"`
				Patched bool   `json:"Patched"`
			} `json:"Fixes"`
		} `json:"Livepatch"`
	} `json:"Status"`
}

// parseCanonicalLivepatchStatus returns the report for the running kernel, or
// nil when the output carries no entry for it.
func parseCanonicalLivepatchStatus(data []byte) (*canonicalLivepatchReport, error) {
	var status canonicalLivepatchStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	for _, s := range status.Status {
		if !s.Running {
			continue
		}
		report := &canonicalLivepatchReport{
			version: s.Livepatch.Version,
			state:   s.Livepatch.State,
			cves:    []string{},
		}
		for _, fix := range s.Livepatch.Fixes {
			if fix.Patched && fix.Name != "" {
				report.cves = append(report.cves, strings.ToUpper(fix.Name))
			}
		}
		return report, nil
	}
	return nil, nil
}

// canonicalClient runs the Canonical Livepatch client once per resource. A nil
// report means no client reports on the running kernel: it is not installed,
// not enabled, or has no entry for the running kernel.
func (l *mqlKernelLivepatch) canonicalClient() (*canonicalLivepatchReport, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.clientLoaded {
		return l.client, l.clientErr
	}
	l.clientLoaded = true
	l.client, l.clientErr = l.loadCanonicalClient()
	return l.client, l.clientErr
}

func (l *mqlKernelLivepatch) loadCanonicalClient() (*canonicalLivepatchReport, error) {
	conn, ok := l.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}
	if installed, _ := (&afero.Afero{Fs: conn.FileSystem()}).Exists(canonicalLivepatchClient); !installed {
		return nil, nil
	}

	o, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(canonicalLivepatchClient + " status --format json"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		out := strings.TrimSpace(cmd.GetStdout().Data + " " + cmd.GetStderr().Data)
		// An installed client that was never enabled, or was disabled, reports
		// nothing about the kernel. Its patches may still be loaded.
		if strings.Contains(out, "Machine is not enabled") {
			log.Debug().Msg("kernel.livepatch> the Canonical Livepatch client is not enabled")
			return nil, nil
		}
		return nil, fmt.Errorf("canonical-livepatch status failed with exit code %d: %s", exit.Data, out)
	}

	report, err := parseCanonicalLivepatchStatus([]byte(cmd.GetStdout().Data))
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("could not parse canonical-livepatch status: %w", err))
	}
	return report, nil
}

func (l *mqlKernelLivepatch) version() (string, error) {
	report, err := l.canonicalClient()
	if err != nil {
		return "", err
	}
	// the client reports an empty version when no patch applies
	if report == nil || report.version == "" {
		l.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return report.version, nil
}

func (l *mqlKernelLivepatch) state() (string, error) {
	report, err := l.canonicalClient()
	if err != nil {
		return "", err
	}
	if report == nil {
		l.State.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return report.state, nil
}

func (l *mqlKernelLivepatch) cves() ([]any, error) {
	report, err := l.canonicalClient()
	if err != nil {
		return nil, err
	}
	if report == nil {
		l.Cves.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsAsAnySlice(report.cves), nil
}

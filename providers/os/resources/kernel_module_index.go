// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// normalizeModuleName canonicalizes a kernel module name for lookup. The
// kernel treats '-' and '_' as interchangeable in module names (modprobe
// normalizes between them), and lsmod / /proc/modules always report the
// underscore form, so every key and lookup is keyed on underscores.
func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

// moduleNameFromPath extracts the bare module name from a path entry in
// modules.dep or modules.builtin. Entries look like
// "kernel/net/netfilter/nf_conntrack.ko" (optionally with a .xz / .zst / .gz
// compression suffix). Module names never contain a dot, so the name is the
// basename up to its first dot.
func moduleNameFromPath(p string) string {
	base := path.Base(strings.TrimSpace(p))
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return normalizeModuleName(base)
}

// parseModulesDep parses the contents of a /lib/modules/<version>/modules.dep
// index and returns the set of module names that have a loadable .ko file on
// disk. Each line has the form "kernel/.../foo.ko: dep1.ko dep2.ko ...": the
// module is the path to the left of the colon, and the space-separated paths
// to the right are that module's dependencies — already covered by their own
// lines, so only the left-hand side is recorded. Blank or path-less lines are
// skipped, and names are normalized so a later lookup by either the dash or
// underscore spelling resolves.
func parseModulesDep(content string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		lhs := line
		if i := strings.IndexByte(line, ':'); i >= 0 {
			lhs = line[:i]
		}
		if strings.TrimSpace(lhs) == "" {
			continue
		}
		out[moduleNameFromPath(lhs)] = true
	}
	return out
}

// parseModulesBuiltin parses the contents of a
// /lib/modules/<version>/modules.builtin index and returns the set of module
// names compiled into the kernel. Each non-blank line is a single module path
// (e.g. "kernel/fs/ext4/ext4.ko"); names are normalized the same way as
// parseModulesDep.
func parseModulesBuiltin(content string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out[moduleNameFromPath(line)] = true
	}
	return out
}

// loadModuleIndex reads the running kernel's modules.dep and modules.builtin
// once and records, per module name, whether a loadable .ko file is installed
// on disk and whether the module is compiled into the kernel. Missing index
// files are best-effort: a stripped-down image (or a non-Linux platform with
// no /lib/modules tree) yields empty sets, so every module reports false
// rather than erroring the query.
func (k *mqlKernel) loadModuleIndex() (onDisk map[string]bool, builtIn map[string]bool, err error) {
	k.moduleIndexOnce.Do(func() {
		onDiskSet := map[string]bool{}
		builtInSet := map[string]bool{}

		version, verr := k.runningKernelVersion()
		if verr != nil {
			k.moduleIndexErr = verr
			return
		}
		if version == "" {
			k.moduleOnDisk = onDiskSet
			k.moduleBuiltIn = builtInSet
			return
		}

		base := "/lib/modules/" + version

		dep, ok, derr := k.readKernelIndexFile(base + "/modules.dep")
		if derr != nil {
			k.moduleIndexErr = derr
			return
		}
		if ok {
			onDiskSet = parseModulesDep(dep)
		}

		bi, ok, berr := k.readKernelIndexFile(base + "/modules.builtin")
		if berr != nil {
			k.moduleIndexErr = berr
			return
		}
		if ok {
			builtInSet = parseModulesBuiltin(bi)
		}

		k.moduleOnDisk = onDiskSet
		k.moduleBuiltIn = builtInSet
	})

	return k.moduleOnDisk, k.moduleBuiltIn, k.moduleIndexErr
}

// runningKernelVersion returns the uname -r string for the running kernel,
// which is also the directory name under /lib/modules that holds that
// kernel's module tree. It reads the already-resolved kernel.info dict.
func (k *mqlKernel) runningKernelVersion() (string, error) {
	info := k.GetInfo()
	if info.Error != nil {
		return "", info.Error
	}
	m, ok := info.Data.(map[string]any)
	if !ok {
		return "", nil
	}
	version, _ := m["version"].(string)
	return version, nil
}

// readKernelIndexFile reads a /lib/modules index file via the file resource.
// The bool reports whether the file exists; a missing file is not an error
// (returns "", false, nil) so callers can treat absent indexes as empty.
func (k *mqlKernel) readKernelIndexFile(filePath string) (string, bool, error) {
	f, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(filePath),
	})
	if err != nil {
		return "", false, err
	}
	mf := f.(*mqlFile)

	exists := mf.GetExists()
	if exists.Error != nil {
		return "", false, exists.Error
	}
	if !exists.Data {
		return "", false, nil
	}

	content := mf.GetContent()
	if content.Error != nil {
		if errors.Is(content.Error, resources.NotFoundError{}) {
			return "", false, nil
		}
		return "", false, content.Error
	}
	return content.Data, true, nil
}

// moduleIndex resolves the parent kernel resource and reports, from the
// platform's module configuration, whether this module is present on disk and
// whether it is built into the kernel.
func (m *mqlKernelModule) moduleIndex() (onDisk bool, builtIn bool, err error) {
	obj, err := CreateResource(m.MqlRuntime, "kernel", map[string]*llx.RawData{})
	if err != nil {
		return false, false, err
	}
	return obj.(*mqlKernel).moduleConfig().index(m.Name.Data)
}

// index looks the module up in the running kernel's modules.dep and
// modules.builtin (kernelModuleConfig).
func (l linuxKernelModules) index(name string) (onDisk bool, builtIn bool, err error) {
	onDiskSet, builtInSet, err := l.kernel.loadModuleIndex()
	if err != nil {
		return false, false, err
	}

	name = normalizeModuleName(name)
	return onDiskSet[name], builtInSet[name], nil
}

func (m *mqlKernelModule) onDisk() (bool, error) {
	onDisk, _, err := m.moduleIndex()
	return onDisk, err
}

func (m *mqlKernelModule) builtIn() (bool, error) {
	_, builtIn, err := m.moduleIndex()
	return builtIn, err
}

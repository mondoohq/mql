// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// FreeBSD side of kernel.module (kernelModuleConfig). The file name must not
// end in _freebsd.go, which Go would build only for GOOS=freebsd. Parsing
// lives in kernel/freebsd.go and kernel/freebsd_loader.go; this file reads
// the files and settings over the asset's connection.

import (
	"path"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/kernel"
)

// freebsdKernelModules answers kernel.module from the loader configuration
// (module_blacklist) and kern.module_path. FreeBSD has no install rules, so
// installBypass is always false and disabled equals blacklisted.
type freebsdKernelModules struct {
	kernel *mqlKernel
}

// rule reports whether the loader's module_blacklist names the module.
func (f freebsdKernelModules) rule(name string) (modprobeRule, error) {
	blacklist, err := f.blacklist()
	if err != nil {
		return modprobeRule{}, err
	}
	return modprobeRule{blacklisted: blacklist[normalizeModuleName(name)]}, nil
}

// blacklist reads the loader configuration files once per query, in the
// loader's order, and returns the module names of the resulting
// module_blacklist, normalized.
func (f freebsdKernelModules) blacklist() (map[string]bool, error) {
	k := f.kernel
	k.freebsdBlacklistOnce.Do(func() {
		confDirFiles, err := listConfDFiles(k.MqlRuntime, []string{kernel.FreeBSDLoaderConfDir})
		if err != nil && plugin.StructuredErrors() {
			k.freebsdBlacklistErr = err
			return
		}

		env := map[string]string{}
		for _, file := range kernel.FreeBSDLoaderConfFiles(confDirFiles) {
			content, ok, err := k.readKernelIndexFile(file)
			if err != nil {
				// /boot/loader.conf is readable by root only
				if plugin.StructuredErrors() {
					k.freebsdBlacklistErr = err
					return
				}
				continue
			}
			if ok {
				kernel.ParseFreeBSDLoaderConf(content, env)
			}
		}

		res := map[string]bool{}
		for name := range kernel.ParseFreeBSDModuleBlacklist(env["module_blacklist"]) {
			res[normalizeModuleName(name)] = true
		}
		k.freebsdBlacklist = res
	})
	return k.freebsdBlacklist, k.freebsdBlacklistErr
}

// index reports whether a .ko file for the module is installed in
// kern.module_path, so kldload can load it, and whether the module is
// compiled into the running kernel (`kldstat -v` lists it under the kernel).
func (f freebsdKernelModules) index(name string) (onDisk bool, builtIn bool, err error) {
	k := f.kernel
	if err := k.refreshCache(nil); err != nil {
		return false, false, err
	}
	if mod, ok := k.loadedModule(name); ok {
		builtIn = mod.BuiltIn.State&plugin.StateIsSet != 0 && mod.BuiltIn.Data
	}

	file := kernel.FreeBSDModuleFile(name)
	if file == "" {
		return false, builtIn, nil
	}
	for _, dir := range f.modulePath() {
		raw, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path.Join(dir, file)),
		})
		if err != nil {
			return false, builtIn, err
		}
		exists := raw.(*mqlFile).GetExists()
		if exists.Error != nil {
			return false, builtIn, exists.Error
		}
		if exists.Data {
			return true, builtIn, nil
		}
	}
	return false, builtIn, nil
}

// modulePath returns the directories of kern.module_path, from
// kernel.parameters, or the default path when it cannot be read.
func (f freebsdKernelModules) modulePath() []string {
	value := ""
	if params := f.kernel.GetParameters(); params.Error == nil {
		value, _ = params.Data["kern.module_path"].(string)
	}
	return kernel.ParseFreeBSDModulePath(value)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// FreeBSD kernel modules: `kldstat -v` lists the loaded modules, and
// kern.module_path the directories kldload loads .ko files from. The loader
// configuration is read in freebsd_loader.go.

var (
	// ` 2    1 0xffffffff82147000    37960 if_ena.ko (/boot/kernel/if_ena.ko)`
	kldstatVerboseFile = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)(?:\s+\((.*)\))?\s*$`)
	// `\t\t334 msdosfs` below `Contains modules:`
	kldstatVerboseModule = regexp.MustCompile(`^\s+(\d+)\s+(\S+)\s*$`)
)

// kldstatKernelFile is the name kldstat gives the kernel itself.
const kldstatKernelFile = "kernel"

// ParseKldstatVerbose parses `kldstat -v` on FreeBSD. It lists every loaded
// file and, below each, the modules it contains:
//
//	Id Refs Address                Size Name
//	 1   15 0xffffffff80200000  1f46790 kernel (/boot/kernel/kernel)
//		Contains modules:
//			 Id Name
//			334 msdosfs
//	 4    1 0xffffffff829ed000    28450 ipfw.ko (/boot/kernel/ipfw.ko)
//		Contains modules:
//			 Id Name
//			503 ipfw
//
// Every module becomes one entry, named as `kldstat -m` and kldload know it,
// with the file it is in. Modules of the kernel file are compiled into the
// kernel; they have no size of their own. A file that contains no module
// adds no entry. Output without any module list (an old kldstat that ignores
// -v) is read like plain kldstat, one entry per file.
func ParseKldstatVerbose(r io.Reader) []*KernelModule {
	res := []*KernelModule{}
	files := []*KernelModule{}

	var file *KernelModule
	inModules := false
	sawModules := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if m := kldstatVerboseFile.FindStringSubmatch(line); m != nil {
			file = &KernelModule{
				Name:   m[5],
				Size:   m[4],
				UsedBy: m[2],
				File:   m[5],
			}
			files = append(files, file)
			inModules = false
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "Contains modules:" {
			inModules = file != nil
			sawModules = true
			continue
		}
		if !inModules || trimmed == "Id Name" {
			continue
		}
		if m := kldstatVerboseModule.FindStringSubmatch(line); m != nil {
			mod := &KernelModule{
				Name:    m[2],
				File:    file.Name,
				BuiltIn: file.Name == kldstatKernelFile,
			}
			if !mod.BuiltIn {
				mod.Size = file.Size
				mod.UsedBy = file.UsedBy
			}
			res = append(res, mod)
		}
	}

	if !sawModules {
		return files
	}
	return res
}

// FreeBSDDefaultModulePath is kern.module_path on a stock install.
const FreeBSDDefaultModulePath = "/boot/kernel;/boot/modules"

// ParseFreeBSDModulePath splits a kern.module_path value into its
// directories. An empty value is the default path.
func ParseFreeBSDModulePath(value string) []string {
	if strings.TrimSpace(value) == "" {
		value = FreeBSDDefaultModulePath
	}
	var dirs []string
	for _, dir := range strings.Split(value, ";") {
		if dir = strings.TrimSpace(dir); dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// FreeBSDModuleFile returns the .ko file name kldload looks for to load a
// module: the module name with .ko appended, unless it has it already.
// A name with a slash (a driver attachment such as `pci/ena`) has no file of
// its own and returns "".
func FreeBSDModuleFile(name string) string {
	if name == "" || strings.Contains(name, "/") {
		return ""
	}
	if strings.HasSuffix(name, ".ko") {
		return name
	}
	return name + ".ko"
}

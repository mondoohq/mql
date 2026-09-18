// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/afero"
)

// reShellVar matches an unexpanded shell variable reference, such as
// ${GRUB2_PASSWORD} or $GRUB2_PASSWORD, which an entry may carry in place of a
// value the boot loader expands.
var reShellVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// Entry roles. Only normal and recovery entries boot a kernel that a control
// over boot parameters applies to.
const (
	BootEntryNormal   = "normal"
	BootEntryRecovery = "recovery"
	BootEntryMemtest  = "memtest"
	BootEntrySubmenu  = "submenu"
	BootEntryOther    = "other"
)

// BootEntry represents a parsed GRUB boot entry, from a menu entry in grub.cfg
// or from a Boot Loader Specification file.
type BootEntry struct {
	Title     string
	Kind      string
	Bootable  bool
	Kernel    string
	Cmdline   string
	Initrd    string
	IsSubmenu bool

	// Parameters holds the key-value tokens of the kernel command line, last
	// occurrence winning as the kernel reads them. Flags holds the bare ones.
	Parameters map[string]string
	Flags      []string

	// Source is the file the entry was read from.
	Source string

	// Classes carries the --class values of a menu entry, or grub_class of a
	// Boot Loader Specification entry, which is how a memory test entry is
	// labelled. Version is the BLS version key, which names a rescue entry.
	Classes []string
	Version string

	// UnifiedKernelImage records that the entry is one signed executable
	// holding the kernel, the initrd and the command line, discovered as a
	// file rather than declared by an entry file. Signed reports whether that
	// executable carries a signature.
	UnifiedKernelImage bool
	Signed             bool
}

// ParseBLSEntry parses one Boot Loader Specification entry file, whose lines
// are a key and a value separated by whitespace.
func ParseBLSEntry(r io.Reader) (BootEntry, error) {
	entry := BootEntry{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		key := line
		value := ""
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			key = line[:idx]
			value = strings.TrimSpace(line[idx+1:])
		}

		switch key {
		case "title":
			entry.Title = value
		case "version":
			entry.Version = value
		case "linux":
			entry.Kernel = value
		case "initrd":
			entry.Initrd = value
		case "options":
			// The specification allows several options lines, which together
			// make up one command line.
			if entry.Cmdline == "" {
				entry.Cmdline = value
			} else {
				entry.Cmdline += " " + value
			}
		case "grub_class":
			entry.Classes = append(entry.Classes, value)
		}
	}
	return entry, scanner.Err()
}

// readBLSEntries reads every entry file in dir, resolving the bootloader
// variables the entries reference.
func readBLSEntries(fs afero.Fs, dir string, vars map[string]string) ([]BootEntry, error) {
	files, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, nil
	}

	names := []string{}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".conf") {
			continue
		}
		names = append(names, f.Name())
	}
	sort.Strings(names)

	entries := make([]BootEntry, 0, len(names))
	for _, name := range names {
		p := path.Join(dir, name)
		f, err := fs.Open(p)
		if err != nil {
			continue
		}
		entry, err := ParseBLSEntry(f)
		f.Close()
		if err != nil {
			continue
		}
		entry.Source = p
		entries = append(entries, entry)
	}

	finalizeEntries(entries, "", vars)
	return entries, nil
}

// expandVars resolves the variables the bootloader would expand. A variable
// with no value is left as written, which is what grubby reports for the tuned
// variables the Red Hat entries carry.
func expandVars(s string, vars map[string]string) string {
	if !strings.ContainsRune(s, '$') {
		return s
	}
	return reShellVar.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.Trim(match, "${}")
		if value, ok := vars[name]; ok {
			return value
		}
		return match
	})
}

// ParseCmdline splits a kernel command line into its key-value parameters and
// its bare flags. A parameter repeated on one command line takes its last
// value, as the kernel does. A token that is still an unresolved variable is
// not a value and is skipped.
func ParseCmdline(cmdline string) (map[string]string, []string) {
	params := map[string]string{}
	flags := []string{}

	for _, token := range strings.Fields(cmdline) {
		if strings.HasPrefix(token, "$") {
			continue
		}
		if key, value, found := strings.Cut(token, "="); found {
			params[key] = value
			continue
		}
		flags = append(flags, token)
	}
	return params, flags
}

// finalizeEntries fills in what every entry needs regardless of the file it
// came from: the kernel it boots, its parsed command line, and its role.
func finalizeEntries(entries []BootEntry, source string, vars map[string]string) {
	for i := range entries {
		entry := &entries[i]
		if entry.Source == "" {
			entry.Source = source
		}

		entry.Cmdline = expandVars(entry.Cmdline, vars)

		args := entry.Cmdline
		if entry.Kernel == "" && args != "" {
			// A grub.cfg entry writes the kernel path as the first argument of
			// its linux line; a Boot Loader Specification entry names it
			// separately and its options are arguments only.
			kernel, rest, _ := strings.Cut(args, " ")
			entry.Kernel = kernel
			args = rest
		}

		entry.Parameters, entry.Flags = ParseCmdline(args)
		entry.Kind = classifyEntry(entry)
		entry.Bootable = entryBootable(entry.Kind)
	}
}

// classifyEntry names the role of an entry from the markers the distributions
// actually use: Debian and Ubuntu write a recovery flag, SUSE writes single,
// and the Red Hat family names a rescue entry in its version.
func classifyEntry(entry *BootEntry) string {
	if entry.IsSubmenu {
		return BootEntrySubmenu
	}
	if entry.Kernel == "" && !entry.UnifiedKernelImage {
		// An entry that boots no kernel, such as one opening the firmware
		// settings or chainloading another operating system, carries no boot
		// parameters to audit. A unified kernel image is itself the kernel, so
		// it boots one even where it records no release.
		return BootEntryOther
	}

	if hasClass(entry.Classes, "memtest") ||
		strings.Contains(strings.ToLower(path.Base(entry.Kernel)), "memtest") {
		return BootEntryMemtest
	}

	for _, flag := range entry.Flags {
		if flag == "recovery" || flag == "single" {
			return BootEntryRecovery
		}
	}
	lowerTitle := strings.ToLower(entry.Title)
	if strings.Contains(lowerTitle, "recovery mode") ||
		strings.Contains(lowerTitle, "rescue") ||
		strings.Contains(strings.ToLower(entry.Version), "rescue") {
		return BootEntryRecovery
	}

	return BootEntryNormal
}

// entryBootable reports whether an entry of this kind boots an operating
// system, which is what decides whether its kernel command line is subject to
// a control over boot parameters. A submenu carries no command line at all, a
// memory test boots a diagnostic rather than the system, and an entry that
// boots no kernel has nothing to audit.
func entryBootable(kind string) bool {
	return kind == BootEntryNormal || kind == BootEntryRecovery
}

func hasClass(classes []string, want string) bool {
	for _, c := range classes {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

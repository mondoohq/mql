// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package nfs parses NFS server exports and NFS client mount state
// for Linux, FreeBSD, macOS, and AIX. Callers feed the contents of
// /etc/exports together with a platform name to ParseExports and
// receive one [ExportEntry] per (path, client) pair, with derived
// audit flags filled in by the platform-specific parser.
package nfs

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Platform names accepted by [ParseExports].
const (
	PlatformLinux   = "linux"
	PlatformFreeBSD = "freebsd"
	PlatformDarwin  = "darwin"
	PlatformAIX     = "aix"
)

// ExportEntry is one (path, client) row in the local NFS export table.
// ReadOnly and NoRootSquash are derived from Options by the
// platform-specific parser so callers don't need to re-evaluate
// platform conventions.
type ExportEntry struct {
	Path         string
	Client       string
	Options      []string
	ReadOnly     bool
	NoRootSquash bool
}

// ParseExports reads /etc/exports content and returns one entry per
// (path, client) pair using the syntax of the given platform.
func ParseExports(r io.Reader, platform string) ([]ExportEntry, error) {
	switch platform {
	case PlatformLinux:
		return parseLinuxExports(r)
	case PlatformFreeBSD, PlatformDarwin:
		return parseBSDExports(r)
	case PlatformAIX:
		return parseAIXExports(r)
	}
	return nil, fmt.Errorf("nfs: unsupported platform %q", platform)
}

func scanExportLines(r io.Reader, visit func(line string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var pending strings.Builder
	flush := func() error {
		joined := pending.String()
		pending.Reset()
		line := strings.TrimSpace(stripComment(joined))
		if line == "" {
			return nil
		}
		return visit(line)
	}
	for scanner.Scan() {
		raw := scanner.Text()
		// A trailing `\` continues the logical line onto the next
		// physical line, per Linux exports(5). Drop the backslash
		// and join with a single space so token boundaries survive.
		if strings.HasSuffix(raw, `\`) {
			pending.WriteString(raw[:len(raw)-1])
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(raw)
		if err := flush(); err != nil {
			return err
		}
	}
	if pending.Len() > 0 {
		if err := flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// stripComment removes a trailing `#...` comment from line, respecting
// backslash escapes so that `\#` stays in the output.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && i+1 < len(line) {
			i++
			continue
		}
		if line[i] == '#' {
			return line[:i]
		}
	}
	return line
}

func containsString(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}

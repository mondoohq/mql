// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"path"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

const (
	coredumpConfigName = "coredump.conf"
	coredumpSection    = "Coredump"
	corePatternPath    = "/proc/sys/kernel/core_pattern"
	// systemd's compiled-in Storage= default, unchanged since systemd 215
	coredumpDefaultStorage = "external"
)

// coredumpBinaryPaths are where distributions install the systemd-coredump
// helper the kernel pipes core dumps to.
var coredumpBinaryPaths = []string{
	"/usr/lib/systemd/systemd-coredump",
	"/lib/systemd/systemd-coredump",
}

type mqlSystemdCoredumpInternal struct {
	lock     sync.Mutex
	fetched  bool
	fetchErr error
	state    coredumpState
}

type coredumpState struct {
	filePaths []string
	// corePatternRead is false when the core pattern could not be observed
	corePatternRead bool
	active          bool
	settings        coredumpSettings
}

// coredumpSettings are the effective [Coredump] settings. A nil pointer means
// no configuration file sets a valid value.
type coredumpSettings struct {
	params          map[string]string
	storage         *string
	processSizeMax  *int64
	externalSizeMax *int64
}

func (c *mqlSystemdCoredump) id() (string, error) {
	return "systemd.coredump", nil
}

func (c *mqlSystemdCoredump) fetch() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.fetched {
		return c.fetchErr
	}
	c.state, c.fetchErr = c.readState()
	c.fetched = true
	return c.fetchErr
}

func (c *mqlSystemdCoredump) readState() (coredumpState, error) {
	state := coredumpState{settings: coredumpSettings{params: map[string]string{}}}

	pattern, ok, err := readKernelHardeningFile(c.MqlRuntime, corePatternPath)
	if err != nil {
		return state, err
	}
	state.corePatternRead = ok
	state.active = ok && corePatternPipesToSystemdCoredump(pattern)

	conn, ok := c.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return state, nil
	}
	fs := conn.FileSystem()

	mainPath, err := findSystemdMainConfig(fs, coredumpConfigName)
	if err != nil {
		return state, err
	}
	if mainPath != "" {
		state.filePaths = append(state.filePaths, mainPath)
	}
	dropins, err := findSystemdConfigDropins(fs, coredumpConfigName)
	if err != nil {
		return state, err
	}
	state.filePaths = append(state.filePaths, dropins...)

	contents := make([]string, 0, len(state.filePaths))
	for _, p := range state.filePaths {
		f, err := newFile(c.MqlRuntime, p)
		if err != nil {
			return state, err
		}
		content, err := fileContentOrEmpty(f)
		if err != nil {
			return state, err
		}
		contents = append(contents, content)
	}

	assignments, err := coredumpAssignments(state.filePaths, contents)
	if err != nil {
		return state, err
	}

	installed := state.active
	if !installed {
		installed, err = anyFileExists(fs, coredumpBinaryPaths)
		if err != nil {
			return state, err
		}
	}
	state.settings = effectiveCoredumpSettings(assignments, installed)
	return state, nil
}

func anyFileExists(fs afero.Fs, paths []string) (bool, error) {
	for _, p := range paths {
		exists, err := afero.Exists(fs, p)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// coredumpAssignments parses each configuration file and returns the
// [Coredump] assignments in the order systemd applies them.
func coredumpAssignments(paths []string, contents []string) ([]parsers.UnitParam, error) {
	var assignments []parsers.UnitParam
	for i, content := range contents {
		unit, err := parsers.ParseUnit(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", paths[i], err)
		}
		for _, section := range unit.Sections {
			if section.Name != coredumpSection {
				continue
			}
			assignments = append(assignments, section.Params...)
		}
	}
	return assignments, nil
}

// effectiveCoredumpSettings applies the assignments the way systemd-coredump
// does: later assignments override earlier ones, and an assignment systemd
// cannot parse is ignored, leaving the previous value in place. Storage falls
// back to systemd's default only when systemd-coredump is installed, so a host
// without it does not look configured. The size defaults depend on the systemd
// version and architecture, which are not known here, so unset sizes stay nil.
func effectiveCoredumpSettings(assignments []parsers.UnitParam, installed bool) coredumpSettings {
	settings := coredumpSettings{params: map[string]string{}}
	for _, a := range assignments {
		settings.params[a.Name] = a.Value
		switch a.Name {
		case "Storage":
			switch a.Value {
			case "none", "external", "journal":
				v := a.Value
				settings.storage = &v
			}
		case "ProcessSizeMax":
			if v, err := parseSystemdSize(a.Value); err == nil {
				settings.processSizeMax = &v
			}
		case "ExternalSizeMax":
			if a.Value == "infinity" {
				v := int64(-1)
				settings.externalSizeMax = &v
			} else if v, err := parseSystemdSize(a.Value); err == nil {
				settings.externalSizeMax = &v
			}
		}
	}
	if settings.storage == nil && installed {
		v := coredumpDefaultStorage
		settings.storage = &v
	}
	return settings
}

// corePatternPipesToSystemdCoredump reports whether a kernel core_pattern
// hands core dumps to systemd-coredump, e.g.
// "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h".
func corePatternPipesToSystemdCoredump(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	rest, ok := strings.CutPrefix(pattern, "|")
	if !ok {
		return false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return false
	}
	return path.Base(fields[0]) == "systemd-coredump"
}

var errInvalidSystemdSize = errors.New("invalid size")

// systemdSizeSuffixes is the base-1024 suffix table of systemd's parse_size(),
// largest first. The empty suffix means bytes.
var systemdSizeSuffixes = []struct {
	suffix string
	factor uint64
}{
	{"E", 1 << 60},
	{"P", 1 << 50},
	{"T", 1 << 40},
	{"G", 1 << 30},
	{"M", 1 << 20},
	{"K", 1 << 10},
	{"B", 1},
	{"", 1},
}

// parseSystemdSize parses a size the way systemd's parse_size() does with base
// 1024: one or more components, each a decimal number with an optional
// fraction and a case-sensitive suffix, with suffixes strictly decreasing
// ("1G 512M" is 1.5G). Negative numbers and unknown suffixes are errors. A
// size that does not fit in an int64 (8E or more) is returned as -1.
func parseSystemdSize(s string) (int64, error) {
	var total uint64
	start := 0
	p := s
	for {
		p = strings.TrimLeft(p, " \t\n\r")
		if strings.HasPrefix(p, "-") {
			return 0, errInvalidSystemdSize
		}
		p = strings.TrimPrefix(p, "+")
		digits := leadingDigits(p)
		if digits == "" {
			return 0, errInvalidSystemdSize
		}
		whole, err := parseUint64Digits(digits)
		if err != nil {
			return 0, err
		}
		e := p[len(digits):]

		frac := 0.0
		if strings.HasPrefix(e, ".") {
			e = e[1:]
			if fracDigits := leadingDigits(e); fracDigits != "" {
				v, err := parseUint64Digits(fracDigits)
				if err != nil {
					return 0, err
				}
				frac = float64(v) / math.Pow10(len(fracDigits))
				e = e[len(fracDigits):]
			}
		}
		e = strings.TrimLeft(e, " \t\n\r")

		i := start
		for ; i < len(systemdSizeSuffixes); i++ {
			if strings.HasPrefix(e, systemdSizeSuffixes[i].suffix) {
				break
			}
		}
		if i >= len(systemdSizeSuffixes) {
			return 0, errInvalidSystemdSize
		}
		factor := systemdSizeSuffixes[i].factor

		extra := uint64(0)
		if frac > 0 {
			extra = 1
		}
		if whole == math.MaxUint64 || whole+extra > math.MaxUint64/factor {
			return 0, errInvalidSystemdSize
		}
		hi, component := bits.Mul64(whole, factor)
		if hi != 0 {
			return 0, errInvalidSystemdSize
		}
		component += uint64(frac * float64(factor))
		sum, carry := bits.Add64(total, component, 0)
		if carry != 0 {
			return 0, errInvalidSystemdSize
		}
		total = sum

		p = e[len(systemdSizeSuffixes[i].suffix):]
		start = i + 1
		if p == "" {
			break
		}
	}

	if total > math.MaxInt64 {
		return -1, nil
	}
	return int64(total), nil
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func parseUint64Digits(digits string) (uint64, error) {
	var v uint64
	for i := 0; i < len(digits); i++ {
		hi, lo := bits.Mul64(v, 10)
		if hi != 0 {
			return 0, errInvalidSystemdSize
		}
		lo, carry := bits.Add64(lo, uint64(digits[i]-'0'), 0)
		if carry != 0 {
			return 0, errInvalidSystemdSize
		}
		v = lo
	}
	return v, nil
}

func (c *mqlSystemdCoredump) active() (bool, error) {
	if err := c.fetch(); err != nil {
		return false, err
	}
	if !c.state.corePatternRead {
		c.Active.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return c.state.active, nil
}

func (c *mqlSystemdCoredump) files() ([]any, error) {
	if err := c.fetch(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(c.state.filePaths))
	for _, p := range c.state.filePaths {
		f, err := newFile(c.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (c *mqlSystemdCoredump) params() (map[string]any, error) {
	if err := c.fetch(); err != nil {
		return nil, err
	}
	res := make(map[string]any, len(c.state.settings.params))
	for k, v := range c.state.settings.params {
		res[k] = v
	}
	return res, nil
}

func (c *mqlSystemdCoredump) storage() (string, error) {
	if err := c.fetch(); err != nil {
		return "", err
	}
	if c.state.settings.storage == nil {
		c.Storage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *c.state.settings.storage, nil
}

func (c *mqlSystemdCoredump) processSizeMax() (int64, error) {
	if err := c.fetch(); err != nil {
		return 0, err
	}
	if c.state.settings.processSizeMax == nil {
		c.ProcessSizeMax.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *c.state.settings.processSizeMax, nil
}

func (c *mqlSystemdCoredump) externalSizeMax() (int64, error) {
	if err := c.fetch(); err != nil {
		return 0, err
	}
	if c.state.settings.externalSizeMax == nil {
		c.ExternalSizeMax.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *c.state.settings.externalSizeMax, nil
}

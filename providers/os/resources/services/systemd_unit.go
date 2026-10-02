// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-systemd/unit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SystemdUnit carries the execution and confinement settings of a systemd unit.
type SystemdUnit struct {
	Name          string
	Description   string
	Installed     bool
	FragmentPath  string
	LoadState     string
	ActiveState   string
	SubState      string
	UnitFileState string
	Type          string
	ExecStart     string

	User        string
	Group       string
	DynamicUser bool
	UMask       string

	NoNewPrivileges         bool
	ProtectSystem           string
	ProtectHome             string
	PrivateTmp              bool
	PrivateDevices          bool
	PrivateNetwork          bool
	PrivateUsers            bool
	ProtectKernelTunables   bool
	ProtectKernelModules    bool
	ProtectKernelLogs       bool
	ProtectControlGroups    string
	ProtectClock            bool
	ProtectHostname         bool
	ProtectProc             string
	ProcSubset              string
	RestrictSUIDSGID        bool
	RestrictRealtime        bool
	RestrictNamespaces      string
	RestrictAddressFamilies string
	LockPersonality         bool
	MemoryDenyWriteExecute  bool
	RemoveIPC               bool
	KeyringMode             string

	CapabilityBoundingSet   []string
	AmbientCapabilities     []string
	SystemCallFilter        []string
	SystemCallArchitectures string
	ReadWritePaths          []string
	ReadOnlyPaths           []string
	InaccessiblePaths       []string

	// Unsupported names the properties the running systemd does not have
	// (ProtectClock on systemd 232, for example). Their values above are
	// zero and say nothing about the unit.
	Unsupported map[string]bool
}

// Supports reports whether the running systemd has the property, so its value
// on the unit means something.
func (u *SystemdUnit) Supports(property string) bool {
	return !u.Unsupported[property]
}

// systemdUnsupportedKey is a record key no systemctl output or unit file can
// produce. It carries the space-separated names of the properties the running
// systemd does not have, from the record into the unit.
const systemdUnsupportedKey = "\x00unsupported"

// systemdPropertySince is the systemd release that introduced each property
// read from a unit file that some release still in use does not know. A unit
// file can set them on any release; an older systemd ignores the line, so the
// setting does not apply.
var systemdPropertySince = map[string]int{
	"AmbientCapabilities":    229,
	"MemoryDenyWriteExecute": 231,
	"RestrictRealtime":       231,
	"ReadWritePaths":         231,
	"ReadOnlyPaths":          231,
	"InaccessiblePaths":      231,
	"DynamicUser":            232,
	"PrivateUsers":           232,
	"ProtectKernelTunables":  232,
	"ProtectKernelModules":   232,
	"ProtectControlGroups":   232,
	"RemoveIPC":              232,
	"RestrictNamespaces":     233,
	"LockPersonality":        235,
	"KeyringMode":            235,
	"ProtectHostname":        242,
	"RestrictSUIDSGID":       242,
	"ProtectKernelLogs":      244,
	"ProtectClock":           245,
	"ProtectProc":            247,
	"ProcSubset":             247,
}

// markUnsupportedShowProperties records which requested properties the
// running systemd does not have, from what systemctl show left out.
//
// systemctl prints every property of a unit's execution settings it knows.
// An older release leaves out the ones it does not know: systemd 241 (Debian
// 10) exits 0 without ProtectClock, and the --all retry on systemd 232 (Debian
// 9) and 219 (RHEL 7) prints neither. Reading those as "no" claims a setting
// was checked when the release cannot apply it. NoNewPrivileges, which every
// release in use has, tells a unit with execution settings from one without
// (a target), whose missing properties are not a gap in the release.
//
// systemd before 242 also prints RestrictAddressFamilies as "[unprintable]",
// which is no value at all.
func markUnsupportedShowProperties(record map[string]string) {
	var unsupported []string
	if _, hasExec := record["NoNewPrivileges"]; hasExec {
		for _, property := range strings.Split(systemdUnitShowProperties, ",") {
			if _, ok := record[property]; !ok {
				unsupported = append(unsupported, property)
			}
		}
	}
	for property, value := range record {
		if value == "[unprintable]" {
			unsupported = append(unsupported, property)
		}
	}
	if len(unsupported) > 0 {
		record[systemdUnsupportedKey] = strings.Join(unsupported, " ")
	}
}

// markUnsupportedFileProperties records which properties a unit file can set
// that systemd release version does not know. A version of 0 means the
// release is unknown (an image scan), and the file's settings are taken as
// written.
func markUnsupportedFileProperties(props map[string]string, version int) {
	if version <= 0 {
		return
	}
	var unsupported []string
	for property, since := range systemdPropertySince {
		if since > version {
			unsupported = append(unsupported, property)
		}
	}
	if len(unsupported) > 0 {
		sort.Strings(unsupported)
		props[systemdUnsupportedKey] = strings.Join(unsupported, " ")
	}
}

// parseSystemctlVersion reads the release number from `systemctl --version`,
// whose first line is "systemd 232" or "systemd 252 (252.39-1~deb12u2)". It
// returns 0 when the output is not that.
func parseSystemctlVersion(output string) int {
	line, _, _ := strings.Cut(output, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}
	version, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return version
}

// systemdUnitShowProperties are the properties fetched for a unit. Naming them
// explicitly keeps the output small enough to request every unit in one call.
const systemdUnitShowProperties = "Id,Description,FragmentPath,LoadState,ActiveState,SubState,UnitFileState,Type," +
	"ExecStart,User,Group,DynamicUser,UMask,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices," +
	"PrivateNetwork,PrivateUsers,ProtectKernelTunables,ProtectKernelModules,ProtectKernelLogs,ProtectControlGroups," +
	"ProtectClock,ProtectHostname,ProtectProc,ProcSubset,RestrictSUIDSGID,RestrictRealtime,RestrictNamespaces," +
	"RestrictAddressFamilies,LockPersonality,MemoryDenyWriteExecute,RemoveIPC,KeyringMode,CapabilityBoundingSet," +
	"AmbientCapabilities,SystemCallFilter,SystemCallArchitectures,ReadWritePaths,ReadOnlyPaths,InaccessiblePaths"

// systemdUnitShowChunk bounds how many units go into one systemctl invocation,
// so a host with a very large unit set cannot build a command line past what the
// shell accepts.
const systemdUnitShowChunk = 60

// SystemdUnitLister can list and look up systemd units with their confinement
// settings.
type SystemdUnitLister interface {
	List() ([]*SystemdUnit, error)
	Get(name string) (*SystemdUnit, error)
}

// ResolveSystemdUnitManager returns a command-based manager when the connection
// can run commands, otherwise one reading unit files from the filesystem.
func ResolveSystemdUnitManager(conn shared.Connection) SystemdUnitLister {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &SystemdFSUnitManager{Fs: conn.FileSystem()}
	}
	return &SystemdUnitManager{conn: conn}
}

// SystemdUnitManager reads unit settings through systemctl, which reports the
// values in effect after drop-ins have been merged.
type SystemdUnitManager struct {
	conn shared.Connection

	versionOnce sync.Once
	version     int
}

// systemdVersion is the release of the systemd on the host, or 0 when
// systemctl --version does not say.
func (m *SystemdUnitManager) systemdVersion() int {
	m.versionOnce.Do(func() {
		cmd, err := m.conn.RunCommand("systemctl --version")
		if err != nil || cmd.ExitStatus != 0 {
			return
		}
		out, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			return
		}
		m.version = parseSystemctlVersion(string(out))
	})
	return m.version
}

// fsFallback reads the unit files off disk. systemctl needs a running systemd
// to answer, so it is not available in a container, a chroot, a rescue boot, or
// on a host that keeps unit files around while another init runs. It reports
// that by exiting non-zero with nothing on stdout, which parses into an empty
// unit list -- indistinguishable from a host that genuinely runs no services,
// and enough to make an assertion over systemd.units pass without ever having
// read a unit.
//
// The host's systemd may be older than the settings in a unit file, and
// ignores the ones it does not know, so the fallback is told the release.
func (m *SystemdUnitManager) fsFallback() *SystemdFSUnitManager {
	return &SystemdFSUnitManager{Fs: m.conn.FileSystem(), Version: m.systemdVersion()}
}

func (m *SystemdUnitManager) List() ([]*SystemdUnit, error) {
	units, err := m.listViaSystemctl()
	if err == nil {
		return units, nil
	}

	log.Debug().Err(err).
		Msg("mql[systemd]> could not list units through systemctl, reading unit files instead")
	return m.fsFallback().List()
}

func (m *SystemdUnitManager) listViaSystemctl() ([]*SystemdUnit, error) {
	cmd, err := m.conn.RunCommand("systemctl list-unit-files --type service --all --no-legend")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, systemctlError("systemctl list-unit-files", cmd)
	}

	names, err := parseSystemdUnitFileNames(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return []*SystemdUnit{}, nil
	}

	// systemctl refuses to show an uninstantiated template ("Unit name
	// autovt@.service is neither a valid invocation ID nor unit name") and
	// exits non-zero for the whole batch when one is in it. Almost every host
	// has at least one template, so leaving them in meant every batch failed
	// and the whole resource fell back to reading unit files -- which loses the
	// units a generator produced into /run, since the filesystem search path
	// deliberately does not look there. On openSUSE Leap 16 that was 10 real
	// units missing. Ask systemctl only about the concrete names and read the
	// templates off disk, where they always have a unit file.
	concrete, templates := splitSystemdTemplateUnits(names)

	res := make([]*SystemdUnit, 0, len(names))
	// list-unit-files names an alias as well as the unit it points at, and
	// `systemctl show` answers for both with the same Id. Keying on the Id
	// collapses them back into the one unit they are: without this, a NixOS
	// 25.11 host reported 117 units for 108 distinct names, double-counting
	// every aliased unit in a length or a where().
	//
	// It also keeps the resource cache honest. The cache key is the unit name,
	// so the second CreateResource for a name returns the first instance --
	// putting the same resource in the list twice rather than two resources.
	seen := make(map[string]struct{}, len(concrete))
	for start := 0; start < len(concrete); start += systemdUnitShowChunk {
		end := min(start+systemdUnitShowChunk, len(concrete))

		chunk := concrete[start:end]
		records, exitErr, err := m.showUnits(chunk)
		if err != nil {
			return nil, err
		}
		if exitErr != nil {
			return nil, exitErr
		}

		for _, record := range records {
			u := systemdUnitFromProperties(record)
			if u == nil {
				continue
			}
			if _, dup := seen[u.Name]; dup {
				continue
			}
			seen[u.Name] = struct{}{}
			res = append(res, u)
		}
	}

	// systemctl named the units, so it knowing nothing about any of them is a
	// failure to report rather than a host with nothing on it
	if len(concrete) > 0 && len(res) == 0 {
		return nil, fmt.Errorf("systemctl show returned no properties for any of the %d service units", len(concrete))
	}

	fs := m.fsFallback()
	for _, name := range templates {
		u, err := fs.Get(name)
		if err != nil {
			// the template was named by list-unit-files, so it has a unit file
			// somewhere; if we cannot read it, say so rather than dropping it
			log.Debug().Err(err).Str("unit", name).
				Msg("mql[systemd]> could not read template unit file")
			continue
		}
		if _, dup := seen[u.Name]; dup {
			continue
		}
		seen[u.Name] = struct{}{}
		res = append(res, u)
	}

	return res, nil
}

// splitSystemdTemplateUnits separates uninstantiated template units
// (`name@.service`) from concrete ones.
func splitSystemdTemplateUnits(names []string) (concrete, templates []string) {
	for _, name := range names {
		if isSystemdTemplateUnit(name) {
			templates = append(templates, name)
			continue
		}
		concrete = append(concrete, name)
	}
	return concrete, templates
}

// isSystemdTemplateUnit reports whether name is a template rather than an
// instance: the instance part, between the "@" and the type suffix, is empty.
func isSystemdTemplateUnit(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	if dot < 1 {
		return false
	}
	return name[dot-1] == '@'
}

// systemctlError turns a non-zero systemctl exit into an error carrying the
// reason systemctl printed, which is the part that says what went wrong
// ("System has not been booted with systemd as init system (PID 1)").
func systemctlError(what string, cmd *shared.Command) error {
	reason := ""
	if cmd.Stderr != nil {
		if out, err := io.ReadAll(cmd.Stderr); err == nil {
			reason = strings.TrimSpace(string(out))
		}
	}
	if reason == "" {
		return fmt.Errorf("%s exited %d", what, cmd.ExitStatus)
	}
	return fmt.Errorf("%s exited %d: %s", what, cmd.ExitStatus, reason)
}

// showUnits runs `systemctl show` for units and parses its records. A
// non-zero exit is returned as exitErr, separately from a failure to run the
// command at all, so the caller can decide whether to read unit files instead.
//
// systemctl exits non-zero when it is asked for a property its release does
// not know. systemd 219 (RHEL 7) knows none of ProtectKernelLogs, ProtectClock,
// DynamicUser and the other settings added since, prints the first unit's
// known properties, and stops there without a word on stderr. Taking that as
// "systemctl cannot answer" dropped every unit to the unit-file fallback, which
// has no runtime state, so a running, enabled chronyd read as inactive. When
// the output proves systemctl is answering, ask again for every property the
// release has (--all, no property list) and take the ones we know from that.
func (m *SystemdUnitManager) showUnits(units []string) (records []map[string]string, exitErr error, err error) {
	cmd, err := m.conn.RunCommand(buildSystemdUnitShowCommand(units))
	if err != nil {
		return nil, nil, err
	}
	if cmd.ExitStatus == 0 {
		records, err = parseSystemdShowRecords(cmd.Stdout)
		for _, record := range records {
			markUnsupportedShowProperties(record)
		}
		return records, nil, err
	}
	exitErr = systemctlError("systemctl show", cmd)

	partial, err := parseSystemdShowRecords(cmd.Stdout)
	if err != nil || !hasSystemdUnitRecord(partial) {
		return nil, exitErr, nil
	}

	log.Debug().Err(exitErr).Strs("units", units).
		Msg("mql[systemd]> systemctl does not know every requested property, reading all properties instead")
	cmd, err = m.conn.RunCommand(buildSystemdUnitShowAllCommand(units))
	if err != nil {
		return nil, nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, systemctlError("systemctl show --all", cmd), nil
	}
	records, err = parseSystemdShowRecords(cmd.Stdout)
	for _, record := range records {
		markUnsupportedShowProperties(record)
	}
	return records, nil, err
}

// hasSystemdUnitRecord reports whether systemctl printed at least one unit,
// which a systemctl that cannot reach systemd never does.
func hasSystemdUnitRecord(records []map[string]string) bool {
	for _, record := range records {
		if record["Id"] != "" {
			return true
		}
	}
	return false
}

func (m *SystemdUnitManager) Get(name string) (*SystemdUnit, error) {
	records, exitErr, err := m.showUnits([]string{name})
	if err != nil {
		return nil, err
	}
	if exitErr != nil {
		// same reason as List: a systemctl that cannot answer must not read as
		// "there is no such unit"
		log.Debug().Err(exitErr).Str("unit", name).
			Msg("mql[systemd]> could not read unit through systemctl, reading the unit file instead")
		return m.fsFallback().Get(name)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
	}

	u := systemdUnitFromProperties(records[0])
	if u == nil {
		return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
	}

	// systemctl answers for a name it does not know with a synthetic record, so
	// the load state is what says whether the unit exists
	if u.LoadState == "not-found" || u.LoadState == "" {
		return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
	}

	return u, nil
}

func buildSystemdUnitShowCommand(units []string) string {
	return buildSystemdUnitShowArgs([]string{"--property=" + systemdUnitShowProperties}, units)
}

// buildSystemdUnitShowAllCommand asks for every property the systemd release
// has, empty ones included, for a release that does not know some of the
// properties named in systemdUnitShowProperties.
func buildSystemdUnitShowAllCommand(units []string) string {
	return buildSystemdUnitShowArgs([]string{"--all"}, units)
}

func buildSystemdUnitShowArgs(flags []string, units []string) string {
	// "--" keeps a unit name that begins with a dash from being read as a flag;
	// the name reaches Get straight from a query, so it is not ours to trust
	args := append([]string{"systemctl", "show"}, flags...)
	args = append(args, "--")
	args = append(args, units...)

	escaped := make([]string, len(args))
	for i := range args {
		escaped[i] = shared.ShellEscape(args[i])
	}
	return strings.Join(escaped, " ")
}

// parseSystemdUnitFileNames reads the unit names out of
// "systemctl list-unit-files" output.
func parseSystemdUnitFileNames(input io.Reader) ([]string, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// the command asks for --no-legend, but selecting on the .service suffix
	// rather than skipping a fixed number of lines means a header or footer still
	// falls out on its own, in any locale and on a systemd too old for the flag
	names := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		names = append(names, fields[0])
	}

	return names, nil
}

// parseSystemdShowRecords splits "systemctl show" output into one property map
// per unit. Records are separated by an empty line when more than one unit is
// requested. A repeated key is joined with a newline, matching how a unit can
// carry several ExecStart lines.
func parseSystemdShowRecords(input io.Reader) ([]map[string]string, error) {
	records := []map[string]string{}
	current := map[string]string{}

	flush := func() {
		if len(current) > 0 {
			records = append(records, current)
			current = map[string]string{}
		}
	}

	scanner := bufio.NewScanner(input)
	// a unit can carry long values, so allow more than the default line budget
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if existing, seen := current[key]; seen {
			current[key] = existing + "\n" + value
		} else {
			current[key] = value
		}
	}
	flush()

	return records, scanner.Err()
}

// systemdUnitFromProperties maps a property record onto a unit, returning nil
// when the record names no unit.
func systemdUnitFromProperties(props map[string]string) *SystemdUnit {
	name := props["Id"]
	if name == "" {
		return nil
	}

	u := &SystemdUnit{
		Name:          name,
		Description:   props["Description"],
		Installed:     props["LoadState"] != "not-found" && props["LoadState"] != "",
		FragmentPath:  props["FragmentPath"],
		LoadState:     props["LoadState"],
		ActiveState:   props["ActiveState"],
		SubState:      props["SubState"],
		UnitFileState: props["UnitFileState"],
		Type:          props["Type"],
		ExecStart:     parseSystemdExecStart(props["ExecStart"]),

		User:        props["User"],
		Group:       props["Group"],
		DynamicUser: parseSystemdBool(props["DynamicUser"]),
		UMask:       props["UMask"],

		NoNewPrivileges:         parseSystemdBool(props["NoNewPrivileges"]),
		ProtectSystem:           props["ProtectSystem"],
		ProtectHome:             props["ProtectHome"],
		PrivateTmp:              parseSystemdBool(props["PrivateTmp"]),
		PrivateDevices:          parseSystemdBool(props["PrivateDevices"]),
		PrivateNetwork:          parseSystemdBool(props["PrivateNetwork"]),
		PrivateUsers:            parseSystemdBool(props["PrivateUsers"]),
		ProtectKernelTunables:   parseSystemdBool(props["ProtectKernelTunables"]),
		ProtectKernelModules:    parseSystemdBool(props["ProtectKernelModules"]),
		ProtectKernelLogs:       parseSystemdBool(props["ProtectKernelLogs"]),
		ProtectControlGroups:    props["ProtectControlGroups"],
		ProtectClock:            parseSystemdBool(props["ProtectClock"]),
		ProtectHostname:         parseSystemdBool(props["ProtectHostname"]),
		ProtectProc:             props["ProtectProc"],
		ProcSubset:              props["ProcSubset"],
		RestrictSUIDSGID:        parseSystemdBool(props["RestrictSUIDSGID"]),
		RestrictRealtime:        parseSystemdBool(props["RestrictRealtime"]),
		RestrictNamespaces:      props["RestrictNamespaces"],
		RestrictAddressFamilies: props["RestrictAddressFamilies"],
		LockPersonality:         parseSystemdBool(props["LockPersonality"]),
		MemoryDenyWriteExecute:  parseSystemdBool(props["MemoryDenyWriteExecute"]),
		RemoveIPC:               parseSystemdBool(props["RemoveIPC"]),
		KeyringMode:             props["KeyringMode"],

		CapabilityBoundingSet:   splitSystemdList(props["CapabilityBoundingSet"]),
		AmbientCapabilities:     splitSystemdList(props["AmbientCapabilities"]),
		SystemCallFilter:        splitSystemdList(props["SystemCallFilter"]),
		SystemCallArchitectures: props["SystemCallArchitectures"],
		ReadWritePaths:          splitSystemdList(props["ReadWritePaths"]),
		ReadOnlyPaths:           splitSystemdList(props["ReadOnlyPaths"]),
		InaccessiblePaths:       splitSystemdList(props["InaccessiblePaths"]),
	}

	if names := strings.Fields(props[systemdUnsupportedKey]); len(names) > 0 {
		u.Unsupported = make(map[string]bool, len(names))
		for _, name := range names {
			u.Unsupported[name] = true
		}
	}
	return u
}

// parseSystemdBool reads a systemd boolean. systemctl normalizes to yes/no,
// while a unit file accepts several spellings.
func parseSystemdBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// splitSystemdList splits a whitespace-separated property value. systemctl wraps
// some list values in braces, which are not part of the entries.
func splitSystemdList(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "{")
	value = strings.TrimSuffix(value, "}")

	fields := strings.Fields(value)
	res := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		res = append(res, field)
	}
	return res
}

// parseSystemdExecStart reduces an ExecStart property to the command line it
// runs. systemctl reports it as a structured value like
// "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ... }", where argv[] holds
// the command as invoked.
func parseSystemdExecStart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	// only the first ExecStart line is the command; later ones are extra
	if idx := strings.IndexByte(value, '\n'); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}

	if !strings.Contains(value, "argv[]=") {
		return value
	}

	// drop the braces delimiting the structure before splitting on the field
	// separator, so a closing brace cannot end up attached to the last field and
	// an argument that itself ends in a brace survives
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}

	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if argv, ok := strings.CutPrefix(part, "argv[]="); ok {
			return strings.TrimSpace(argv)
		}
	}

	return value
}

// SystemdFSUnitManager reads unit settings from unit files. It is used when
// command execution is not available, such as an image scan. Runtime state is not
// knowable from the filesystem and is left empty.
type SystemdFSUnitManager struct {
	Fs afero.Fs
	// Version is the release of the host's systemd, 0 when unknown. Settings
	// a unit file makes that this release does not know are not reported.
	Version int
}

func (m *SystemdFSUnitManager) List() ([]*SystemdUnit, error) {
	seen := map[string]bool{}
	res := []*SystemdUnit{}

	for _, searchPath := range systemdUnitSearchPath {
		entries, err := afero.ReadDir(m.Fs, searchPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}
			// the search path is ordered by precedence, so the first copy wins
			if seen[entry.Name()] {
				continue
			}
			seen[entry.Name()] = true

			u, err := m.readUnit(entry.Name(), path.Join(searchPath, entry.Name()))
			if err != nil {
				continue
			}
			res = append(res, u)
		}
	}

	return res, nil
}

func (m *SystemdFSUnitManager) Get(name string) (*SystemdUnit, error) {
	// systemctl reads a name without a unit type as a service, and so does a
	// query: systemd.unit("chronyd") is chronyd.service
	name = withSystemdUnitType(name)
	for _, searchPath := range systemdUnitSearchPath {
		unitPath := path.Join(searchPath, name)
		if _, err := m.Fs.Stat(unitPath); err != nil {
			continue
		}
		return m.readUnit(name, unitPath)
	}
	return nil, fmt.Errorf("%w: %s", ErrServiceNotFound, name)
}

func (m *SystemdFSUnitManager) readUnit(name string, unitPath string) (*SystemdUnit, error) {
	props := map[string]string{"Id": name}

	if m.isMasked(unitPath) {
		props["LoadState"] = "masked"
		props["UnitFileState"] = "masked"
		return systemdUnitFromProperties(props), nil
	}

	props["LoadState"] = "loaded"
	props["FragmentPath"] = unitPath

	// the unit file first, then its drop-ins in name order, so a later value
	// overrides an earlier one the way systemd merges them
	if err := m.foldUnitFile(props, unitPath); err != nil {
		return nil, err
	}
	for _, dropIn := range m.dropInFiles(name) {
		if err := m.foldUnitFile(props, dropIn); err != nil {
			continue
		}
	}
	markUnsupportedFileProperties(props, m.Version)

	return systemdUnitFromProperties(props), nil
}

// isMasked reports whether a unit file is masked, meaning systemd refuses to
// start it at all.
//
// Masking symlinks the unit to /dev/null, so reading the link is the direct
// answer. Not every filesystem can read a link, though: an archive-backed or
// remote filesystem may not implement afero.LinkReader, and a masked unit that
// went undetected would be reported as loaded with no settings, which reads
// exactly like a service running with no confinement. So an empty unit file is
// treated as masked too. The cost of being wrong is small in the other
// direction, since a zero-byte unit file carries no settings either way.
func (m *SystemdFSUnitManager) isMasked(unitPath string) bool {
	if lr, ok := m.Fs.(afero.LinkReader); ok {
		if linkPath, err := lr.ReadlinkIfPossible(unitPath); err == nil {
			return linkPath == "/dev/null"
		}
	}

	info, err := m.Fs.Stat(unitPath)
	if err != nil {
		return false
	}
	return info.Size() == 0
}

// foldUnitFile reads the [Unit] and [Service] settings of one file into props.
func (m *SystemdFSUnitManager) foldUnitFile(props map[string]string, unitPath string) error {
	f, err := m.Fs.Open(unitPath)
	if err != nil {
		return err
	}
	defer f.Close()

	opts, err := unit.Deserialize(f)
	if err != nil {
		return err
	}

	for _, opt := range opts {
		switch opt.Section {
		case "Unit":
			if opt.Name == "Description" {
				props["Description"] = opt.Value
			}
		case "Service":
			// an empty assignment resets a list setting, so it clears what came
			// before rather than appending to it
			if opt.Value == "" {
				delete(props, opt.Name)
				continue
			}
			if existing, seen := props[opt.Name]; seen && systemdListProperty(opt.Name) {
				props[opt.Name] = existing + " " + opt.Value
				continue
			}
			props[opt.Name] = opt.Value
		}
	}

	return nil
}

// dropInFiles returns the drop-in files for a unit, in the order systemd reads
// them: every drop-in directory is merged and the result is ordered by file
// name, not by the directory it came from, so 05-early.conf under /usr/lib
// still applies before 10-late.conf under /etc. When the same file name appears
// in more than one directory, the earlier search path wins and shadows the rest.
func (m *SystemdFSUnitManager) dropInFiles(name string) []string {
	winners := map[string]string{}
	names := []string{}

	for _, searchPath := range systemdUnitSearchPath {
		dir := path.Join(searchPath, name+".d")
		entries, err := afero.ReadDir(m.Fs, dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			if _, taken := winners[entry.Name()]; taken {
				continue
			}
			winners[entry.Name()] = path.Join(dir, entry.Name())
			names = append(names, entry.Name())
		}
	}

	sort.Strings(names)

	res := make([]string, 0, len(names))
	for _, dropIn := range names {
		res = append(res, winners[dropIn])
	}

	return res
}

// systemdListProperty reports whether a setting accumulates across assignments
// rather than being replaced by the last one.
func systemdListProperty(name string) bool {
	switch name {
	case "CapabilityBoundingSet", "AmbientCapabilities", "SystemCallFilter",
		"ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "RestrictAddressFamilies":
		return true
	}
	return false
}

// systemdUnitTypes are the unit type suffixes systemd knows.
var systemdUnitTypes = []string{
	".service", ".socket", ".device", ".mount", ".automount", ".swap",
	".target", ".path", ".timer", ".slice", ".scope",
}

// withSystemdUnitType appends ".service" to a unit name that carries no unit
// type, the way systemctl completes it.
func withSystemdUnitType(name string) string {
	for _, suffix := range systemdUnitTypes {
		if strings.HasSuffix(name, suffix) {
			return name
		}
	}
	return name + ".service"
}

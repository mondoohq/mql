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
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
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
}

// fsFallback reads the unit files off disk. systemctl needs a running systemd
// to answer, so it is not available in a container, a chroot, a rescue boot, or
// on a host that keeps unit files around while another init runs. It reports
// that by exiting non-zero with nothing on stdout, which parses into an empty
// unit list -- indistinguishable from a host that genuinely runs no services,
// and enough to make an assertion over systemd.units pass without ever having
// read a unit.
func (m *SystemdUnitManager) fsFallback() *SystemdFSUnitManager {
	return &SystemdFSUnitManager{Fs: m.conn.FileSystem()}
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
	for start := 0; start < len(concrete); start += systemdUnitShowChunk {
		end := min(start+systemdUnitShowChunk, len(concrete))

		chunk := concrete[start:end]
		showCmd, err := m.conn.RunCommand(buildSystemdUnitShowCommand(chunk))
		if err != nil {
			return nil, err
		}
		if showCmd.ExitStatus != 0 {
			return nil, systemctlError("systemctl show", showCmd)
		}

		records, err := parseSystemdShowRecords(showCmd.Stdout)
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			if u := systemdUnitFromProperties(record); u != nil {
				res = append(res, u)
			}
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

func (m *SystemdUnitManager) Get(name string) (*SystemdUnit, error) {
	cmd, err := m.conn.RunCommand(buildSystemdUnitShowCommand([]string{name}))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		// same reason as List: a systemctl that cannot answer must not read as
		// "there is no such unit"
		log.Debug().Err(systemctlError("systemctl show", cmd)).Str("unit", name).
			Msg("mql[systemd]> could not read unit through systemctl, reading the unit file instead")
		return m.fsFallback().Get(name)
	}

	records, err := parseSystemdShowRecords(cmd.Stdout)
	if err != nil {
		return nil, err
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
	// "--" keeps a unit name that begins with a dash from being read as a flag;
	// the name reaches Get straight from a query, so it is not ours to trust
	args := []string{"systemctl", "show", "--property=" + systemdUnitShowProperties, "--"}
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

	return &SystemdUnit{
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

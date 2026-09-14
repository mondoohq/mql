// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

var (
	SYSTEMD_LIST_UNITS_REGEX = regexp.MustCompile(`(?m)^(?:[^\S\n]{2}|●[^\S\n]|)(\S+)(?:[^\S\n])+(\S+)(?:[^\S\n])+(\S+)(?:[^\S\n])+(\S+)(?:[^\S\n])+(.+)$`)
	serviceNameRegex         = regexp.MustCompile(`(.*)\.(service|target|socket)$`)
	errIgnored               = errors.New("ignored")
)

const (
	systemdShowProperties = "Id,LoadState,ActiveState,UnitFileState,Description"
)

func ResolveSystemdServiceManager(conn shared.Connection) OSServiceManager {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return &SystemdFSServiceManager{Fs: conn.FileSystem()}
	}
	return &SystemDServiceManager{conn: conn}
}

// Newer linux systems use systemd as service manager
type SystemDServiceManager struct {
	conn shared.Connection
}

func (s *SystemDServiceManager) Name() string {
	return "systemd Service Manager"
}

// errSystemctlNoOutput reports that systemctl ran but produced nothing this
// parser recognizes as a unit-file listing. It is the one failure that means
// "systemd is not the running init here", which is what makes reading the units
// off disk the right answer. A read failure on stdout is an IO fault and says
// nothing about the target, so it is deliberately not covered by this sentinel.
var errSystemctlNoOutput = errors.New("unexpected output from systemctl list-unit-files")

func ParseServiceSystemDUnitFiles(input io.Reader) ([]*Service, error) {
	var services []*Service
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error executing systemctl list-unit-files: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("%w: %q", errSystemctlNoOutput, content)
	}

	for _, line := range lines[1 : len(lines)-1] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		if strings.Contains(line, "unit files listed.") {
			continue
		}

		service := &Service{
			Name:      normalizeSystemdServiceName(fields[0]),
			Installed: true,
			Type:      "systemd",
		}
		applySystemdUnitFileState(service, fields[1])

		services = append(services, service)
	}

	return services, nil
}

// ParseSystemdListUnits parses the output of "systemctl list-units --type service --all"
// and returns a map of normalized service name to Service. This provides running state
// directly from systemd without the fragility of batched "systemctl show" calls.
func ParseSystemdListUnits(input io.Reader) (map[string]*Service, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("error reading systemctl list-units output: %v", err)
	}

	services := map[string]*Service{}
	matches := SYSTEMD_LIST_UNITS_REGEX.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		unitName := match[1]
		if !strings.HasSuffix(unitName, ".service") {
			continue
		}

		name := normalizeSystemdServiceName(unitName)
		services[name] = &Service{
			Name:        name,
			Description: strings.TrimSpace(match[5]),
			Running:     match[3] == "active",
			Installed:   match[2] != "not-found",
			Type:        "systemd",
		}
	}

	return services, nil
}

func applySystemdUnitFileState(service *Service, unitFileState string) {
	// A unit that is not installed (LoadState=not-found or empty) can still
	// report a leftover UnitFileState such as "enabled" — for example a dangling
	// enablement symlink left behind by a removed package. Reporting it as
	// enabled/masked/static would contradict installed=false, so skip applying
	// the unit-file state for units that are not installed.
	if !service.Installed {
		return
	}
	service.Enabled = unitFileState == "enabled" || unitFileState == "enabled-runtime"
	service.Masked = strings.HasPrefix(unitFileState, "masked")
	service.Static = unitFileState == "static"
}

func normalizeSystemdServiceName(unit string) string {
	return strings.TrimSuffix(unit, ".service")
}

func ensureSystemdServiceUnit(name string) string {
	if strings.HasSuffix(name, ".service") {
		return name
	}

	return name + ".service"
}

func buildSystemdShowCommand(units []string) string {
	args := []string{"systemctl", "show", "--property=" + systemdShowProperties}
	args = append(args, units...)

	escaped := make([]string, len(args))
	for i := range args {
		escaped[i] = shared.ShellEscape(args[i])
	}

	return strings.Join(escaped, " ")
}

func ParseServiceSystemDShow(input io.Reader) (map[string]*Service, error) {
	services := map[string]*Service{}
	record := map[string]string{}

	flushRecord := func() error {
		if len(record) == 0 {
			return nil
		}

		service, err := parseSystemDShowRecord(record)
		if err != nil {
			return err
		}
		services[service.Name] = service
		record = map[string]string{}
		return nil
	}

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if err := flushRecord(); err != nil {
				return nil, err
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("unexpected output from systemctl show: %q", line)
		}

		// Defense in depth: if we encounter a new Id= while already building a
		// record, flush the current one first. This handles cases where systemctl
		// omits the blank-line separator (e.g., when a template unit fails).
		if key == "Id" && record["Id"] != "" {
			if err := flushRecord(); err != nil {
				return nil, err
			}
		}

		record[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err := flushRecord(); err != nil {
		return nil, err
	}

	return services, nil
}

func parseSystemDShowRecord(record map[string]string) (*Service, error) {
	id := record["Id"]
	if id == "" {
		return nil, errors.New("unexpected output from systemctl show: missing Id")
	}

	service := &Service{
		Name:        normalizeSystemdServiceName(id),
		Description: record["Description"],
		Installed:   record["LoadState"] != "not-found" && record["LoadState"] != "",
		Running:     record["ActiveState"] == "active",
		Type:        "systemd",
	}
	applySystemdUnitFileState(service, record["UnitFileState"])

	return service, nil
}

func (s *SystemDServiceManager) showUnits(units []string) (map[string]*Service, error) {
	cmd, err := s.conn.RunCommand(buildSystemdShowCommand(units))
	if err != nil {
		return nil, err
	}

	return ParseServiceSystemDShow(cmd.Stdout)
}

func (s *SystemDServiceManager) Get(name string) (*Service, error) {
	services, err := s.showUnits([]string{ensureSystemdServiceUnit(name)})
	if err != nil {
		return nil, err
	}

	service, ok := services[NormalizeServiceLookupName(name)]
	if !ok || !service.Installed {
		return nil, serviceNotFound(name)
	}

	return service, nil
}

// List returns a slice of Service structs representing the state of all services.
// It uses list-unit-files for the complete set (including unloaded services) and
// list-units for running state. This avoids batched "systemctl show" which fails
// on template units (name@.service), causing missing blank-line separators that
// merge adjacent records and silently lose service data.
func (s *SystemDServiceManager) List() ([]*Service, error) {
	// Step 1: Get all service unit files (provides Enabled/Masked/Static/Installed)
	cmdList, err := s.conn.RunCommand("systemctl list-unit-files --type service --all")
	if err != nil {
		return nil, err
	}

	services, err := ParseServiceSystemDUnitFiles(cmdList.Stdout)
	if err != nil {
		// Being able to run a command does not mean systemd is the running
		// init. A container built from a systemd distro carries the unit files
		// without ever starting systemd, so systemctl produces nothing usable
		// there. Read the units off disk instead of reporting the failure as
		// the service list.
		//
		// Only an unusable listing means that. Failing to read stdout is an IO
		// fault, and answering it with a filesystem listing would present a
		// plausible service list built from a read that never completed.
		if !errors.Is(err, errSystemctlNoOutput) {
			return nil, err
		}
		log.Debug().Err(err).Msg("systemctl did not answer, reading systemd units from disk instead")
		return (&SystemdFSServiceManager{Fs: s.conn.FileSystem()}).List()
	}

	// Step 2: Get running state from list-units (provides Running/Description)
	cmdUnits, err := s.conn.RunCommand("systemctl list-units --type service --all")
	if err != nil {
		return nil, err
	}

	unitStates, err := ParseSystemdListUnits(cmdUnits.Stdout)
	if err != nil {
		return nil, err
	}

	// Step 3: Merge - update services from step 1 with running state from step 2.
	// Services in list-unit-files but not in list-units are unloaded/templates;
	// Running=false is correct for them (already the default).
	known := make(map[string]struct{}, len(services))
	for _, service := range services {
		known[service.Name] = struct{}{}

		unitState, ok := unitStates[service.Name]
		if !ok {
			continue
		}
		service.Description = unitState.Description
		service.Running = unitState.Running
		if !unitState.Installed {
			service.Installed = false
		}
	}

	// Step 4: Add loaded units that have no unit file of their own. An
	// instantiated template unit (getty@tty1) is only ever reported by
	// list-units -- list-unit-files carries the template (getty@) instead --
	// so without this the running instance is invisible and the template
	// reads running=false while an instance of it is up.
	return append(services, s.instanceUnits(unitStates, known)...), nil
}

// instanceUnits builds services for loaded units that list-unit-files did not
// report. Their unit-file state is read with a batched "systemctl show" over
// the instances themselves: that call is unreliable for *template* units
// (name@.service yields no record), which is why List does not use it for the
// full set, but concrete instances return a record each. An instance's
// enablement cannot be inherited from its template -- nut-driver@ can be
// "indirect" while nut-driver@apc is "enabled" -- so it has to be asked for.
func (s *SystemDServiceManager) instanceUnits(unitStates map[string]*Service, known map[string]struct{}) []*Service {
	names := make([]string, 0, len(unitStates))
	for name, state := range unitStates {
		if _, ok := known[name]; ok {
			continue
		}
		// list-units --all also names units that do not exist, because some
		// other unit references them in After=/Conflicts=. They load as
		// not-found and are not services on this host.
		if !state.Installed {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)

	units := make([]string, len(names))
	for i, name := range names {
		units[i] = ensureSystemdServiceUnit(name)
	}

	// A failure here costs the unit-file state, not the unit: report the
	// service with what list-units already told us rather than dropping it.
	shown := map[string]*Service{}
	if cmd, err := s.conn.RunCommand(buildSystemdShowCommand(units)); err == nil {
		if parsed, err := ParseServiceSystemDShow(cmd.Stdout); err == nil {
			shown = parsed
		}
	}

	instances := make([]*Service, 0, len(names))
	for _, name := range names {
		if service, ok := shown[name]; ok {
			instances = append(instances, service)
			continue
		}
		state := unitStates[name]
		instances = append(instances, &Service{
			Name:        name,
			Description: state.Description,
			Running:     state.Running,
			Installed:   state.Installed,
			Type:        "systemd",
		})
	}

	return instances
}

type SystemdFSServiceManager struct {
	Fs afero.Fs
}

// systemdUnitSearchPath is the order in which systemd looks up unit files
// We ignore anything in /run as fs scans should not represent a running system
// https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Unit%20File%20Load%20Path
//
// /lib/systemd/system is the last entry because it is the same directory as
// /usr/lib/systemd/system wherever /lib is a symlink into /usr, which is every
// distro that has completed the /usr merge. On the ones that have not --
// Debian 11 and older, Ubuntu 18.04 and older -- /lib is a real directory and
// is where every unit file actually lives, with /usr/lib/systemd/system empty
// or absent. Leaving it out reported those hosts as running no units at all.
var systemdUnitSearchPath = []string{
	"/etc/systemd/system.control",
	"/etc/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

type unitInfo struct {
	// name is the name of the unit without the type extension
	name string
	// uType is the type extension, for example service, target, etc
	uType string
	// description is the description that is provided in the unit section
	description string
	// deps is a list of all name.type values found in the Wants and Requires
	// fields of the Unit section
	deps []string
	// Orderings is a list of all name.type values found in the Before and
	// After fields of the Unit section
	orderings []string
	// masked is set to true of a unit is symlinked to /dev/null
	masked bool
	// missing is set to true if we have a dependency on a unit, but that
	// unit was not found in the search path
	missing bool
	// isDep is true of this unit is found in the dependency tree starting
	// from the default.target
	isDep bool
	// hasInstall is true if the unit file has an [Install] section
	hasInstall bool
	// service is only set for socket units. It contains an optional name.target.
	// If not provided, socketname.service is activated for the socket
	service string
}

type stackEntry struct {
	unit     string
	critical bool
}
type stack []stackEntry

func (s *stack) push(v stackEntry) {
	*s = append(*s, v)
}

func (s *stack) pop() stackEntry {
	n := len(*s) - 1
	v := (*s)[n]
	*s = (*s)[:n]
	return v
}

func (s *stack) len() int {
	return len(*s)
}

func (s *SystemdFSServiceManager) Name() string {
	return "systemd FS Service Manager"
}

func (s *SystemdFSServiceManager) List() ([]*Service, error) {
	enabledUnits, err := s.traverse()
	if err != nil {
		return nil, err
	}
	services := make([]*Service, 0, len(enabledUnits))
	for _, v := range enabledUnits {
		if v.uType != "service" {
			continue
		}
		services = append(services, &Service{
			Name:        v.name,
			Type:        v.uType,
			Description: v.description,
			State:       ServiceUnknown,
			Installed:   !v.missing,
			Enabled:     !v.missing && v.isDep,
			Masked:      v.masked,
			Static:      !v.missing && !v.masked && !v.hasInstall,
		})
	}
	return services, nil
}

func (s *SystemdFSServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

// traverse traverses the root target and finds units. This implementation is
// incomplete. It only looks at targets, services, and sockets, so at least
// mounts and timers are missing. Also, handling of templates is probably not
// fully correct. The implicit and default dependencies for types are also
// not accounted for
func (s *SystemdFSServiceManager) traverse() (map[string]*unitInfo, error) {
	loadedUnits := map[string]*unitInfo{}
	stack := new(stack)
	stack.push(stackEntry{
		critical: true,
		unit:     "default.target",
	})
	for stack.len() > 0 {
		u := stack.pop()
		if l, ok := loadedUnits[u.unit]; ok {
			if !l.isDep && u.critical {
				// We need to revisit all the already loaded units
				// and mark them as a dependency
				l.isDep = true
				for _, v := range l.deps {
					stack.push(stackEntry{
						unit:     v,
						critical: true,
					})
				}
			}
			continue
		}
		uInfo, err := s.findUnit(u.unit)
		if err != nil {
			if errors.Is(err, errIgnored) {
				continue
			}
			return nil, err
		}
		for _, d := range uInfo.deps {
			stack.push(stackEntry{
				unit:     d,
				critical: u.critical,
			})
		}
		for _, d := range uInfo.orderings {
			stack.push(stackEntry{
				unit:     d,
				critical: false,
			})
		}
		if uInfo.uType == "socket" {
			d := uInfo.service
			if d == "" {
				d = fmt.Sprintf("%s.service", uInfo.name)
			}
			stack.push(stackEntry{
				unit:     d,
				critical: u.critical,
			})
		}
		uInfo.isDep = uInfo.isDep || u.critical
		loadedUnits[u.unit] = uInfo
	}
	return loadedUnits, nil
}

func (s *SystemdFSServiceManager) findUnit(unitName string) (*unitInfo, error) {
	name, uType, ok := unitNameAndType(unitName)
	if !ok {
		return nil, errIgnored
	}
	uInfo := unitInfo{
		name:  name,
		uType: uType,
	}

	for _, p := range systemdUnitSearchPath {
		var err error
		var fsInfo fs.FileInfo

		uName := unitName
		unitPath := path.Join(p, unitName)

		// We try to lstat if we can. We want to know if the file is
		// a symlink because symlinks are aliases
		if lstater, ok := s.Fs.(afero.Lstater); ok {
			fsInfo, _, err = lstater.LstatIfPossible(unitPath)
		} else {
			fsInfo, err = s.Fs.Stat(unitPath)
		}
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		findNames := []string{uName}
		if fsInfo.Mode()&fs.ModeSymlink != 0 {
			// If its a symlink, we need to get the real name
			// TODO: check if this needs to be done recursively
			if lr, ok := s.Fs.(afero.LinkReader); ok {
				linkPath, err := lr.ReadlinkIfPossible(unitPath)
				if err != nil {
					return nil, err
				}
				if linkPath == "/dev/null" {
					uInfo.masked = true
					return &uInfo, nil
				} else {
					linkedName := path.Base(linkPath)
					name, uType, ok := unitNameAndType(linkedName)
					// The rules for aliasing only allow same type to same
					// type. So foo.service -> bar.service, but not
					// foo.service -> bar.socket
					if !ok || (uInfo.uType != uType) {
						return nil, fmt.Errorf("invalid unit %s", linkedName)
					}
					uInfo.name = name
					findNames = append(findNames, linkedName)
				}
			}
		}

		if err := s.readUnit(unitPath, &uInfo); err != nil {
			return nil, err
		}

		// We need to search for deps from directories based on both the
		// real name and aliased name
		for _, n := range findNames {
			dirDeps, err := s.findDeps(n)
			if err != nil {
				return nil, err
			}
			uInfo.deps = append(uInfo.deps, dirDeps...)
		}

		return &uInfo, nil
	}

	uInfo.missing = true
	return &uInfo, nil
}

// readUnit reads the unit file:
// deps are pulled from the Wants and Requires keys of the Unit section
// description is pulled from the Description key of the Unit section
// orderings are pulled from the Before and After keys of the Unit section
func (s *SystemdFSServiceManager) readUnit(unitPath string, uInfo *unitInfo) error {
	// First resolve the symlink in case the unitPath is actually a symlink.
	if lr, ok := s.Fs.(afero.LinkReader); ok {
		linkPath, err := lr.ReadlinkIfPossible(unitPath)
		if err == nil {
			// If the linkPath is not absolute, use the directory of unitPath and append the
			// filename.
			if !filepath.IsAbs(linkPath) {
				directory := filepath.Dir(unitPath)
				linkPath = filepath.Join(directory, linkPath)
			}
			unitPath = linkPath
		}
	}

	f, err := s.Fs.Open(unitPath)
	if err != nil {
		return err
	}
	opts, err := unit.Deserialize(f)
	if err != nil {
		return err
	}

	for _, o := range opts {
		if o.Section == "Unit" && (o.Name == "Wants" || o.Name == "Requires") {
			deps := strings.Fields(o.Value)
			for _, d := range deps {
				if serviceNameRegex.MatchString(d) {
					uInfo.deps = append(uInfo.deps, d)
				}
			}
		} else if o.Section == "Unit" && o.Name == "Description" {
			uInfo.description = o.Value
		} else if o.Section == "Unit" && (o.Name == "Before" || o.Name == "After") {
			orderings := strings.Fields(o.Value)
			for _, d := range orderings {
				if serviceNameRegex.MatchString(d) {
					uInfo.orderings = append(uInfo.orderings, d)
				}
			}
		} else if o.Section == "Socket" && o.Name == "Service" {
			uInfo.service = o.Value
		} else if o.Section == "Install" {
			uInfo.hasInstall = true
		}
	}

	return nil
}

// findDeps looks up the dependencies for the given unit name (foo.service)
// by looking up all the links in the foo.service.wants and foo.service.requires
// directories
func (s *SystemdFSServiceManager) findDeps(unitName string) ([]string, error) {
	deps := []string{}
	for _, searchPath := range systemdUnitSearchPath {
		paths := []string{
			path.Join(searchPath, fmt.Sprintf("%s.wants", unitName)),
			path.Join(searchPath, fmt.Sprintf("%s.requires", unitName)),
		}

		for _, p := range paths {
			_, err := s.Fs.Stat(p)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			unitLinks, err := afero.ReadDir(s.Fs, p)
			if err != nil {
				return nil, err
			}
			for _, unitLink := range unitLinks {
				if serviceNameRegex.MatchString(unitLink.Name()) {
					deps = append(deps, unitLink.Name())
				}
			}
		}
	}

	return deps, nil
}

func unitNameAndType(n string) (name string, uType string, ok bool) {
	matches := serviceNameRegex.FindStringSubmatch(n)
	if len(matches) > 1 {
		name = matches[1]
	}
	if len(matches) > 2 {
		uType = matches[2]
	}
	if len(matches) == 3 {
		ok = true
	}
	return
}

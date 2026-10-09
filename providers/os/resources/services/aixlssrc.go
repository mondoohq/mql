// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// AixServiceManager lists the subsystems of the System Resource Controller
// and the daemons init keeps running from /etc/inittab, cron among them,
// which SRC does not control.
type AixServiceManager struct {
	conn shared.Connection
}

func (s *AixServiceManager) Name() string {
	return "System Resource Controller"
}

func (s *AixServiceManager) List() ([]*Service, error) {
	cmd, err := s.conn.RunCommand("lssrc -a")
	if err != nil {
		return nil, err
	}
	entries := parseLssrc(cmd.Stdout)

	fs := s.conn.FileSystem()
	inittab := readAixInittab(fs)
	boot := aixBootStarts(fs, inittab)

	services := make([]*Service, 0, len(entries))
	subsystems := map[string]bool{}
	for _, entry := range entries {
		subsystems[entry.Subsystem] = true
		services = append(services, &Service{
			Name:      entry.Subsystem,
			Enabled:   boot.subsystems[entry.Subsystem] || (entry.Group != "" && boot.groups[entry.Group]),
			Installed: true,
			Running:   entry.Status == "active",
			Type:      "aix",
		})
	}

	daemons := aixInittabDaemons(inittab)
	if len(daemons) == 0 {
		return services, nil
	}
	running := map[string]bool{}
	if cmd, err := s.conn.RunCommand("ps -A -o args="); err == nil && cmd.ExitStatus == 0 {
		running = parsePsPrograms(cmd.Stdout)
	}
	for _, d := range daemons {
		if subsystems[d.ID] {
			continue
		}
		services = append(services, &Service{
			Name:      d.ID,
			Enabled:   true,
			Installed: true,
			Running:   running[d.Program],
			Path:      d.Program,
			Type:      "inittab",
		})
	}
	return services, nil
}

func (s *AixServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

type lssrcEntry struct {
	Subsystem string
	Group     string
	PID       string
	Status    string
}

var lssrcRegex = regexp.MustCompile(`^\s([\w.-]+)(\s+[\w]+\s+){0,1}([\d]+){0,1}\s+([\w]+)$`)

func parseLssrc(input io.Reader) []lssrcEntry {
	entries := []lssrcEntry{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := lssrcRegex.FindStringSubmatch(line)
		if len(m) == 5 {
			entries = append(entries, lssrcEntry{
				Subsystem: m[1],
				Group:     strings.TrimSpace(m[2]),
				PID:       m[3],
				Status:    m[4],
			})
		}
	}
	return entries
}

// aixInittabEntry is one line of /etc/inittab: identifier, run levels,
// action and command.
type aixInittabEntry struct {
	ID        string
	RunLevels string
	Action    string
	Command   string
}

// parseAixInittab reads /etc/inittab. A line starting with a colon is a
// comment, and so is everything after a # in the command.
func parseAixInittab(r io.Reader) []aixInittabEntry {
	var entries []aixInittabEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == ':' {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) != 4 {
			continue
		}
		command, _, _ := strings.Cut(parts[3], "#")
		entries = append(entries, aixInittabEntry{
			ID:        parts[0],
			RunLevels: parts[1],
			Action:    parts[2],
			Command:   strings.TrimSpace(command),
		})
	}
	return entries
}

func readAixInittab(fs afero.Fs) []aixInittabEntry {
	f, err := fs.Open("/etc/inittab")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseAixInittab(f)
}

// aixBootEntries returns the inittab entries init runs when it boots into
// its default run level: neither off nor at another run level.
func aixBootEntries(inittab []aixInittabEntry) []aixInittabEntry {
	level := "2"
	for _, e := range inittab {
		if e.Action == "initdefault" && e.RunLevels != "" {
			level = e.RunLevels
		}
	}
	var res []aixInittabEntry
	for _, e := range inittab {
		if e.Action == "off" || e.Action == "initdefault" {
			continue
		}
		if e.RunLevels != "" && !strings.Contains(e.RunLevels, level) {
			continue
		}
		res = append(res, e)
	}
	return res
}

// aixBoot holds the subsystems and subsystem groups started at boot.
type aixBoot struct {
	subsystems map[string]bool
	groups     map[string]bool
}

var (
	reStartsrc = regexp.MustCompile(`\bstartsrc\s+(?:-[a-zA-Z]+\s+)*-([sg])\s*([\w.-]+)`)
	// the start function of /etc/rc.tcpip takes the daemon's path
	// (start /usr/sbin/syslogd "$src_running"), the one of /etc/rc.nfs
	// the subsystem name (start biod /usr/sbin/biod)
	reRcStart = regexp.MustCompile(`(?:^|[;&|]\s*|\s)start\s+"?([\w./-]+)`)
	reRcDir   = regexp.MustCompile(`^/etc/rc\.d/rc\s+(\d)`)
)

// aixBootStarts collects what AIX starts at boot: startsrc in an inittab
// entry, the uncommented start lines of /etc/rc.tcpip and /etc/rc.nfs when
// inittab runs them, and startsrc in the S scripts of /etc/rc.d/rc<level>.d.
// Commenting out its start line is how a daemon is kept from starting at
// boot. Some start lines are conditional (nfsd and rpc.mountd only start
// when /etc/exports exists); they count as enabled.
func aixBootStarts(fs afero.Fs, inittab []aixInittabEntry) aixBoot {
	boot := aixBoot{subsystems: map[string]bool{}, groups: map[string]bool{}}
	for _, e := range aixBootEntries(inittab) {
		addStartsrc(boot, e.Command)
		program, _, _ := strings.Cut(e.Command, " ")
		switch {
		case program == "/etc/rc.tcpip" || program == "/etc/rc.nfs":
			if data, err := afero.ReadFile(fs, program); err == nil {
				for _, name := range parseAixRcStarts(string(data)) {
					boot.subsystems[name] = true
				}
			}
		case reRcDir.MatchString(e.Command):
			dir := "/etc/rc.d/rc" + reRcDir.FindStringSubmatch(e.Command)[1] + ".d"
			files, err := afero.ReadDir(fs, dir)
			if err != nil {
				continue
			}
			for _, fi := range files {
				if !strings.HasPrefix(fi.Name(), "S") {
					continue
				}
				if data, err := afero.ReadFile(fs, path.Join(dir, fi.Name())); err == nil {
					for _, line := range uncommentedLines(string(data)) {
						addStartsrc(boot, line)
					}
				}
			}
		}
	}
	return boot
}

func addStartsrc(boot aixBoot, line string) {
	for _, m := range reStartsrc.FindAllStringSubmatch(line, -1) {
		if m[1] == "s" {
			boot.subsystems[m[2]] = true
		} else {
			boot.groups[m[2]] = true
		}
	}
}

// parseAixRcStarts returns the subsystems the uncommented start lines of
// /etc/rc.tcpip or /etc/rc.nfs start.
func parseAixRcStarts(script string) []string {
	var names []string
	for _, line := range uncommentedLines(script) {
		m := reRcStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// the definition of the start function itself
		if strings.HasPrefix(strings.TrimSpace(line), "start()") {
			continue
		}
		name := path.Base(m[1])
		if name == "" || strings.HasPrefix(name, "$") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// reTrailingComment matches a shell comment after a command on its line,
// as in `else	#if srcmstr not running, start manually`.
var reTrailingComment = regexp.MustCompile(`\s#.*$`)

// uncommentedLines returns the lines of a shell script without comments.
func uncommentedLines(script string) []string {
	var lines []string
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		lines = append(lines, reTrailingComment.ReplaceAllString(trimmed, ""))
	}
	return lines
}

// aixInittabDaemon is a daemon init starts and restarts itself.
type aixInittabDaemon struct {
	ID      string
	Program string
}

// aixInittabDaemons returns the respawn entries of inittab that run a
// daemon rather than startsrc or a script.
func aixInittabDaemons(inittab []aixInittabEntry) []aixInittabDaemon {
	var res []aixInittabDaemon
	for _, e := range aixBootEntries(inittab) {
		if e.Action != "respawn" {
			continue
		}
		program, _, _ := strings.Cut(e.Command, " ")
		if program == "" || path.Base(program) == "startsrc" || strings.HasPrefix(program, "/etc/rc") {
			continue
		}
		res = append(res, aixInittabDaemon{ID: e.ID, Program: program})
	}
	return res
}

// parsePsPrograms returns the programs of ps -o args output.
func parsePsPrograms(r io.Reader) map[string]bool {
	res := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		program, _, _ := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if program != "" {
			res[program] = true
		}
	}
	return res
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package postgresql

import (
	"bufio"
	"path"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
	"go.mondoo.com/mql/providers/os/resources/systemd"
)

// Instance is a PostgreSQL cluster as the host starts it: the data directory
// the server is pointed at and the settings given on its command line or in
// its environment. Instances come from a running postmaster's command line or
// from a systemd unit, and say where the server's postgresql.conf lives when
// that is not one of the well-known paths (a data directory relocated with a
// systemd drop-in, a PGDG versioned layout).
type Instance struct {
	// DataDir is the directory passed with -D (or PGDATA).
	DataDir string
	// Settings are given on the command line (-p, -c name=value,
	// --name=value). They override postgresql.conf. Names are lowercase with
	// dashes turned into underscores, the way PostgreSQL reads them.
	Settings map[string]string
	// Env is the environment the server starts with. PGPORT only applies
	// when postgresql.conf does not set port.
	Env map[string]string
	// Pid is the postmaster's process id, 0 when the instance does not come
	// from a running process.
	Pid int
}

// ApplyEnv records the environment a postmaster runs with. A postmaster
// started without -D (the official container images run a bare
// `postgres -c ...`) takes its data directory from PGDATA.
func (i *Instance) ApplyEnv(env map[string]string) {
	i.Env = env
	if i.DataDir == "" && env["PGDATA"] != "" {
		i.DataDir = path.Clean(env["PGDATA"])
	}
}

// ParsePostmasterPid reads the pid from the first line of a data
// directory's postmaster.pid, which the running postmaster writes.
func ParsePostmasterPid(content string) (int, bool) {
	line, _, _ := strings.Cut(content, "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// RunningByPid returns the running instance with the given pid, nil when
// none has it.
func RunningByPid(running []Instance, pid int) *Instance {
	for _, inst := range running {
		if inst.Pid == pid {
			inst := inst
			return &inst
		}
	}
	return nil
}

// Overlay returns the settings of a postgresql.conf with the instance's
// command line settings applied: the server reads its command line after
// the file, so pg_settings reports them with source "command line". inst
// may be nil.
func Overlay(params map[string]string, inst *Instance) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[k] = v
	}
	if inst == nil {
		return out
	}
	for k, v := range inst.Settings {
		out[k] = v
	}
	return out
}

// ConfigFile returns the postgresql.conf the instance loads: config_file from
// the command line, or postgresql.conf in the data directory. It returns ""
// when neither is known.
func (i Instance) ConfigFile() string {
	if cf := i.Settings["config_file"]; cf != "" {
		if path.IsAbs(cf) || i.DataDir == "" {
			return path.Clean(cf)
		}
		return path.Join(i.DataDir, cf)
	}
	if i.DataDir == "" {
		return ""
	}
	return path.Join(i.DataDir, "postgresql.conf")
}

// postmasterArgOptions are the single-letter postgres options that take an
// argument (postmaster.c's getopt string "B:bC:c:D:d:EeFf:h:ijk:lN:OPp:r:S:sTt:W:").
const postmasterArgOptions = "BCcDdfhkNprStW"

// ParsePostmasterArgs reads the command line of a running postmaster (argv
// split from /proc/<pid>/cmdline). It reports false when argv is not a
// postmaster: backends and auxiliary processes rewrite their argv[0] to
// "postgres: checkpointer" and similar, so only the postmaster itself has a
// bare postgres or postmaster binary as argv[0].
func ParsePostmasterArgs(argv []string) (Instance, bool) {
	if len(argv) == 0 {
		return Instance{}, false
	}
	switch path.Base(argv[0]) {
	case "postgres", "postmaster":
	default:
		return Instance{}, false
	}

	inst := Instance{Settings: map[string]string{}}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if strings.HasPrefix(arg, "--") {
			if name, value, ok := strings.Cut(arg[2:], "="); ok {
				inst.setSetting(name, value)
			}
			continue
		}
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		opt := arg[1]
		if !strings.ContainsRune(postmasterArgOptions, rune(opt)) {
			continue
		}
		value := arg[2:]
		if value == "" {
			if i+1 >= len(argv) {
				break
			}
			i++
			value = argv[i]
		}
		switch opt {
		case 'D':
			inst.DataDir = path.Clean(value)
		case 'p':
			inst.Settings["port"] = value
		case 'c':
			if name, v, ok := strings.Cut(value, "="); ok {
				inst.setSetting(name, v)
			}
		}
	}
	return inst, true
}

func (i *Instance) setSetting(name, value string) {
	name = strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	i.Settings[name] = value
}

// Unit is one service block of `systemctl show -p Id -p Environment -p
// EnvironmentFiles -p ExecStart` output.
type Unit struct {
	ID          string
	Environment map[string]string
	// EnvironmentFiles are the unit's EnvironmentFile= paths. Their variables
	// are not in Environment until ApplyEnvironmentFile adds them.
	EnvironmentFiles []string
	// ExecStart is the argv of the first ExecStart= command, with ${VAR} and
	// $VAR references still unexpanded.
	ExecStart []string
	// Homes holds the home directories of the accounts a path in the unit's
	// environment names as ~user.
	Homes map[string]string
}

// ApplyEnvironmentFile adds the variables of one of the unit's environment
// files. As in systemd, they override Environment= whatever the order.
func (u *Unit) ApplyEnvironmentFile(content string) {
	if u.Environment == nil {
		u.Environment = map[string]string{}
	}
	for k, v := range systemd.ParseEnvFile(content) {
		u.Environment[k] = v
	}
}

// suseStartScript is what SUSE's postgresql.service runs. It reads the data
// directory from POSTGRES_DATADIR and the server options from
// POSTGRES_OPTIONS in /etc/sysconfig/postgresql, the unit's environment file,
// and starts `pg_ctl start -D $DATADIR -o "$POSTGRES_OPTIONS"`.
const suseStartScript = "postgresql-script"

// suseDefaultDataDir is the script's data directory when POSTGRES_DATADIR is
// unset.
const suseDefaultDataDir = "~postgres/data"

// IsSuseStartScript reports whether the unit starts the server through SUSE's
// start script, whose data directory may name the postgres home as ~postgres.
func (u Unit) IsSuseStartScript() bool {
	return len(u.ExecStart) > 0 && path.Base(u.ExecStart[0]) == suseStartScript
}

// suseScriptInstance returns the cluster SUSE's start script starts.
func suseScriptInstance(u Unit) (Instance, bool) {
	dir := u.Environment["POSTGRES_DATADIR"]
	if dir == "" {
		dir = suseDefaultDataDir
	}
	// The script runs as User=postgres, so a bare ~ is its home too.
	dir, ok := expandHome(dir, "postgres", u.Homes)
	if !ok {
		return Instance{}, false
	}

	words, err := shellquote.Split(u.Environment["POSTGRES_OPTIONS"])
	if err != nil {
		return Instance{}, false
	}
	// pg_ctl passes -D before the options, so a -D among them wins, as it
	// does for postgres
	inst, _ := ParsePostmasterArgs(append([]string{"postgres", "-D", dir}, words...))
	inst.Env = map[string]string{}
	for k, v := range u.Environment {
		inst.Env[k] = v
	}
	return inst, true
}

// expandHome resolves a leading ~ or ~user the way the shell does, from the
// given home directories. A bare ~ is the home of self. It reports false when
// the home is not known.
func expandHome(p, self string, homes map[string]string) (string, bool) {
	if !strings.HasPrefix(p, "~") {
		return p, true
	}
	user, rest, _ := strings.Cut(p[1:], "/")
	if user == "" {
		user = self
	}
	home := homes[user]
	if home == "" {
		return "", false
	}
	return path.Join(home, rest), true
}

// ParseSystemctlShow splits `systemctl show` output for several units into
// one Unit per block. Blocks are separated by a blank line.
func ParseSystemctlShow(out string) []Unit {
	var units []Unit
	cur := Unit{Environment: map[string]string{}}
	seen := false
	flush := func() {
		if seen {
			units = append(units, cur)
		}
		cur = Unit{Environment: map[string]string{}}
		seen = false
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		seen = true
		switch key {
		case "Id":
			cur.ID = value
		case "Environment":
			for _, kv := range splitShellWords(value) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					cur.Environment[k] = v
				}
			}
		case "EnvironmentFiles":
			// one line per file: "/etc/sysconfig/postgresql (ignore_errors=yes)"
			if f, _, _ := strings.Cut(value, " ("); f != "" {
				cur.EnvironmentFiles = append(cur.EnvironmentFiles, f)
			}
		case "ExecStart":
			if cur.ExecStart == nil {
				cur.ExecStart = execStartArgv(value)
			}
		}
	}
	flush()
	return units
}

// execStartArgv pulls argv out of systemd's ExecStart property, which reads
// `{ path=/usr/bin/pg_ctl ; argv[]=/usr/bin/pg_ctl start -D ${PGDATA} ; ... }`.
// systemd prints argv joined by spaces with the original quoting gone.
func execStartArgv(value string) []string {
	_, rest, ok := strings.Cut(value, "argv[]=")
	if !ok {
		return nil
	}
	if end := strings.Index(rest, " ;"); end >= 0 {
		rest = rest[:end]
	}
	return strings.Fields(rest)
}

// splitShellWords splits systemd's Environment property into its
// assignments. An assignment holding spaces is double-quoted.
func splitShellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inQuote, inWord := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == '"':
			inQuote = !inQuote
			inWord = true
		case (c == ' ' || c == '\t') && !inQuote:
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// UnitInstance returns the cluster a systemd unit starts. The data directory
// is PGDATA from the unit's environment, or the -D argument of ExecStart. A
// port the unit forces on the command line is a setting: RHEL 7's unit runs
// `pg_ctl start -D ${PGDATA} -o "-p ${PGPORT}"`, which overrides the port in
// postgresql.conf. It reports false for units that name no data directory,
// such as Debian's pg_ctlcluster wrappers. SUSE's unit runs a start script
// configured from its environment file instead (see suseScriptInstance).
func UnitInstance(u Unit) (Instance, bool) {
	if u.IsSuseStartScript() {
		return suseScriptInstance(u)
	}

	argv := make([]string, len(u.ExecStart))
	for i, a := range u.ExecStart {
		argv[i] = expandEnv(a, u.Environment)
	}

	inst := Instance{Settings: map[string]string{}, Env: map[string]string{}}
	for k, v := range u.Environment {
		inst.Env[k] = v
	}
	if dir := u.Environment["PGDATA"]; dir != "" {
		inst.DataDir = path.Clean(dir)
	}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		switch {
		case arg == "-D" && next != "":
			if inst.DataDir == "" {
				inst.DataDir = path.Clean(next)
			}
			i++
		case arg == "-p" && isPort(next):
			// pg_ctl's own -p names the postgres binary, so only a
			// numeric value is a server port (from -o "-p N").
			inst.Settings["port"] = next
			i++
		case strings.HasPrefix(arg, "-p") && isPort(arg[2:]):
			inst.Settings["port"] = arg[2:]
		case arg == "-c" && strings.HasPrefix(next, "port="):
			inst.Settings["port"] = strings.TrimPrefix(next, "port=")
			i++
		case strings.HasPrefix(arg, "--port="):
			inst.Settings["port"] = strings.TrimPrefix(arg, "--port=")
		}
	}

	if inst.DataDir == "" {
		return Instance{}, false
	}
	return inst, true
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536
}

// expandEnv replaces ${VAR} and $VAR the way systemd expands ExecStart
// arguments. Unknown variables expand to nothing.
func expandEnv(s string, env map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(env[s[i+2:i+2+end]])
			i += 2 + end
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '_' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		if j == i+1 {
			b.WriteByte('$')
			continue
		}
		b.WriteString(env[s[i+1:j]])
		i = j - 1
	}
	return b.String()
}

// EffectivePort returns the port the server listens on, in PostgreSQL's
// precedence: a port given on the command line, then port in
// postgresql.conf, then PGPORT from the server's environment, then 5432. A
// value that is not a number reads as the 5432 default, as it always has.
// inst may be nil when no instance is known for the config file.
func EffectivePort(confPort string, inst *Instance) int64 {
	candidates := []string{}
	if inst != nil {
		candidates = append(candidates, inst.Settings["port"])
	}
	candidates = append(candidates, confPort)
	if inst != nil {
		candidates = append(candidates, inst.Env["PGPORT"])
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(c), 10, 64)
		if err != nil {
			return 5432
		}
		return n
	}
	return 5432
}

// InstanceFor returns what the host says about the server that loads the
// postgresql.conf at confPath, or nil when nothing does. A running
// postmaster's command line is what is in effect, so its settings win over
// the unit's ExecStart. The environment only comes from the unit, since a
// running process's environment is not readable without root.
func InstanceFor(confPath string, running, units []Instance) *Instance {
	confPath = path.Clean(confPath)
	var out *Instance
	for _, inst := range running {
		if inst.ConfigFile() == confPath {
			inst := inst
			out = &inst
			break
		}
	}
	for _, u := range units {
		if u.ConfigFile() != confPath {
			continue
		}
		if out == nil {
			u := u
			return &u
		}
		out.Env = u.Env
		break
	}
	return out
}

// DataDirectory returns the data directory of the server that loads the
// postgresql.conf at confPath: data_directory when set (relative to the
// file's directory), otherwise the directory holding postgresql.conf.
func DataDirectory(confPath string, params map[string]string) string {
	confDir := path.Dir(confPath)
	dd := params["data_directory"]
	if dd == "" {
		return confDir
	}
	if path.IsAbs(dd) {
		return path.Clean(dd)
	}
	return path.Join(confDir, dd)
}

// AuxFilePath returns the pg_hba.conf or pg_ident.conf the server loads for
// the postgresql.conf at confPath: the value of param (hba_file, ident_file)
// when set, otherwise defaultName in the data directory. Relative paths
// resolve against the data directory, which is the server's working
// directory. The data directory is data_directory when set, otherwise the
// directory holding postgresql.conf.
func AuxFilePath(confPath string, params map[string]string, param, defaultName string) string {
	dataDir := DataDirectory(confPath, params)
	if v := params[param]; v != "" {
		if path.IsAbs(v) {
			return path.Clean(v)
		}
		return path.Join(dataDir, v)
	}
	return path.Join(dataDir, defaultName)
}

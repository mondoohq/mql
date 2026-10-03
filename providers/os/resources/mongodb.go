// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/providers/os/resources/mongodb"
	"go.mondoo.com/mql/providers/os/resources/systemd"
)

// ---------------------------------------------------------------------------
// mongodb
// ---------------------------------------------------------------------------

func (m *mqlMongodb) id() (string, error) {
	return "mongodb", nil
}

// version reads the server version from the installed binary.
//
// The banner mongod prints is assembled at runtime rather than stored in the
// binary, so this needs command execution and reports nothing over a transport
// that cannot run commands. mongodb.conf is unaffected, since it comes off the
// filesystem.
func (m *mqlMongodb) version() (string, error) {
	conn, ok := m.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	res, err := conn.RunCommand("mongod --version")
	if err != nil || res.ExitStatus != 0 {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	data, err := io.ReadAll(res.Stdout)
	if err != nil {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	version := mongodb.ParseVersion(string(data))
	if version == "" {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return version, nil
}

// ---------------------------------------------------------------------------
// mongodb.conf
// ---------------------------------------------------------------------------

// mongodbConfPaths lists the well-known paths the parser probes when no
// explicit `path` argument is given, in the order they are tried.
var mongodbConfPaths = []string{
	"/etc/mongod.conf",  // official MongoDB packages, both deb and rpm
	"/etc/mongodb.conf", // older Debian and Ubuntu distribution packages
	"/etc/mongo/mongod.conf",
	"/opt/homebrew/etc/mongod.conf", // Homebrew on Apple silicon
	"/usr/local/etc/mongod.conf",    // Homebrew on Intel
}

func initMongodbConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in mongodb.conf initialization, it must be a string")
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
		delete(args, "path")
	}
	return args, nil, nil
}

func (s *mqlMongodbConf) id() (string, error) {
	// A refusal to locate the file is reported on the fields, where its error
	// keeps its kind. Failing here would fail the resource's creation, and
	// that error reaches the caller as an unclassified RPC error.
	file := s.GetFile()
	if file.Error != nil || file.Data == nil {
		return "mongodb.conf", nil
	}
	return file.Data.Path.Data, nil
}

type mqlMongodbConfInternal struct {
	// launchArgs is the command line, without the program name, of the
	// mongod that named the configuration file, when file() found it from a
	// process or the unit. Empty for an explicit path.
	launchArgs []string
}

// mongodUnits are the systemd services that start mongod: mongod.service from
// MongoDB's packages and mongodb.service from Debian and Ubuntu's.
var mongodUnits = []string{"mongod.service", "mongodb.service"}

// mongodConfigPath returns the configuration file mongod is started with, from
// the -f or --config argument of the running service's process, then of any
// other running mongod (one started by hand, outside its unit), or else of the
// service's ExecStart= with its environment expanded. MongoDB's rpm unit runs
// `mongod $OPTIONS` and takes OPTIONS from /etc/sysconfig/mongod, so the file
// can be anywhere. It is empty when nothing names a file. otherPids are the
// pids of the mongod processes on the host (see mongodPids). The command line
// that named the file comes back with it: its other options override the
// file (see mongodb.ArgOverrides).
//
// A service process whose command line the scan cannot read, because /proc is
// mounted with hidepid and the scan does not run as root, is a refusal: the
// unit only says how the next start would run, not how the running server
// did. The error is returned when no readable process names a file, together
// with what the unit says, which is what v13 reported.
func mongodConfigPath(afs *afero.Afero, otherPids []string) (string, []string, error) {
	var refusal error
	seen := map[string]bool{}
	for _, unit := range mongodUnits {
		for _, pid := range systemd.ServicePids(afs, unit) {
			seen[pid] = true
			conf, argv, err := mongodConfigOfPid(afs, pid)
			if err != nil {
				if refusal == nil && (errors.Is(err, fs.ErrPermission) || (errors.Is(err, fs.ErrNotExist) && procHidesPids(afs))) {
					refusal = err
				}
				continue
			}
			if conf != "" {
				return conf, argv, nil
			}
		}
	}

	for _, pid := range otherPids {
		if seen[pid] {
			continue
		}
		if conf, argv, err := mongodConfigOfPid(afs, pid); err == nil && conf != "" {
			return conf, argv, nil
		}
	}

	for _, unit := range mongodUnits {
		env, ok := systemd.ResolveUnitEnv(afs, unit)
		if !ok || env.ExecStart == "" {
			continue
		}
		argv := haproxy.ExpandSystemdCommand(env.ExecStart, env.Vars)
		if len(argv) == 0 {
			continue
		}
		if conf := mongodb.ConfigFromArgs(argv[1:]); conf != "" {
			return conf, argv[1:], refusal
		}
	}
	return "", nil, refusal
}

// mongodConfigOfPid returns the configuration file the mongod process pid was
// started with, and its arguments, empty when the process is not mongod or
// names no file.
func mongodConfigOfPid(afs *afero.Afero, pid string) (string, []string, error) {
	raw, err := afs.ReadFile(path.Join("/proc", pid, "cmdline"))
	if err != nil {
		return "", nil, err
	}
	argv := haproxy.SplitProcCmdline(raw)
	if len(argv) == 0 || path.Base(argv[0]) != "mongod" {
		return "", nil, nil
	}
	return mongodb.ConfigFromArgs(argv[1:]), argv[1:], nil
}

// procHidesPids reports whether /proc is mounted with hidepid, which hides
// other users' processes from a scan that does not run as root.
func procHidesPids(afs *afero.Afero) bool {
	raw, err := afs.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return procMountHidesPids(string(raw))
}

// procMountHidesPids reports whether the /proc entry of a mounts table sets
// hidepid to anything but 0 ("off"): 1 or "noaccess", 2 or "invisible", and 4
// or "ptraceable" all keep a process's command line from other users.
func procMountHidesPids(mounts string) bool {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "/proc" || fields[2] != "proc" {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if v, ok := strings.CutPrefix(opt, "hidepid="); ok {
				return v != "0" && v != "off"
			}
		}
	}
	return false
}

// mongodPidsCmd lists the processes named mongod. pgrep exits 1 when nothing
// matches.
const mongodPidsCmd = "pgrep -x mongod"

// mongodPids returns the pids of the running mongod processes. Where commands
// run, pgrep lists them; otherwise every /proc entry is a candidate, and
// mongodConfigOfPid skips those that are not mongod.
func mongodPids(runtime *plugin.Runtime, afs *afero.Afero) []string {
	conn := runtime.Connection.(shared.Connection)
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
			"command": llx.StringData(mongodPidsCmd),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			switch cmd.GetExitcode().Data {
			case 0:
				return strings.Fields(cmd.GetStdout().Data)
			case 1:
				return nil
			}
		}
	}
	entries, err := afs.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []string
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, e.Name())
		}
	}
	return pids
}

// file locates the configuration file. It is only reached when the resource
// was not initialized with an explicit path. The file mongod is started with
// comes first, then the well-known paths.
func (s *mqlMongodbConf) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	path, argv, err := mongodConfigPath(afs, mongodPids(s.MqlRuntime, afs))
	if err != nil && plugin.StructuredErrors() {
		return nil, llx.Forbidden(err)
	}
	if path != "" {
		s.launchArgs = argv
		// A file that does not exist would stop mongod from starting, so it
		// says nothing about the server; one this user cannot stat is still
		// the right file, and reading it reports the refusal.
		if _, err := afs.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	for _, path := range mongodbConfPaths {
		if ok, _ := afs.Exists(path); ok {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	// No configuration file anywhere, so MongoDB is most likely not
	// installed. Mark the field set and null so dependent fields report
	// empty instead of cascading a missing-file error.
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlMongodbConf) params(file *mqlFile) (any, error) {
	if file == nil {
		return map[string]any{}, nil
	}
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		return map[string]any{}, nil
	}

	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}

	cfg, err := mongodb.ParseConf(content.Data)
	if err != nil {
		return nil, err
	}
	// The options mongod was started with besides -f override the file.
	return mongodb.ApplyArgOverrides(cfg.Params, mongodb.ArgOverrides(s.launchArgs)), nil
}

// mongoParams narrows the dict the accessors depend on back to a tree.
//
// The comma-ok form is what keeps a malformed file from taking down the
// scan: the executor runs blocks in goroutines, so a failed bare type
// assertion here would be an unrecoverable panic rather than one bad field.
func mongoParams(params any) map[string]any {
	m, ok := params.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return m
}

// networking

func (s *mqlMongodbConf) port(params any) (int64, error) {
	return mongodb.Int(mongoParams(params), 27017, "net", "port"), nil
}

// bindIp resolves the addresses the server listens on.
//
// net.bindIpAll binds every interface whatever net.bindIp lists. When neither
// is set the server picks the addresses itself, and which ones depends on its
// version (see mongodb.DefaultBindIp). Without a version there is no way to
// tell a localhost-only server from one listening on every interface, so the
// field is null rather than a guess.
func (s *mqlMongodbConf) bindIp(params any) ([]any, error) {
	p := mongoParams(params)
	if addrs := mongodb.BindAddresses(p, ""); addrs != nil {
		return toAnySlice(addrs), nil
	}

	version, err := s.serverVersion()
	if err != nil {
		return nil, err
	}
	addrs := mongodb.BindAddresses(p, version)
	if addrs == nil {
		s.BindIp.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toAnySlice(addrs), nil
}

// serverVersion reads the installed server's version from the mongodb
// resource, empty when it could not be determined.
func (s *mqlMongodbConf) serverVersion() (string, error) {
	raw, err := CreateResource(s.MqlRuntime, "mongodb", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	version := raw.(*mqlMongodb).GetVersion()
	if version.Error != nil {
		return "", version.Error
	}
	return version.Data, nil
}

func (s *mqlMongodbConf) bindIpAll(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "net", "bindIpAll"), nil
}

func (s *mqlMongodbConf) ipv6(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "net", "ipv6"), nil
}

func (s *mqlMongodbConf) maxIncomingConnections(params any) (int64, error) {
	return mongodb.Int(mongoParams(params), 65536, "net", "maxIncomingConnections"), nil
}

func (s *mqlMongodbConf) unixDomainSocketEnabled(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), true, "net", "unixDomainSocket", "enabled"), nil
}

func (s *mqlMongodbConf) unixDomainSocketPathPrefix(params any) (string, error) {
	return mongodb.String(mongoParams(params), "net", "unixDomainSocket", "pathPrefix"), nil
}

// unixDomainSocketFilePermissions reports the socket mode as an octal string.
//
// The conventional 0700 spelling is an octal literal in YAML, so it decodes to
// a decimal number. Formatting it back keeps the value readable as the mode it
// denotes rather than as the 448 it decoded to.
func (s *mqlMongodbConf) unixDomainSocketFilePermissions(params any) (string, error) {
	p := mongoParams(params)
	path := []string{"net", "unixDomainSocket", "filePermissions"}

	v, ok := mongodb.Lookup(p, path...)
	if !ok || v == nil {
		return "", nil
	}
	if n, ok := v.(int64); ok {
		return fmt.Sprintf("%#o", n), nil
	}
	return mongodb.String(p, path...), nil
}

// TLS

func (s *mqlMongodbConf) tlsMode(params any) (string, error) {
	return mongodb.TLSMode(mongoParams(params)), nil
}

func (s *mqlMongodbConf) tlsCertificateKeyFile(params any) (string, error) {
	return mongodb.TLSString(mongoParams(params), "certificateKeyFile"), nil
}

func (s *mqlMongodbConf) tlsCaFile(params any) (string, error) {
	return mongodb.TLSString(mongoParams(params), "CAFile"), nil
}

func (s *mqlMongodbConf) tlsClusterFile(params any) (string, error) {
	return mongodb.TLSString(mongoParams(params), "clusterFile"), nil
}

func (s *mqlMongodbConf) tlsClusterCaFile(params any) (string, error) {
	return mongodb.TLSString(mongoParams(params), "clusterCAFile"), nil
}

func (s *mqlMongodbConf) tlsCrlFile(params any) (string, error) {
	return mongodb.TLSString(mongoParams(params), "CRLFile"), nil
}

func (s *mqlMongodbConf) tlsAllowConnectionsWithoutCertificates(params any) (bool, error) {
	return mongodb.TLSBool(mongoParams(params), false, "allowConnectionsWithoutCertificates"), nil
}

func (s *mqlMongodbConf) tlsAllowInvalidCertificates(params any) (bool, error) {
	return mongodb.TLSBool(mongoParams(params), false, "allowInvalidCertificates"), nil
}

func (s *mqlMongodbConf) tlsAllowInvalidHostnames(params any) (bool, error) {
	return mongodb.TLSBool(mongoParams(params), false, "allowInvalidHostnames"), nil
}

func (s *mqlMongodbConf) tlsDisabledProtocols(params any) ([]any, error) {
	return toAnySlice(mongodb.TLSList(mongoParams(params), "disabledProtocols")), nil
}

func (s *mqlMongodbConf) tlsFipsMode(params any) (bool, error) {
	return mongodb.TLSBool(mongoParams(params), false, "FIPSMode"), nil
}

func (s *mqlMongodbConf) certificate() ([]any, error) {
	path := s.GetTlsCertificateKeyFile()
	if path.Error != nil || path.Data == "" {
		return []any{}, nil
	}
	return readCertificatesFromPath(s.MqlRuntime, path.Data)
}

// authentication, authorization, and encryption at rest

func (s *mqlMongodbConf) authorization(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "authorization"), nil
}

func (s *mqlMongodbConf) keyFile(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "keyFile"), nil
}

func (s *mqlMongodbConf) clusterAuthMode(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "clusterAuthMode"), nil
}

// javascriptEnabled defaults to true, matching the server: an absent option
// leaves server-side JavaScript execution on.
func (s *mqlMongodbConf) javascriptEnabled(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), true, "security", "javascriptEnabled"), nil
}

func (s *mqlMongodbConf) redactClientLogData(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "security", "redactClientLogData"), nil
}

func (s *mqlMongodbConf) enableEncryption(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "security", "enableEncryption"), nil
}

func (s *mqlMongodbConf) encryptionKeyFile(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "encryptionKeyFile"), nil
}

func (s *mqlMongodbConf) encryptionCipherMode(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "encryptionCipherMode"), nil
}

func (s *mqlMongodbConf) ldapServers(params any) ([]any, error) {
	return toAnySlice(mongodb.List(mongoParams(params), "security", "ldap", "servers")), nil
}

func (s *mqlMongodbConf) ldapTransportSecurity(params any) (string, error) {
	return mongodb.String(mongoParams(params), "security", "ldap", "transportSecurity"), nil
}

// setParameter

func (s *mqlMongodbConf) setParameters(params any) (any, error) {
	v, ok := mongodb.Lookup(mongoParams(params), "setParameter")
	if !ok || v == nil {
		return map[string]any{}, nil
	}
	block, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}, nil
	}
	return block, nil
}

// enableLocalhostAuthBypass defaults to true, matching the server: an absent
// option leaves the bypass in place.
func (s *mqlMongodbConf) enableLocalhostAuthBypass(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), true, "setParameter", "enableLocalhostAuthBypass"), nil
}

// authenticationMechanisms reports the mechanisms the server accepts. When
// the option is unset that is the server default for the installed version,
// not an empty list: a server with no setting accepts SCRAM and X.509. It is
// null when the option is unset and the version cannot be read.
func (s *mqlMongodbConf) authenticationMechanisms(params any) ([]any, error) {
	p := mongoParams(params)
	if mechs := mongodb.List(p, "setParameter", "authenticationMechanisms"); len(mechs) > 0 {
		return toAnySlice(mechs), nil
	}

	version, err := s.serverVersion()
	if err != nil {
		return nil, err
	}
	mechs := mongodb.DefaultAuthenticationMechanisms(version, mongodb.TLSBool(p, false, "FIPSMode"))
	if mechs == nil {
		s.AuthenticationMechanisms.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toAnySlice(mechs), nil
}

// scramIterationCount reports the SCRAM-SHA-1 iteration count, 10000 when
// unset. It is null for a server too old to have SCRAM.
func (s *mqlMongodbConf) scramIterationCount(params any) (int64, error) {
	p := mongoParams(params)
	if _, ok := mongodb.Lookup(p, "setParameter", "scramIterationCount"); ok {
		return mongodb.Int(p, 10000, "setParameter", "scramIterationCount"), nil
	}

	version, err := s.serverVersion()
	if err != nil {
		return 0, err
	}
	n, ok := mongodb.DefaultScramIterationCount(version)
	if !ok {
		s.ScramIterationCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return n, nil
}

func (s *mqlMongodbConf) opensslCipherConfig(params any) (string, error) {
	return mongodb.String(mongoParams(params), "setParameter", "opensslCipherConfig"), nil
}

func (s *mqlMongodbConf) auditAuthorizationSuccess(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "setParameter", "auditAuthorizationSuccess"), nil
}

// audit log

func (s *mqlMongodbConf) auditLogDestination(params any) (string, error) {
	return mongodb.String(mongoParams(params), "auditLog", "destination"), nil
}

func (s *mqlMongodbConf) auditLogFormat(params any) (string, error) {
	return mongodb.String(mongoParams(params), "auditLog", "format"), nil
}

func (s *mqlMongodbConf) auditLogPath(params any) (string, error) {
	return mongodb.String(mongoParams(params), "auditLog", "path"), nil
}

func (s *mqlMongodbConf) auditLogFilter(params any) (string, error) {
	return mongodb.String(mongoParams(params), "auditLog", "filter"), nil
}

// system log

func (s *mqlMongodbConf) logDestination(params any) (string, error) {
	return mongodb.String(mongoParams(params), "systemLog", "destination"), nil
}

func (s *mqlMongodbConf) logPath(params any) (string, error) {
	return mongodb.String(mongoParams(params), "systemLog", "path"), nil
}

func (s *mqlMongodbConf) logAppend(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "systemLog", "logAppend"), nil
}

func (s *mqlMongodbConf) logRotate(params any) (string, error) {
	return mongodb.String(mongoParams(params), "systemLog", "logRotate"), nil
}

func (s *mqlMongodbConf) logVerbosity(params any) (int64, error) {
	return mongodb.Int(mongoParams(params), 0, "systemLog", "verbosity"), nil
}

func (s *mqlMongodbConf) quiet(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "systemLog", "quiet"), nil
}

// storage

func (s *mqlMongodbConf) dbPath(params any) (string, error) {
	return mongodb.String(mongoParams(params), "storage", "dbPath"), nil
}

func (s *mqlMongodbConf) storageEngine(params any) (string, error) {
	return mongodb.String(mongoParams(params), "storage", "engine"), nil
}

func (s *mqlMongodbConf) directoryPerDB(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "storage", "directoryPerDB"), nil
}

// process management

func (s *mqlMongodbConf) fork(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), false, "processManagement", "fork"), nil
}

func (s *mqlMongodbConf) pidFilePath(params any) (string, error) {
	return mongodb.String(mongoParams(params), "processManagement", "pidFilePath"), nil
}

// replication and sharding

func (s *mqlMongodbConf) replSetName(params any) (string, error) {
	return mongodb.String(mongoParams(params), "replication", "replSetName"), nil
}

func (s *mqlMongodbConf) oplogSizeMB(params any) (int64, error) {
	return mongodb.Int(mongoParams(params), 0, "replication", "oplogSizeMB"), nil
}

func (s *mqlMongodbConf) enableMajorityReadConcern(params any) (bool, error) {
	return mongodb.Bool(mongoParams(params), true, "replication", "enableMajorityReadConcern"), nil
}

func (s *mqlMongodbConf) clusterRole(params any) (string, error) {
	return mongodb.String(mongoParams(params), "sharding", "clusterRole"), nil
}

// query profiling

func (s *mqlMongodbConf) profilingMode(params any) (string, error) {
	return mongodb.String(mongoParams(params), "operationProfiling", "mode"), nil
}

func (s *mqlMongodbConf) slowOpThresholdMs(params any) (int64, error) {
	return mongodb.Int(mongoParams(params), 100, "operationProfiling", "slowOpThresholdMs"), nil
}

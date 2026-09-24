// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	stdpath "path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

type mqlAuditdConfigInternal struct {
	lock sync.Mutex
}

func initAuditdConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in auditd.config initialization, it must be a string")
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

const defaultAuditdConfig = "/etc/audit/auditd.conf"

func (s *mqlAuditdConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}

	return file.Data.Path.Data, nil
}

func (s *mqlAuditdConfig) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultAuditdConfig),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlAuditdConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if file == nil {
		return errors.New("no base auditd config file to read")
	}

	content, err := fileRequiredContent(file)
	if err != nil {
		return err
	}

	ini := parsers.ParseIni(content, "=")

	res := make(map[string]any, len(ini.Fields))
	s.Params.Data = res
	s.Params.State = plugin.StateIsSet

	if len(ini.Fields) == 0 {
		return nil
	}

	root := ini.Fields[""]
	if root == nil {
		s.Params.Error = errors.New("failed to parse auditd config")
		return s.Params.Error
	}

	fields, ok := root.(map[string]any)
	if !ok {
		s.Params.Error = errors.New("failed to parse auditd config (invalid data retrieved)")
		return s.Params.Error
	}

	normalized, err := normalizeAuditdConfigFields(fields)
	maps.Copy(res, normalized)
	s.Params.Error = err
	return err
}

// normalizeAuditdConfigFields lowercases the keys of the parsed auditd config,
// downcases the values of boolean/enum keywords, and reports any field whose
// value is not a string.
func normalizeAuditdConfigFields(fields map[string]any) (map[string]any, error) {
	res := make(map[string]any, len(fields))
	var errs multierr.Errors
	for k, v := range fields {
		key := strings.ToLower(k)
		s, ok := v.(string)
		if !ok {
			errs.Add(fmt.Errorf("can't parse field '%s', value is %+v", k, v))
			continue
		}
		if slices.Contains(auditdDowncaseKeywords, key) {
			res[key] = strings.ToLower(s)
		} else {
			res[key] = s
		}
	}
	return res, errs.Deduplicate()
}

func (s *mqlAuditdConfig) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

// The defaults below are auditd's own, from clear_config() in
// src/auditd-config.c (unchanged from audit 2.8 through 4.x). They apply when
// a key is absent and differ from the values in the auditd.conf that
// distributions ship.

func (s *mqlAuditdConfig) maxLogFile(params map[string]any) (int64, error) {
	return auditdConfigInt(params, "max_log_file", 0)
}

func (s *mqlAuditdConfig) numLogs(params map[string]any) (int64, error) {
	return auditdConfigInt(params, "num_logs", 0)
}

func (s *mqlAuditdConfig) maxLogFileAction(params map[string]any) (string, error) {
	return auditdConfigString(params, "max_log_file_action", "ignore"), nil
}

func (s *mqlAuditdConfig) spaceLeftAction(params map[string]any) (string, error) {
	return auditdConfigString(params, "space_left_action", "ignore"), nil
}

func (s *mqlAuditdConfig) adminSpaceLeftAction(params map[string]any) (string, error) {
	return auditdConfigString(params, "admin_space_left_action", "ignore"), nil
}

func (s *mqlAuditdConfig) diskFullAction(params map[string]any) (string, error) {
	return auditdConfigString(params, "disk_full_action", "ignore"), nil
}

func (s *mqlAuditdConfig) diskErrorAction(params map[string]any) (string, error) {
	return auditdConfigString(params, "disk_error_action", "syslog"), nil
}

func (s *mqlAuditdConfig) actionMailAcct(params map[string]any) (string, error) {
	return auditdConfigString(params, "action_mail_acct", "root"), nil
}

func auditdConfigString(params map[string]any, key string, def string) string {
	v, _ := params[key].(string)
	if v == "" {
		return def
	}
	return v
}

func auditdConfigInt(params map[string]any, key string, def int64) (int64, error) {
	v, _ := params[key].(string)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("auditd config %s is not a number: %q", key, v)
	}
	return n, nil
}

var auditdDowncaseKeywords = []string{
	"local_events",
	"write_logs",
	"log_format",
	"flush",
	"max_log_file_action",
	"verify_email",
	"space_left_action",
	"admin_space_left_action",
	"disk_full_action",
	"disk_error_action",
	"use_libwrap",
	"enable_krb5",
	"overflow_action",
}

type mqlAuditdRulesInternal struct {
	lock      sync.Mutex
	loaded    bool
	loadError error
}

const (
	defaultAuditdRulesDir  = "/etc/audit/rules.d"
	defaultAuditdRulesFile = "/etc/audit/audit.rules"
)

func (s *mqlAuditdRules) id() (string, error) {
	return s.Path.Data, nil
}

// path resolves the ruleset the way the audit service loads it: augenrules
// builds audit.rules from rules.d, and leaves an existing audit.rules alone
// when rules.d has no *.rules files.
func (s *mqlAuditdRules) path() (string, error) {
	files, err := auditdRuleFiles(s.MqlRuntime, defaultAuditdRulesDir)
	if err != nil {
		return "", err
	}
	if len(files) > 0 {
		return defaultAuditdRulesDir, nil
	}

	files, err = auditdRuleFiles(s.MqlRuntime, defaultAuditdRulesFile)
	if err != nil {
		return "", err
	}
	if len(files) > 0 {
		return defaultAuditdRulesFile, nil
	}

	return defaultAuditdRulesDir, nil
}

// auditdRuleFiles returns the rule files at path. For a directory these are
// the top-level *.rules files in natural sort order, which is what augenrules
// reads. A missing path has no rule files.
func auditdRuleFiles(runtime *plugin.Runtime, path string) ([]*mqlFile, error) {
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	f := raw.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, nil
	}

	perm := f.GetPermissions()
	if perm.Error != nil {
		return nil, perm.Error
	}
	if !perm.Data.IsDirectory.Data {
		return []*mqlFile{f}, nil
	}

	conn := runtime.Connection.(shared.Connection)
	entries, err := afero.ReadDir(conn.FileSystem(), path)
	if err != nil {
		return nil, err
	}

	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".rules") {
			continue
		}
		names = append(names, name)
	}
	slices.SortFunc(names, naturalCompare)

	res := make([]*mqlFile, 0, len(names))
	for _, name := range names {
		raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(stdpath.Join(path, name)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, raw.(*mqlFile))
	}
	return res, nil
}

// naturalCompare orders file names the way `sort -V` does for them: runs of
// digits compare by value, so 9-a.rules sorts before 10-b.rules.
func naturalCompare(a, b string) int {
	x, y := a, b
	for x != "" && y != "" {
		xDigit, yDigit := isASCIIDigit(x[0]), isASCIIDigit(y[0])
		if xDigit != yDigit {
			return strings.Compare(x, y)
		}

		xRun, xRest := splitDigitRun(x, xDigit)
		yRun, yRest := splitDigitRun(y, yDigit)
		var c int
		if xDigit {
			xNum, yNum := strings.TrimLeft(xRun, "0"), strings.TrimLeft(yRun, "0")
			c = cmp.Compare(len(xNum), len(yNum))
			if c == 0 {
				c = strings.Compare(xNum, yNum)
			}
		} else {
			c = strings.Compare(xRun, yRun)
		}
		if c != 0 {
			return c
		}
		x, y = xRest, yRest
	}
	if c := cmp.Compare(len(x), len(y)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func splitDigitRun(s string, digits bool) (string, string) {
	i := 0
	for i < len(s) && isASCIIDigit(s[i]) == digits {
		i++
	}
	return s[:i], s[i:]
}

func (s *mqlAuditdRules) setEmptyRules() {
	s.Controls = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Files = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Syscalls = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Watches = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Immutable = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
}

func (s *mqlAuditdRules) setLoadError(err error) {
	s.Controls = plugin.TValue[[]any]{State: plugin.StateIsSet, Error: err}
	s.Files = plugin.TValue[[]any]{State: plugin.StateIsSet, Error: err}
	s.Syscalls = plugin.TValue[[]any]{State: plugin.StateIsSet, Error: err}
	s.Watches = plugin.TValue[[]any]{State: plugin.StateIsSet, Error: err}
	s.Exists = plugin.TValue[bool]{State: plugin.StateIsSet, Error: err}
	s.Immutable = plugin.TValue[bool]{State: plugin.StateIsSet, Error: err}
}

func (s *mqlAuditdRules) load(path string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.loaded {
		return s.loadError
	}

	if path == "" {
		return errors.New("the path must be non-empty to parse auditd rules")
	}

	files, err := auditdRuleFiles(s.MqlRuntime, path)
	if err != nil {
		s.setLoadError(err)
		return err
	}

	s.Exists = plugin.TValue[bool]{Data: len(files) > 0, State: plugin.StateIsSet}
	if len(files) == 0 {
		s.setEmptyRules()
		s.loaded = true
		return nil
	}

	var errors multierr.Errors
	for _, file := range files {
		content := file.GetContent()
		if content.Error != nil {
			s.setLoadError(content.Error)
			return content.Error
		}

		s.parse(content.Data, &errors)
	}

	singleFile := len(files) == 1 && files[0].Path.Data == path
	s.Immutable = plugin.TValue[bool]{Data: auditdImmutable(s.Controls.Data, singleFile), State: plugin.StateIsSet}

	// Set state after all parsing is complete. Setting state inside parse()
	// creates a race: concurrent GetOrCompute callers see IsSet()==true while
	// data is still being appended, returning partially populated slices.
	s.Syscalls.State = plugin.StateIsSet
	s.Files.State = plugin.StateIsSet
	s.Controls.State = plugin.StateIsSet
	s.Watches.State = plugin.StateIsSet

	s.loadError = errors.Deduplicate()
	s.loaded = true
	return s.loadError
}

// auditdImmutable reports whether the -e controls lock the configuration.
// augenrules keeps only the last -e of a rules directory. A single rules file
// is applied in order, and the kernel rejects every change after -e 2.
func auditdImmutable(controls []any, singleFile bool) bool {
	immutable := false
	for _, raw := range controls {
		c := raw.(*mqlAuditdRuleControl)
		if c.Flag.Data != "-e" {
			continue
		}
		if singleFile {
			if c.Value.Data == "2" {
				return true
			}
			continue
		}
		immutable = c.Value.Data == "2"
	}
	return immutable
}

func isAuditdSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

func parseKeyVal(line string) (string, string, int) {
	i := 0
	skipToken := func() {
		for i < len(line) && !isAuditdSpace(line[i]) {
			i++
		}
	}
	skipSpace := func() {
		for i < len(line) && isAuditdSpace(line[i]) {
			i++
		}
	}

	// invalid prefix
	if line[0] != '-' {
		skipToken()
		skipSpace()
		return "", "", i
	}

	if len(line) < 2 {
		return "", "", len(line)
	}
	if line[1] == '-' {
		i = 2
	} else {
		i = 1
	}

	skipToken()
	if i == len(line) {
		return line, "", i
	}
	keyend := i

	skipSpace()
	valstart := i
	skipToken()
	valend := i
	skipSpace()

	return line[:keyend], line[valstart:valend], i
}

// Make sure this regex matches the most complete form first (ie >=) before
// matching the shorter forms (ie =)
var reOperator = regexp.MustCompile(`(!=|<=|>=|=|>|<)`)

func (s *mqlAuditdRules) parse(content string, errors *multierr.Errors) {
	lines := strings.Split(content, "\n")
	for _, rawline := range lines {
		line := strings.TrimSpace(rawline)
		if line == "" || line[0] == '#' {
			continue
		}

		resourceName := "auditd.rule.control"
		args := map[string]*llx.RawData{}
		rawFields := []string{}
		rawComparisons := []string{}
		syscalls := []any{}
		other := [][2]string{}

		for line != "" {
			k, v, idx := parseKeyVal(line)
			line = line[idx:]

			switch k {
			case "-a", "-A":
				// -A prepends the rule instead of appending it
				resourceName = "auditd.rule.syscall"
				action, list := splitAuditdRuleAction(v)
				args["action"] = llx.StringData(action)
				args["list"] = llx.StringData(list)

			case "-F":
				rawFields = append(rawFields, v)
				// auditctl treats -F key= exactly like -k
				if key, ok := strings.CutPrefix(v, "key="); ok {
					args["keyname"] = llx.StringData(key)
				}

			case "-C":
				rawComparisons = append(rawComparisons, v)

			case "-w":
				resourceName = "auditd.rule.file"
				args["path"] = llx.StringData(v)

			case "-k":
				args["keyname"] = llx.StringData(v)
				// -k is shorthand for -F key=; normalize into fields so queries
				// don't need to check both representations.
				rawFields = append(rawFields, "key="+v)

			case "-p":
				args["permissions"] = llx.StringData(v)

			case "-S":
				// -S accepts a comma-separated list of syscalls (and may be
				// repeated); store each syscall individually so policies can
				// match them as a flat list.
				for _, sc := range strings.Split(v, ",") {
					if sc != "" {
						syscalls = append(syscalls, sc)
					}
				}

			default:
				other = append(other, [2]string{k, v})
			}
		}

		switch resourceName {
		case "auditd.rule.file":
			if _, ok := args["keyname"]; !ok {
				args["keyname"] = llx.StringData("")
			}

			r, err := CreateResource(s.MqlRuntime, resourceName, args)
			if err != nil {
				errors.Add(err)
				continue
			}
			s.Files.Data = append(s.Files.Data, r)

			// a watch without -p fires on every access type, as in auditctl
			perm := "rwxa"
			if p, ok := args["permissions"]; ok {
				perm, _ = p.Value.(string)
			}
			path, _ := args["path"].Value.(string)
			keyname, _ := args["keyname"].Value.(string)
			s.addWatch("watch", path, perm, keyname, errors)

		case "auditd.rule.syscall":
			args["syscalls"] = llx.ArrayData(syscalls, types.String)

			fields := make([]any, len(rawFields))
			for i, raw := range rawFields {
				op := reOperator.FindString(raw)
				if op == "" {
					fields[i] = map[string]any{"key": raw}
					continue
				}
				// it must exist according to the preceding statement
				idx := strings.Index(raw, op)
				fields[i] = map[string]any{
					"key":   raw[0:idx],
					"op":    raw[idx : idx+len(op)],
					"value": raw[idx+len(op):],
				}
			}
			args["fields"] = llx.ArrayData(fields, types.Dict)

			comparisons := make([]any, len(rawComparisons))
			for i, raw := range rawComparisons {
				op := reOperator.FindString(raw)
				if op == "" {
					comparisons[i] = map[string]any{"field1": raw}
					continue
				}
				idx := strings.Index(raw, op)
				comparisons[i] = map[string]any{
					"field1": raw[0:idx],
					"op":     raw[idx : idx+len(op)],
					"field2": raw[idx+len(op):],
				}
			}
			args["comparisons"] = llx.ArrayData(comparisons, types.Dict)

			// Derive convenience accessors from the parsed -F fields so policies
			// can match the common arch/auid filters directly instead of
			// re-implementing the key/op/value lookups in MQL.
			var arch string
			var auidMin *int64
			excludesUnsetAuid := false
			var watchType, watchPath, watchPerm string
			for _, raw := range fields {
				f, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				key, _ := f["key"].(string)
				op, _ := f["op"].(string)
				val, _ := f["value"].(string)
				switch key {
				case "arch":
					if op == "=" {
						arch = val
					}
				case "path", "dir":
					if op == "=" {
						watchType, watchPath = key, val
					}
				case "perm":
					if op == "=" {
						watchPerm = val
					}
				case "auid":
					switch op {
					case ">=", ">":
						// auidMin is the effective lower bound, so `auid>999`
						// (equivalent to `auid>=1000`) and `auid>=1000` both
						// report 1000.
						if n, err := strconv.ParseInt(val, 10, 64); err == nil {
							if op == ">" {
								n++
							}
							auidMin = &n
						}
					case "!=":
						// auid is unset for processes without a login UID;
						// the kernel reports it as the raw sentinels below.
						if val == "unset" || val == "4294967295" || val == "-1" {
							excludesUnsetAuid = true
						}
					}
				}
			}
			args["arch"] = llx.StringData(arch)
			args["auidMin"] = llx.IntDataPtr(auidMin)
			args["excludesUnsetAuid"] = llx.BoolData(excludesUnsetAuid)

			if _, ok := args["keyname"]; !ok {
				args["keyname"] = llx.StringData("")
			}

			r, err := CreateResource(s.MqlRuntime, resourceName, args)
			if err != nil {
				errors.Add(err)
				continue
			}
			s.Syscalls.Data = append(s.Syscalls.Data, r)

			// `-a always,exit -F path=X -F perm=P` is the syscall form of `-w X -p P`
			action, _ := args["action"].Value.(string)
			list, _ := args["list"].Value.(string)
			if action == "always" && list == "exit" && watchPath != "" && watchPerm != "" {
				keyname, _ := args["keyname"].Value.(string)
				s.addWatch(watchType, watchPath, watchPerm, keyname, errors)
			}

		default:
			for io := range other {
				r, err := CreateResource(s.MqlRuntime, resourceName, map[string]*llx.RawData{
					"flag":  llx.StringData(other[io][0]),
					"value": llx.StringData(other[io][1]),
				})
				if err != nil {
					errors.Add(err)
					continue
				}
				s.Controls.Data = append(s.Controls.Data, r)
			}
		}
	}
}

var auditdRuleActions = []string{"always", "never"}

// splitAuditdRuleAction splits the argument of -a into its action and list.
// auditctl accepts both `always,exit` and `exit,always`. A malformed argument
// without a comma yields an empty list.
func splitAuditdRuleAction(v string) (string, string) {
	first, second, _ := strings.Cut(v, ",")
	if !slices.Contains(auditdRuleActions, first) && slices.Contains(auditdRuleActions, second) {
		return second, first
	}
	return first, second
}

func (s *mqlAuditdRules) addWatch(watchType string, path string, perm string, keyname string, errors *multierr.Errors) {
	if trimmed := strings.TrimRight(path, "/"); trimmed != "" {
		path = trimmed
	}

	permissions := []any{}
	for _, p := range []string{"r", "w", "x", "a"} {
		if strings.Contains(perm, p) {
			permissions = append(permissions, p)
		}
	}

	r, err := CreateResource(s.MqlRuntime, "auditd.rule.watch", map[string]*llx.RawData{
		"path":        llx.StringData(path),
		"permissions": llx.ArrayData(permissions, types.String),
		"keyname":     llx.StringData(keyname),
		"type":        llx.StringData(watchType),
	})
	if err != nil {
		errors.Add(err)
		return
	}
	s.Watches.Data = append(s.Watches.Data, r)
}

func (s *mqlAuditdRules) exists(path string) (bool, error) {
	return false, s.load(path)
}

func (s *mqlAuditdRules) watches(path string) ([]any, error) {
	return nil, s.load(path)
}

func (s *mqlAuditdRules) immutable(path string) (bool, error) {
	return false, s.load(path)
}

func (s *mqlAuditdRules) controls(path string) ([]any, error) {
	return nil, s.load(path)
}

func (s *mqlAuditdRules) files(path string) ([]any, error) {
	return nil, s.load(path)
}

func (s *mqlAuditdRules) syscalls(path string) ([]any, error) {
	return nil, s.load(path)
}

func (s *mqlAuditdRuleFile) id() (string, error) {
	var f checksums.Fast
	return f.
		Add(s.Path.Data).
		Add(s.Permissions.Data).
		Add(s.Keyname.Data).
		String(), nil
}

func (s *mqlAuditdRuleWatch) id() (string, error) {
	var f checksums.Fast
	f = f.
		Add(s.Type.Data).
		Add(s.Path.Data).
		Add(s.Keyname.Data)
	for i := range s.Permissions.Data {
		f = f.Add(s.Permissions.Data[i].(string))
	}
	return f.String(), nil
}

func (s *mqlAuditdRuleControl) id() (string, error) {
	var f checksums.Fast
	return f.
		Add(s.Flag.Data).
		Add(s.Value.Data).
		String(), nil
}

func (s *mqlAuditdRuleSyscall) id() (string, error) {
	var f checksums.Fast
	f = f.
		Add(s.Action.Data).
		Add(s.List.Data).
		Add(s.Keyname.Data)
	for i := range s.Syscalls.Data {
		f = f.Add(s.Syscalls.Data[i].(string))
	}
	for i := range s.Fields.Data {
		c := s.Fields.Data[i].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(c)) {
			f = f.Add(k).Add(c[k].(string))
		}
	}
	for i := range s.Comparisons.Data {
		c := s.Comparisons.Data[i].(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(c)) {
			f = f.Add(k).Add(c[k].(string))
		}
	}

	return f.String(), nil
}

func (s *mqlAuditdStatus) id() (string, error) {
	return "auditd.status", nil
}

func initAuditdStatus(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn := runtime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil, errors.New("auditd.status runs auditctl, which this connection cannot do")
	}

	cmd, err := conn.RunCommand("auditctl -s")
	if err != nil {
		return nil, nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, nil, fmt.Errorf("auditctl -s failed: %s", strings.TrimSpace(string(stderr)))
	}
	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, nil, err
	}

	status, err := parseAuditctlStatus(string(stdout))
	if err != nil {
		return nil, nil, err
	}
	return map[string]*llx.RawData{
		"enabled":      llx.IntData(status["enabled"]),
		"failure":      llx.IntData(status["failure"]),
		"pid":          llx.IntData(status["pid"]),
		"rateLimit":    llx.IntData(status["rate_limit"]),
		"backlogLimit": llx.IntData(status["backlog_limit"]),
		"lost":         llx.IntData(status["lost"]),
		"backlog":      llx.IntData(status["backlog"]),
	}, nil, nil
}

// auditctl prints enabled and failure as words when run with -i
var auditctlStatusWords = map[string]map[string]int64{
	"enabled": {"disable": 0, "enabled": 1, "enabled+immutable": 2},
	"failure": {"silent": 0, "printk": 1, "panic": 2},
}

var auditctlStatusKeys = []string{"enabled", "failure", "pid", "rate_limit", "backlog_limit", "lost", "backlog"}

// parseAuditctlStatus reads the `key value` lines of `auditctl -s`.
func parseAuditctlStatus(out string) (map[string]int64, error) {
	res := map[string]int64{}
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !slices.Contains(auditctlStatusKeys, fields[0]) {
			continue
		}
		key, val := fields[0], fields[1]
		if n, ok := auditctlStatusWords[key][val]; ok {
			res[key] = n
			continue
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected auditctl -s value for %s: %q", key, val)
		}
		res[key] = n
	}

	for _, key := range auditctlStatusKeys {
		if _, ok := res[key]; !ok {
			return nil, fmt.Errorf("auditctl -s did not report %s", key)
		}
	}
	return res, nil
}

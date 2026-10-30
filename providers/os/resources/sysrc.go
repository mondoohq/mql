// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// sysrcPaths lists the rc.conf file paths to check on FreeBSD systems.
var sysrcPaths = []string{
	"/etc/rc.conf",
	"/etc/rc.conf.local",
	"/usr/local/etc/rc.conf",
}

// sysrcDirs lists the rc.conf.d directories to check on FreeBSD systems.
var sysrcDirs = []string{
	"/etc/rc.conf.d",
}

// sysrcDefaultsPaths are sourced by sysrc before any rc.conf file, in order.
// /etc/defaults/rc.conf sources vendor.conf at its end.
var sysrcDefaultsPaths = []string{
	"/etc/defaults/rc.conf",
	"/etc/defaults/vendor.conf",
}

// sysrcDefaultRcConfFiles is rc_conf_files as /etc/defaults/rc.conf sets it,
// used when the defaults file is missing.
const sysrcDefaultRcConfFiles = "/etc/rc.conf /etc/rc.conf.local"

type mqlSysrcInternal struct {
	// defaultLayout is set when files were discovered rather than passed as
	// a path, so values follows rc_conf_files instead of the given files.
	defaultLayout bool
}

func initSysrc(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' it must be a string")
		}

		files, err := getSortedPathFiles(runtime, path)
		if err != nil {
			return nil, nil, err
		}
		args["files"] = llx.ArrayData(files, types.Resource("file"))
		delete(args, "path")
	}

	return args, nil, nil
}

func (s *mqlSysrc) id() (string, error) {
	if len(s.Files.Data) == 0 {
		return "sysrc", nil
	}
	checksum := checksums.New
	for i := range s.Files.Data {
		path := s.Files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}
	return checksum.String(), nil
}

func (s *mqlSysrcEntry) id() (string, error) {
	return s.File.Data + ":" + s.Name.Data, nil
}

// files returns the list of rc.conf configuration files
func (s *mqlSysrc) files() ([]any, error) {
	s.defaultLayout = true

	var allFiles []any
	var errs []error

	for _, path := range sysrcPaths {
		s.collectFile(path, &allFiles, &errs)
	}

	for _, dir := range sysrcDirs {
		s.collectDir(dir, &allFiles, &errs)
	}

	if len(errs) > 0 {
		return allFiles, errors.Join(errs...)
	}

	return allFiles, nil
}

// collectFile adds a single file to the list if it exists
func (s *mqlSysrc) collectFile(path string, allFiles *[]any, errs *[]error) {
	fileRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to create file resource for %s: %w", path, err))
		return
	}
	f := fileRes.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to check if %s exists: %w", path, exists.Error))
		return
	}

	if !exists.Data {
		return
	}

	*allFiles = append(*allFiles, f)
}

// collectDir adds all files from a directory to the list
func (s *mqlSysrc) collectDir(dirPath string, allFiles *[]any, errs *[]error) {
	dirRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(dirPath),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to create file resource for directory %s: %w", dirPath, err))
		return
	}
	dir := dirRes.(*mqlFile)
	dirExists := dir.GetExists()
	if dirExists.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to check if directory %s exists: %w", dirPath, dirExists.Error))
		return
	}

	if !dirExists.Data {
		return
	}

	files, err := CreateResource(s.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from": llx.StringData(dirPath),
		"type": llx.StringData("file"),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to list files in %s: %w", dirPath, err))
		return
	}

	ff := files.(*mqlFilesFind)
	list := ff.GetList()
	if list.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to get file list from %s: %w", dirPath, list.Error))
		return
	}

	for i := range list.Data {
		file := list.Data[i].(*mqlFile)
		*allFiles = append(*allFiles, file)
	}
}

// content aggregates the content from all rc.conf files
func (s *mqlSysrc) content(files []any) (string, error) {
	var res strings.Builder
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		res.WriteString(content.Data)
		res.WriteString("\n")
	}

	if len(errs) > 0 {
		return res.String(), errors.Join(errs...)
	}

	return res.String(), nil
}

// entries parses all rc.conf files and returns key-value entries
func (s *mqlSysrc) entries(files []any) ([]any, error) {
	var allEntries []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		entries, err := parseSysrcEntries(s.MqlRuntime, file.Path.Data, content.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse %s: %w", file.Path.Data, err))
			continue
		}

		allEntries = append(allEntries, entries...)
	}

	if len(errs) > 0 {
		return allEntries, errors.Join(errs...)
	}

	return allEntries, nil
}

// SysrcEntry represents a parsed rc.conf variable assignment.
type SysrcEntry struct {
	Name  string
	Value string
}

// ParseSysrc parses rc.conf content and returns key-value entries.
// rc.conf files use shell variable assignment syntax: key="value" or key=value,
// optionally followed by a comment. When the same variable is assigned
// multiple times, only the last assignment is kept, matching real sysrc
// semantics. Assignments inside if/case blocks or function bodies are
// skipped, since they only take effect when the shell evaluates them.
func ParseSysrc(content string) []SysrcEntry {
	// Use ordered deduplication: track insertion order but let later values win
	seen := map[string]int{} // name -> index in entries
	var entries []SysrcEntry

	for _, a := range parseSysrcAssignments(content) {
		value, _ := parseShellWord(a.word, nil)
		if idx, ok := seen[a.name]; ok {
			if a.applies(entries[idx].Value, true) {
				// Update existing entry in place (last assignment wins)
				entries[idx].Value = value
			}
		} else {
			seen[a.name] = len(entries)
			entries = append(entries, SysrcEntry{Name: a.name, Value: value})
		}
	}

	return entries
}

// sysrcAssignment is one assignment as written, before its value is evaluated.
type sysrcAssignment struct {
	name string
	// word is the unparsed value, starting right after `=`
	word string
	// cond is the operator of a `: ${name<cond>word}` default: ":=" assigns
	// when name is unset or empty, "=" only when it is unset. Empty for a
	// plain assignment.
	cond string
}

// applies reports whether the assignment takes effect given the variable's
// current value and whether it is set.
func (a sysrcAssignment) applies(current string, set bool) bool {
	switch a.cond {
	case ":=":
		return current == ""
	case "=":
		return !set
	default:
		return true
	}
}

// parseSysrcAssignments returns the top-level variable assignments in
// rc.conf content, in file order.
func parseSysrcAssignments(content string) []sysrcAssignment {
	var res []sysrcAssignment
	depth := 0

	for raw := range strings.Lines(content) {
		line := strings.TrimSpace(raw)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch sysrcBlockDelta(line) {
		case 1:
			depth++
			continue
		case -1:
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth > 0 {
			continue
		}

		// `: ${name:="value"}` sets a default, as /etc/defaults/rc.conf does
		// for _localbase, and `: ${name="value"}` sets one only when unset
		if strings.HasPrefix(line, ": ${") {
			end := matchingBrace(line[2:])
			n := shellNamePrefix(line[4:])
			if end < 0 || n == 0 {
				continue
			}
			name, rest := line[4:4+n], line[4+n:2+end]
			cond := ":="
			word, ok := strings.CutPrefix(rest, cond)
			if !ok {
				cond = "="
				word, ok = strings.CutPrefix(rest, cond)
			}
			if !ok {
				continue
			}
			if _, ok := parseShellWord(word, nil); ok {
				res = append(res, sysrcAssignment{name: name, word: word, cond: cond})
			}
			continue
		}

		// Parse key=value assignments
		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		name := before
		if !isShellName(name) {
			continue
		}
		word := after
		if _, ok := parseShellWord(word, nil); !ok {
			continue
		}
		res = append(res, sysrcAssignment{name: name, word: word})
	}

	return res
}

// sysrcBlockDelta returns 1 for a line that opens a shell compound command,
// -1 for one that closes it, and 0 otherwise. Only the forms rc.conf files
// use are recognized: if/fi, case/esac, and brace-delimited function bodies.
func sysrcBlockDelta(line string) int {
	first := line
	if i := strings.IndexAny(line, " \t;"); i >= 0 {
		first = line[:i]
	}
	switch first {
	case "if", "case":
		// a one-line `if ...; then ...; fi` opens and closes itself
		if strings.HasSuffix(line, "fi") || strings.HasSuffix(line, "esac") {
			return 0
		}
		return 1
	case "fi", "esac", "}":
		return -1
	}
	if strings.HasSuffix(line, "{") && strings.Contains(line, "()") {
		return 1
	}
	return 0
}

// shellNamePrefix returns the length of the shell variable name at the start
// of s, or 0 if there is none.
func shellNamePrefix(s string) int {
	n := 0
	for n < len(s) && isShellName(s[:n+1]) {
		n++
	}
	return n
}

// matchingBrace returns the index of the `}` closing the `${` at the start of
// s, counting nested `${...}`, or -1 if it is never closed.
func matchingBrace(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			depth++
			i++
		case s[i] == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// isShellName reports whether s is a valid shell variable name.
func isShellName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// parseShellWord reads the value of an assignment the way sh reads one word:
// quoted and unquoted runs concatenate until unquoted whitespace or `;`, so
// a trailing comment is not part of the value. With a lookup, `$name` and
// `${name}` outside single quotes expand to the variable's value, along with
// the `${name:-word}` and `${name-word}` forms; without one they stay as
// written. It returns false when a quote is never closed.
func parseShellWord(s string, lookup func(name string) (string, bool)) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', ';':
			return b.String(), true
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				switch {
				case s[j] == '\\' && j+1 < len(s):
					j++
					b.WriteByte(s[j])
				case s[j] == '$' && lookup != nil:
					j += expandShellParam(&b, s[j:], lookup) - 1
				default:
					b.WriteByte(s[j])
				}
			}
			if j >= len(s) {
				return "", false
			}
			i = j
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '$':
			if lookup == nil {
				b.WriteByte(c)
				continue
			}
			i += expandShellParam(&b, s[i:], lookup) - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// expandShellParam expands the parameter reference at the start of s, which
// begins with `$`, into b and returns how many bytes of s it consumed. A form
// it does not recognize is written as is.
func expandShellParam(b *strings.Builder, s string, lookup func(name string) (string, bool)) int {
	if strings.HasPrefix(s, "${") {
		end := matchingBrace(s)
		if end < 0 {
			b.WriteByte('$')
			return 1
		}
		inner := s[2:end]
		n := shellNamePrefix(inner)
		name, op := inner[:n], inner[n:]
		value, set := lookup(name)
		switch {
		case n == 0:
			b.WriteString(s[:end+1])
		case op == "":
			b.WriteString(value)
		case strings.HasPrefix(op, ":-"), strings.HasPrefix(op, ":="):
			if value == "" {
				value, _ = parseShellWord(op[2:], lookup)
			}
			b.WriteString(value)
		case strings.HasPrefix(op, "-"), strings.HasPrefix(op, "="):
			if !set {
				value, _ = parseShellWord(op[1:], lookup)
			}
			b.WriteString(value)
		default:
			b.WriteString(s[:end+1])
		}
		return end + 1
	}

	n := shellNamePrefix(s[1:])
	if n == 0 {
		b.WriteByte('$')
		return 1
	}
	value, _ := lookup(s[1 : n+1])
	b.WriteString(value)
	return n + 1
}

// ResolveSysrcValues returns the effective value of every variable the way
// `sysrc -n` computes it (f_sysrc_get and source_rc_confs in FreeBSD): the
// defaults files, then each file in rc_conf_files sourced once, with a second
// pass that picks up files added by a redefined rc_conf_files. When rcConfs
// is non-nil it replaces the rc_conf_files list, as `sysrc -f` does. read
// returns a file's content and whether it exists.
func ResolveSysrcValues(read func(path string) (string, bool, error), rcConfs []string) (map[string]string, error) {
	values := map[string]string{}
	lookup := func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
	apply := func(path string) (bool, error) {
		content, ok, err := read(path)
		if err != nil || !ok {
			return ok, err
		}
		for _, a := range parseSysrcAssignments(content) {
			if current, set := values[a.name]; !a.applies(current, set) {
				continue
			}
			values[a.name], _ = parseShellWord(a.word, lookup)
		}
		return true, nil
	}

	for _, path := range sysrcDefaultsPaths {
		if _, err := apply(path); err != nil {
			return nil, err
		}
	}

	// with -f, sysrc reports the defaults value of rc_conf_files unless one
	// of the files redefines it
	defaultsRcConfFiles, hasDefaults := values["rc_conf_files"]
	initial := defaultsRcConfFiles
	switch {
	case rcConfs != nil:
		initial = strings.Join(rcConfs, " ")
	case !hasDefaults:
		// read the stock files, but do not report a value no file sets
		initial = sysrcDefaultRcConfFiles
	}
	values["rc_conf_files"] = initial

	sourced := map[string]bool{}
	for range 2 {
		for path := range strings.FieldsSeq(values["rc_conf_files"]) {
			if sourced[path] {
				continue
			}
			sourced[path] = true
			if _, err := apply(path); err != nil {
				return nil, err
			}
		}
	}

	if values["rc_conf_files"] == initial {
		if hasDefaults {
			values["rc_conf_files"] = defaultsRcConfFiles
		} else {
			delete(values, "rc_conf_files")
		}
	}
	return values, nil
}

// values returns the effective value of every rc.conf variable
func (s *mqlSysrc) values(files []any) (map[string]any, error) {
	var rcConfs []string
	if !s.defaultLayout {
		rcConfs = make([]string, 0, len(files))
		for i := range files {
			rcConfs = append(rcConfs, files[i].(*mqlFile).Path.Data)
		}
	}

	resolved, err := ResolveSysrcValues(s.readFile, rcConfs)
	if err != nil {
		return nil, err
	}

	res := make(map[string]any, len(resolved))
	for k, v := range resolved {
		res[k] = v
	}
	return res, nil
}

// readFile returns a file's content and whether it exists. rc_conf_files is
// read from the target, so anything other than a regular file (a device such
// as /dev/zero, a FIFO) is treated as missing rather than read without end.
func (s *mqlSysrc) readFile(path string) (string, bool, error) {
	fileRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return "", false, err
	}
	f := fileRes.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return "", false, exists.Error
	}
	if !exists.Data {
		return "", false, nil
	}
	perm := f.GetPermissions()
	if perm.Error != nil {
		return "", false, perm.Error
	}
	if perm.Data == nil || !perm.Data.IsFile.Data {
		log.Debug().Str("path", path).Msg("sysrc> skipping rc.conf path that is not a regular file")
		return "", false, nil
	}
	content := f.GetContent()
	if content.Error != nil {
		return "", false, fmt.Errorf("failed to read %s: %w", path, content.Error)
	}
	return content.Data, true, nil
}

// parseSysrcEntries parses rc.conf content and creates MQL resources for each entry.
func parseSysrcEntries(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	parsed := ParseSysrc(content)
	var resources []any

	for _, entry := range parsed {
		resource, err := CreateResource(runtime, "sysrc.entry", map[string]*llx.RawData{
			"name":  llx.StringData(entry.Name),
			"value": llx.StringData(entry.Value),
			"file":  llx.StringData(filePath),
		})
		if err != nil {
			return nil, err
		}

		resources = append(resources, resource.(*mqlSysrcEntry))
	}

	return resources, nil
}

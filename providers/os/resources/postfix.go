// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kballard/go-shellquote"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	postfixMainCfName   = "main.cf"
	postfixMasterCfName = "master.cf"
)

// postfixConfigDirs holds the Postfix configuration directory for platforms
// whose package installs outside the usual /etc/postfix prefix — the BSDs
// build Postfix from ports/pkgsrc into their own tree. Everything else
// (Linux, macOS, Solaris) defaults to /etc/postfix. A non-default
// config_directory can still be targeted with postfix("/path/to/main.cf").
var postfixConfigDirs = map[string]string{
	"freebsd":      "/usr/local/etc/postfix",
	"dragonflybsd": "/usr/local/etc/postfix",
	"openbsd":      "/usr/local/etc/postfix",
	"netbsd":       "/usr/pkg/etc/postfix",
}

func postfixConfigDir(conn shared.Connection) string {
	if asset := conn.Asset(); asset != nil && asset.Platform != nil {
		if dir, ok := postfixConfigDirs[asset.Platform.Name]; ok {
			return dir
		}
	}
	return "/etc/postfix"
}

func (p *mqlPostfix) id() (string, error) {
	mainCf := p.GetMainCfPath()
	if mainCf.Error != nil {
		return "", mainCf.Error
	}
	return "postfix:" + mainCf.Data, nil
}

func initPostfix(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok && x != nil {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in postfix initialization, it must be a string")
		}
		args["mainCfPath"] = llx.StringData(path)
		delete(args, "path")
	}
	return args, nil, nil
}

func (p *mqlPostfix) mainCfPath() (string, error) {
	// only reached when no path was supplied via init
	conn := p.MqlRuntime.Connection.(shared.Connection)
	return filepath.Join(postfixConfigDir(conn), postfixMainCfName), nil
}

func (p *mqlPostfix) masterCfPath() (string, error) {
	mainCf := p.GetMainCfPath()
	if mainCf.Error != nil {
		return "", mainCf.Error
	}
	// master.cf lives alongside main.cf
	return filepath.Join(filepath.Dir(mainCf.Data), postfixMasterCfName), nil
}

// explicitMainCfExists returns an error when postfix(path) names a main.cf
// that does not exist, as snmpd.config and nginx.conf do; postconf then
// fails and the main.cf fallback reads nothing, which passed
// inetInterfaces.all(_ == "127.0.0.1"). A missing main.cf at the default
// location means postfix is not configured and reads as empty.
func (p *mqlPostfix) explicitMainCfExists() error {
	mainCf := p.GetMainCfPath()
	if mainCf.Error != nil {
		return mainCf.Error
	}
	conn := p.MqlRuntime.Connection.(shared.Connection)
	if mainCf.Data == filepath.Join(postfixConfigDir(conn), postfixMainCfName) {
		return nil
	}
	if _, err := conn.FileSystem().Stat(mainCf.Data); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("could not read %q: no such file", mainCf.Data)
	}
	return nil
}

func (p *mqlPostfix) params() (map[string]any, error) {
	if err := p.explicitMainCfExists(); err != nil {
		return nil, err
	}

	// prefer postconf: it reports effective values, including built-in defaults
	// for parameters that are not written to main.cf
	params, ok, err := p.postconfParams()
	if err != nil {
		return nil, err
	}
	if ok {
		return params, nil
	}

	// fall back to parsing main.cf directly (file values only)
	mainCf := p.GetMainCfPath()
	if mainCf.Error != nil {
		return nil, mainCf.Error
	}
	content, err := p.readFile(mainCf.Data)
	if err != nil {
		return nil, err
	}
	return parsePostfixMainCf(content), nil
}

// postconfParams runs `postconf` and returns the effective parameters. The
// second return is false (without an error) when postconf is unavailable or
// exits non-zero, signalling the caller to fall back to main.cf.
func (p *mqlPostfix) postconfParams() (map[string]any, bool, error) {
	mainCf := p.GetMainCfPath()
	if mainCf.Error != nil {
		return nil, false, mainCf.Error
	}
	// point postconf at the resolved config directory so a custom main.cf
	// location (postfix("/path/to/main.cf")) reads the matching config rather
	// than the system default
	command := shellquote.Join("postconf", "-c", filepath.Dir(mainCf.Data))
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(command),
	})
	if err != nil {
		return nil, false, err
	}
	cmd := o.(*mqlCommand)

	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, false, exit.Error
	}
	if exit.Data != 0 {
		// postconf missing or failed — let the caller parse main.cf instead
		return nil, false, nil
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, false, stdout.Error
	}
	return parsePostconf(stdout.Data), true, nil
}

func (p *mqlPostfix) inetInterfaces() ([]any, error) {
	params := p.GetParams()
	if params.Error != nil {
		return nil, params.Error
	}
	value, _ := params.Data["inet_interfaces"].(string)
	return splitPostfixList(value), nil
}

func (p *mqlPostfix) services() ([]any, error) {
	if err := p.explicitMainCfExists(); err != nil {
		return nil, err
	}
	masterCf := p.GetMasterCfPath()
	if masterCf.Error != nil {
		return nil, masterCf.Error
	}
	content, err := p.readFile(masterCf.Data)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, svc := range parseMasterCf(content) {
		o, err := CreateResource(p.MqlRuntime, "postfix.service", map[string]*llx.RawData{
			"service":      llx.StringData(svc.Service),
			"type":         llx.StringData(svc.Type),
			"private":      llx.StringData(svc.Private),
			"unprivileged": llx.StringData(svc.Unprivileged),
			"chroot":       llx.StringData(svc.Chroot),
			"wakeup":       llx.StringData(svc.Wakeup),
			"maxProcesses": llx.StringData(svc.MaxProcesses),
			"command":      llx.StringData(svc.Command),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// readFile reads a config file from the target's filesystem. A missing file
// yields empty content rather than an error, so an MTA that isn't fully
// configured resolves cleanly.
func (p *mqlPostfix) readFile(path string) (string, error) {
	conn := p.MqlRuntime.Connection.(shared.Connection)
	f, err := conn.FileSystem().Open(path)
	if err != nil {
		// the connection's virtual filesystem may not return *os.PathError,
		// so match the wrapped sentinel rather than using os.IsNotExist
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *mqlPostfixService) id() (string, error) {
	// service name + type is not unique on its own (e.g. two `smtp inet`
	// listeners on different addresses), so include the command to keep the
	// cache key distinct
	return s.Service.Data + "/" + s.Type.Data + "/" + s.Command.Data, nil
}

// parsePostconf parses `postconf` output (one `name = value` per line).
func parsePostconf(out string) map[string]any {
	params := map[string]any{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if key == "" {
			continue
		}
		params[key] = strings.TrimSpace(line[idx+1:])
	}
	return params
}

var postfixVarRe = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}|\$([a-zA-Z0-9_]+)`)

// parsePostfixMainCf parses a Postfix main.cf into effective-ish parameters:
// continuation lines (a line starting with whitespace continues the previous
// logical line) are folded, comments and blanks dropped, and `$name` /
// `${name}` references are interpolated against the file's own values. Built-in
// defaults are NOT known here — that needs postconf.
func parsePostfixMainCf(content string) map[string]any {
	logical := foldContinuationLines(content)

	raw := map[string]string{}
	order := make([]string, 0, len(logical))
	for _, line := range logical {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		if key == "" {
			continue
		}
		if _, seen := raw[key]; !seen {
			order = append(order, key)
		}
		raw[key] = strings.TrimSpace(trimmed[idx+1:])
	}

	// $name / ${name} references are expanded a single level against the
	// file's own values. Postfix expands recursively; full fidelity needs
	// postconf, which params() prefers when the binary is available.
	params := map[string]any{}
	for _, key := range order {
		params[key] = postfixVarRe.ReplaceAllStringFunc(raw[key], func(match string) string {
			sub := postfixVarRe.FindStringSubmatch(match)
			name := sub[1] // ${name}
			if name == "" {
				name = sub[2] // $name
			}
			if v, ok := raw[name]; ok {
				return v
			}
			return match
		})
	}
	return params
}

// foldContinuationLines joins lines that start with whitespace into the
// preceding logical line, matching how Postfix reads main.cf and master.cf
// (readllines in src/util/readlline.c, unchanged since at least 2.10).
// Comment lines (first non-blank character '#', indented or not) and blank
// lines are skipped without ending the logical line, so an indented line after
// them still continues it. Text that starts with whitespace before any logical
// line is discarded, as Postfix does with a warning.
func foldContinuationLines(content string) []string {
	var logical []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(logical) > 0 {
				logical[len(logical)-1] += " " + trimmed
			}
			continue
		}
		logical = append(logical, line)
	}
	return logical
}

// splitPostfixList splits a comma- and/or whitespace-separated Postfix value
// (such as inet_interfaces) into its individual tokens.
func splitPostfixList(value string) []any {
	res := []any{}
	for _, tok := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if tok != "" {
			res = append(res, tok)
		}
	}
	return res
}

type masterCfEntry struct {
	Service      string
	Type         string
	Private      string
	Unprivileged string
	Chroot       string
	Wakeup       string
	MaxProcesses string
	Command      string
}

// parseMasterCf parses Postfix master.cf rows. Each entry has seven fixed
// columns followed by the command (with arguments); continuation lines fold
// into the command.
func parseMasterCf(content string) []masterCfEntry {
	entries := []masterCfEntry{}
	for _, line := range foldContinuationLines(content) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 8 {
			continue
		}
		entries = append(entries, masterCfEntry{
			Service:      fields[0],
			Type:         fields[1],
			Private:      fields[2],
			Unprivileged: fields[3],
			Chroot:       fields[4],
			Wakeup:       fields[5],
			MaxProcesses: fields[6],
			Command:      strings.Join(fields[7:], " "),
		})
	}
	return entries
}

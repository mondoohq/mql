// copyright: 2020, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/filesfind"
)

func initFilesFind(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args["permissions"] == nil {
		args["permissions"] = llx.IntData(int64(0o777))
	}

	return args, nil, nil
}

func (l *mqlFilesFind) id() (string, error) {
	var id strings.Builder
	id.WriteString(l.From.Data)

	if !l.Xdev.Data {
		id.WriteString(" -xdev")
	}
	if l.Type.Data != "" {
		id.WriteString(" type=" + l.Type.Data)
	}

	if l.Regex.Data != "" {
		id.WriteString(" regex=" + l.Regex.Data)
	}

	if l.Name.Data != "" {
		id.WriteString(" name=" + l.Name.Data)
	}

	if l.Depth.Data > 0 {
		id.WriteString(" depth=" + strconv.Itoa(int(l.Depth.Data)))
	}

	if l.Permissions.Data != 0o777 {
		id.WriteString(" permissions=" + filesfind.Octal2string(l.Permissions.Data))
	}

	return id.String(), nil
}

func (l *mqlFilesFind) list() ([]any, error) {
	var err error
	var foundFiles []string
	conn := l.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	if pf == nil {
		return nil, errors.New("missing platform information")
	}

	if conn.Capabilities().Has(shared.Capability_FindFile) {
		foundFiles, err = l.fsFilesFind(conn)
		if err != nil {
			return nil, err
		}
	} else if conn.Capabilities().Has(shared.Capability_RunCommand) && pf.IsFamily("unix") {
		foundFiles, err = l.unixFilesFindCmd()
		if err != nil {
			return nil, err
		}
	} else if conn.Capabilities().Has(shared.Capability_RunCommand) && pf.IsFamily("windows") {
		foundFiles, err = l.windowsPowershellCmd()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("find is not supported for your platform")
	}

	files := make([]any, len(foundFiles))
	var filepath string
	for i := range foundFiles {
		filepath = foundFiles[i]
		files[i], err = CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(filepath),
		})
		if err != nil {
			return nil, err
		}
	}

	// return the packages as new entries
	return files, nil
}

func (l *mqlFilesFind) fsFilesFind(conn shared.Connection) ([]string, error) {
	log.Debug().Msgf("use native files find approach")
	fs := conn.FileSystem()
	fsSearch, ok := fs.(shared.FileSearch)
	if !ok {
		return nil, errors.New("find is not supported for your platform")
	}

	var perm *uint32
	if l.Permissions.Data != 0o777 {
		p := uint32(l.Permissions.Data)
		perm = &p
	}

	var depth *int
	if l.Depth.IsSet() {
		d := int(l.Depth.Data)
		depth = &d
	}

	var compiledRegexp *regexp.Regexp
	var err error
	if len(l.Regex.Data) > 0 {
		compiledRegexp, err = regexp.Compile(l.Regex.Data)
		if err != nil {
			return nil, err
		}
	}

	matchesName, err := findNameMatcher(l.Name.Data)
	if err != nil {
		return nil, err
	}

	found, err := fsSearch.Find(l.From.Data, compiledRegexp, l.Type.Data, perm, depth)
	if err != nil || matchesName == nil {
		return found, err
	}
	res := found[:0]
	for _, p := range found {
		if matchesName(p) {
			res = append(res, p)
		}
	}
	return res, nil
}

// findNameMatcher returns a test for files.find's name filter, which is a
// `find -name` glob on the last path component. It returns nil when no name
// is set. The native search used to compile the name as a regular expression
// against the full path: "*.conf" was a regexp error and "in.conf" matched
// anywhere in a path (or, on the mounted filesystem, nowhere).
func findNameMatcher(name string) (func(string) bool, error) {
	if name == "" {
		return nil, nil
	}
	// fnmatch negates a bracket expression with "!", Go's path.Match with "^"
	pattern := strings.ReplaceAll(name, "[!", "[^")
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("invalid files.find name pattern %q: %w", name, err)
	}
	return func(p string) bool {
		ok, _ := path.Match(pattern, path.Base(p))
		return ok
	}, nil
}

func (l *mqlFilesFind) unixFilesFindCmd() ([]string, error) {
	var depth *int64
	if l.Depth.IsSet() {
		depth = &l.Depth.Data
	}

	callCmd := filesfind.BuildFilesFindCmd(l.From.Data, l.Xdev.Data, l.Type.Data, l.Regex.Data, l.Permissions.Data, l.Name.Data, depth, l.hasGNUFind())
	rawCmd, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(callCmd),
	})
	if err != nil {
		return nil, err
	}

	cmd := rawCmd.(*mqlCommand)
	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	var foundFiles []string
	lines := strings.TrimSpace(out.Data)
	if lines == "" {
		foundFiles = []string{}
	} else {
		foundFiles = strings.Split(lines, "\n")
	}
	return foundFiles, nil
}

// hasGNUFind reports whether the target's find is GNU findutils, which has
// -xtype. Linux alone doesn't imply it: BusyBox find (Alpine and many
// containers) rejects -xtype, and because the find output is read from stdout
// only, the search would silently come back empty. The command resource is
// cached per connection, so the probe runs once per scan.
func (l *mqlFilesFind) hasGNUFind() bool {
	raw, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("find --version"),
	})
	if err != nil {
		return false
	}
	out := raw.(*mqlCommand).GetStdout()
	return out.Error == nil && strings.Contains(out.Data, "GNU findutils")
}

func (l *mqlFilesFind) windowsPowershellCmd() ([]string, error) {
	var depth *int64
	if l.Depth.IsSet() {
		depth = &l.Depth.Data
	}

	pwshScript := filesfind.BuildPowershellCmd(l.From.Data, l.Xdev.Data, l.Type.Data, l.Regex.Data, l.Permissions.Data, l.Name.Data, depth)
	rawCmd, err := CreateResource(l.MqlRuntime, "powershell", map[string]*llx.RawData{
		"script": llx.StringData(pwshScript),
	})
	if err != nil {
		return nil, err
	}

	ps := rawCmd.(*mqlPowershell)
	out := ps.GetStdout()
	if out.Error != nil {
		return nil, out.Error
	}

	var foundFiles []string
	lines := strings.TrimSpace(out.Data)
	if lines == "" {
		foundFiles = []string{}
	} else {
		foundFiles = strings.Split(strings.ReplaceAll(lines, "\r\n", "\n"), "\n")
	}
	return foundFiles, nil
}

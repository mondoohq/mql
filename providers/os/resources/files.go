// copyright: 2020, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/filesfind"
	"go.mondoo.com/mql/providers/os/resources/mount"
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
	} else if len(l.Name.Data) > 0 {
		compiledRegexp, err = regexp.Compile(l.Name.Data)
		if err != nil {
			return nil, err
		}
	}

	return fsSearch.Find(l.From.Data, compiledRegexp, l.Type.Data, perm, depth)
}

func (l *mqlFilesFind) unixFilesFindCmd() ([]string, error) {
	var depth *int64
	if l.Depth.IsSet() {
		depth = &l.Depth.Data
	}

	callCmd := l.unixFindCommand(depth)
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

// unixFindCommand builds the find command line for the search. Staying on the
// filesystem that holds `from` is -xdev, except on a filesystem with
// subvolumes, where -xdev would also skip every subvolume that is not mounted
// and the mount points below `from` are pruned instead. That needs the mount
// table, which is read on Linux only, and -path with -prune, which only GNU
// find is relied on for; everywhere else the search keeps -xdev.
//
// A search for links keeps -xdev as well. It is the one search that follows
// symlinked directories, and a mount reached through a link is not under a
// pruned path, so only -xdev keeps that walk off other filesystems.
func (l *mqlFilesFind) unixFindCommand(depth *int64) string {
	gnu := l.hasGNUFind()
	if !l.Xdev.Data && gnu && l.Type.Data != "link" {
		if prunes, ok := filesfind.MountPrunes(l.From.Data, l.linuxMounts()); ok {
			return filesfind.BuildFilesFindCmdPruningMounts(l.From.Data, prunes, l.Type.Data, l.Regex.Data, l.Permissions.Data, l.Name.Data, depth, gnu)
		}
	}
	return filesfind.BuildFilesFindCmd(l.From.Data, l.Xdev.Data, l.Type.Data, l.Regex.Data, l.Permissions.Data, l.Name.Data, depth, gnu)
}

// linuxMounts returns the mount table of a Linux target, or nothing when it
// cannot be read, which leaves the search on -xdev. It is read with the same
// command transport as the search itself, so it is the mount namespace find
// runs in, and the result is cached per connection.
func (l *mqlFilesFind) linuxMounts() []mount.MountPoint {
	conn, ok := l.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	if asset := conn.Asset(); asset == nil || !asset.Platform.IsFamily("linux") {
		return nil
	}
	raw, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(procMountsCmd),
	})
	if err != nil {
		return nil
	}
	out := raw.(*mqlCommand).GetStdout()
	if out.Error != nil {
		return nil
	}
	return mount.ParseLinuxProcMount(strings.NewReader(out.Data))
}

const procMountsCmd = "cat /proc/self/mounts"

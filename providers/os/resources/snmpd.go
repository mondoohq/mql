// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/snmpd"
	"go.mondoo.com/mql/types"
)

const (
	defaultSnmpdConfig   = "/etc/snmp/snmpd.conf"
	snmpdLocalConfigName = "snmpd.local.conf"
)

// snmpdPersistentConfigCandidates are the persistent snmpd.conf locations,
// probed in order. snmpd reads the one in its persistent directory after its
// configuration directory; it holds the users createUser defined and any
// directives written at runtime. Debian and Ubuntu use /var/lib/snmp, Red Hat
// /var/lib/net-snmp, and upstream builds (FreeBSD) /var/net-snmp.
var snmpdPersistentConfigCandidates = []string{
	"/var/lib/snmp/snmpd.conf",
	"/var/lib/net-snmp/snmpd.conf",
	"/var/net-snmp/snmpd.conf",
}

// snmpdConfigCandidates are the snmpd.conf locations probed in order. The
// net-snmp package on FreeBSD searches /usr/local/etc/snmp and then
// /usr/local/share/snmp (`net-snmp-config --snmpconfpath`), and its rc.d
// script defaults to /usr/local/share/snmp/snmpd.conf.
var snmpdConfigCandidates = []string{
	defaultSnmpdConfig,
	"/usr/local/etc/snmp/snmpd.conf",
	"/usr/local/share/snmp/snmpd.conf",
}

// snmpdConfigPath returns the first candidate that exists on fs, or the
// default path when none does.
func snmpdConfigPath(fs afero.Fs) string {
	if fs == nil {
		return defaultSnmpdConfig
	}
	for _, p := range snmpdConfigCandidates {
		if fi, err := fs.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return defaultSnmpdConfig
}

func initSnmpdConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in snmpd.config initialization, it must be a string")
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

func (s *mqlSnmpdConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return "snmpd.config/" + file.Data.Path.Data, nil
}

func (s *mqlSnmpdConfig) file() (*mqlFile, error) {
	var fs afero.Fs
	if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok {
		fs = conn.FileSystem()
	}
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(snmpdConfigPath(fs)),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// fileResource resolves a path into the corresponding file resource.
func (s *mqlSnmpdConfig) fileResource(path string) (*mqlFile, error) {
	raw, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlFile), nil
}

func (s *mqlSnmpdConfig) files(file *mqlFile) ([]any, error) {
	if file == nil {
		return nil, errors.New("no base snmpd config file to read")
	}

	if err := snmpdExplicitConfigExists(file); err != nil {
		return nil, err
	}

	visited := map[string]bool{}
	res := []any{}

	if err := s.collectFile(file, visited, &res); err != nil {
		return nil, err
	}

	// After snmpd.conf, snmpd reads snmpd.local.conf from the same directory
	// and then its persistent snmpd.conf. A snmpd.conf.d directory is read
	// only through an includeDir directive, which collectFile follows.
	if _, err := s.collectIfExists(filepath.Join(filepath.Dir(file.Path.Data), snmpdLocalConfigName), visited, &res); err != nil {
		return nil, err
	}
	for _, p := range snmpdPersistentConfigCandidates {
		found, err := s.collectIfExists(p, visited, &res)
		if err != nil {
			return nil, err
		}
		if found {
			break
		}
	}

	return res, nil
}

// snmpdExplicitConfigExists returns an error when snmpd.config(path) names a
// file that does not exist, the way nginx.conf, haproxy.config and bind9
// report a missing explicit path. Only a missing default location means snmpd
// is not configured on the host, which reads as no directives.
func snmpdExplicitConfigExists(file *mqlFile) error {
	if slices.Contains(snmpdConfigCandidates, file.Path.Data) {
		return nil
	}
	exists := file.GetExists()
	if exists.Error != nil {
		return exists.Error
	}
	if !exists.Data {
		return fmt.Errorf("could not read %q: no such file", file.Path.Data)
	}
	return nil
}

// collectIfExists collects the file at path when it exists and reports
// whether it did.
func (s *mqlSnmpdConfig) collectIfExists(path string, visited map[string]bool, res *[]any) (bool, error) {
	f, err := s.fileResource(path)
	if err != nil {
		return false, err
	}
	exists := f.GetExists()
	if exists.Error != nil {
		return false, exists.Error
	}
	if !exists.Data {
		return false, nil
	}
	return true, s.collectFile(f, visited, res)
}

// collectFile appends a file and recursively resolves its includeFile and
// includeDir directives. The visited set guards against include cycles.
func (s *mqlSnmpdConfig) collectFile(file *mqlFile, visited map[string]bool, res *[]any) error {
	path := file.Path.Data
	if visited[path] {
		return nil
	}
	visited[path] = true

	content, err := snmpdFileContent(file)
	if err != nil {
		return err
	}

	*res = append(*res, file)
	if content == "" {
		return nil
	}

	base := filepath.Dir(path)
	for _, d := range snmpd.Parse(content) {
		if len(d.Args) == 0 {
			continue
		}
		switch strings.ToLower(d.Keyword) {
		case "includefile":
			f, err := s.fileResource(resolveSnmpdPath(d.Args[0], base))
			if err != nil {
				return err
			}
			if err := s.collectFile(f, visited, res); err != nil {
				return err
			}
		case "includedir":
			// includeDir only reads files ending in .conf.
			if err := s.collectDir(resolveSnmpdPath(d.Args[0], base), visited, res); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectDir appends the files in dir (sorted) that end in .conf, matching
// snmpd's includeDir behavior, and resolves their includes. A missing
// directory is not an error.
func (s *mqlSnmpdConfig) collectDir(dir string, visited map[string]bool, res *[]any) error {
	d, err := s.fileResource(dir)
	if err != nil {
		return err
	}
	exists := d.GetExists()
	if exists.Error != nil {
		return exists.Error
	}
	if !exists.Data {
		return nil
	}

	files, err := getSortedPathFiles(s.MqlRuntime, dir)
	if err != nil {
		return err
	}

	for i := range files {
		f := files[i].(*mqlFile)
		if !strings.HasSuffix(f.Path.Data, ".conf") {
			continue
		}
		if err := s.collectFile(f, visited, res); err != nil {
			return err
		}
	}

	return nil
}

// resolveSnmpdPath resolves an include path relative to the including file's
// directory, leaving absolute paths untouched.
func resolveSnmpdPath(path, base string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// snmpdFileContent returns the file's content, or an empty string when the
// file is absent. A missing snmpd.conf is a normal state (the host simply
// doesn't run snmpd), so it yields no directives rather than an error.
func snmpdFileContent(file *mqlFile) (string, error) {
	exists := file.GetExists()
	if exists.Error != nil {
		return "", exists.Error
	}
	if !exists.Data {
		return "", nil
	}

	content := file.GetContent()
	if content.Error != nil {
		return "", content.Error
	}
	if content.IsNull() {
		return "", nil
	}
	return content.Data, nil
}

func (s *mqlSnmpdConfig) content(files []any) (string, error) {
	parts := make([]string, 0, len(files))
	for i := range files {
		c, err := snmpdFileContent(files[i].(*mqlFile))
		if err != nil {
			return "", err
		}
		parts = append(parts, c)
	}
	return strings.Join(parts, "\n"), nil
}

func (s *mqlSnmpdConfig) roCommunities(content string) ([]any, error) {
	ro, _ := snmpd.Communities(content)
	return convert.SliceAnyToInterface(ro), nil
}

func (s *mqlSnmpdConfig) rwCommunities(content string) ([]any, error) {
	_, rw := snmpd.Communities(content)
	return convert.SliceAnyToInterface(rw), nil
}

func (s *mqlSnmpdConfig) roUsers(content string) ([]any, error) {
	return convert.SliceAnyToInterface(snmpd.UserNames(content, "rouser")), nil
}

func (s *mqlSnmpdConfig) rwUsers(content string) ([]any, error) {
	return convert.SliceAnyToInterface(snmpd.UserNames(content, "rwuser")), nil
}

// users parses the VACM user directives file by file, so each entry keeps the
// file and line it was declared on.
func (s *mqlSnmpdConfig) users(files []any) ([]any, error) {
	res := []any{}
	for i := range files {
		file := files[i].(*mqlFile)

		content, err := snmpdFileContent(file)
		if err != nil {
			return nil, err
		}
		if content == "" {
			continue
		}

		for _, u := range snmpd.Users(content) {
			ctx, err := CreateResource(s.MqlRuntime, "file.context", map[string]*llx.RawData{
				"file":  llx.ResourceData(file, "file"),
				"range": llx.RangeData(llx.NewRange().AddLine(uint32(u.Line))),
			})
			if err != nil {
				return nil, err
			}

			accessTypes := make([]any, 0, len(u.AccessTypes))
			for _, t := range u.AccessTypes {
				accessTypes = append(accessTypes, t)
			}

			obj, err := CreateResource(s.MqlRuntime, "snmpd.config.user", map[string]*llx.RawData{
				// A user can be declared more than once and in several files,
				// so the file and line keep each declaration distinct.
				"__id":          llx.StringData(fmt.Sprintf("snmpd.config.user/%s/%d", file.Path.Data, u.Line)),
				"directive":     llx.StringData(u.Directive),
				"name":          llx.StringData(u.Name),
				"access":        llx.StringData(u.Access),
				"accessTypes":   llx.ArrayData(accessTypes, types.String),
				"securityLevel": llx.StringData(u.SecurityLevel),
				"securityModel": llx.StringData(u.SecurityModel),
				"oid":           llx.StringData(u.OID),
				"view":          llx.StringData(u.View),
				"contextName":   llx.StringData(u.ContextName),
				"context":       llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, obj)
		}
	}
	return res, nil
}

func (s *mqlSnmpdConfigUser) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for snmpd.config.user")
}

func (s *mqlSnmpdConfig) agentAddresses(content string) ([]any, error) {
	res := []any{}
	for _, d := range snmpd.Parse(content) {
		if strings.ToLower(d.Keyword) != "agentaddress" {
			continue
		}
		// agentAddress takes a comma-separated list of transport specifiers.
		for _, part := range strings.Split(strings.Join(d.Args, " "), ",") {
			if p := strings.TrimSpace(part); p != "" {
				res = append(res, p)
			}
		}
	}
	return res, nil
}

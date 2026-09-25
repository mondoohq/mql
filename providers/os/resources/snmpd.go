// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/snmpd"
	"go.mondoo.com/mql/types"
)

const (
	defaultSnmpdConfig = "/etc/snmp/snmpd.conf"
	snmpdDropInDirName = "snmpd.conf.d"
)

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
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultSnmpdConfig),
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

	visited := map[string]bool{}
	res := []any{}

	if err := s.collectFile(file, visited, &res); err != nil {
		return nil, err
	}

	// snmpd reads a snmpd.conf.d drop-in directory alongside the main config.
	// We include it implicitly so audits don't have to know the on-disk layout.
	dropInDir := filepath.Join(filepath.Dir(file.Path.Data), snmpdDropInDirName)
	if err := s.collectDir(dropInDir, false, visited, &res); err != nil {
		return nil, err
	}

	return res, nil
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
			if err := s.collectDir(resolveSnmpdPath(d.Args[0], base), true, visited, res); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectDir appends the files in dir (sorted) and resolves their includes.
// When onlyConf is set, only files ending in .conf are read, matching snmpd's
// includeDir behavior. A missing directory is not an error.
func (s *mqlSnmpdConfig) collectDir(dir string, onlyConf bool, visited map[string]bool, res *[]any) error {
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
		if onlyConf && !strings.HasSuffix(f.Path.Data, ".conf") {
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

// firstArgsByKeyword collects the first argument of every directive whose
// keyword matches one of the given keywords (compared case-insensitively).
// This is the community string for ro/rwcommunity and the user name for
// ro/rwuser, dropping any trailing source or OID-restriction arguments.
func firstArgsByKeyword(content string, keywords ...string) []any {
	set := make(map[string]struct{}, len(keywords))
	for _, k := range keywords {
		set[k] = struct{}{}
	}

	res := []any{}
	for _, d := range snmpd.Parse(content) {
		if _, ok := set[strings.ToLower(d.Keyword)]; ok && len(d.Args) > 0 {
			res = append(res, d.Args[0])
		}
	}
	return res
}

func (s *mqlSnmpdConfig) roCommunities(content string) ([]any, error) {
	return firstArgsByKeyword(content, "rocommunity", "rocommunity6"), nil
}

func (s *mqlSnmpdConfig) rwCommunities(content string) ([]any, error) {
	return firstArgsByKeyword(content, "rwcommunity", "rwcommunity6"), nil
}

func (s *mqlSnmpdConfig) roUsers(content string) ([]any, error) {
	return firstArgsByKeyword(content, "rouser"), nil
}

func (s *mqlSnmpdConfig) rwUsers(content string) ([]any, error) {
	return firstArgsByKeyword(content, "rwuser"), nil
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

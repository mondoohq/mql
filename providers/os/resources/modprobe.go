// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

var (
	// Regular expressions for parsing modprobe directives
	installRegex   = regexp.MustCompile(`^install\s+(\S+)\s+(.+)$`)
	removeRegex    = regexp.MustCompile(`^remove\s+(\S+)\s+(.+)$`)
	blacklistRegex = regexp.MustCompile(`^blacklist\s+(\S+)`)
	optionsRegex   = regexp.MustCompile(`^options\s+(\S+)\s+(.+)$`)
	aliasRegex     = regexp.MustCompile(`^alias\s+(\S+)\s+(\S+)`)
	softdepRegex   = regexp.MustCompile(`^softdep\s+(\S+)\s+(.+)$`)
)

func initModprobe(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' it must be a string")
		}

		// If a custom path is provided, just use that file
		files, err := getSortedPathFiles(runtime, path)
		if err != nil {
			return nil, nil, err
		}
		args["files"] = llx.ArrayData(files, types.Resource("file"))
		delete(args, "path")
	}

	return args, nil, nil
}

func (m *mqlModprobe) id() (string, error) {
	checksum := checksums.New
	for i := range m.Files.Data {
		path := m.Files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}
	return checksum.String(), nil
}

func (mi *mqlModprobeInstall) id() (string, error) {
	file := mi.File.Data
	lineNum := strconv.FormatInt(mi.LineNumber.Data, 10)
	return file + ":" + lineNum + ":install", nil
}

func (mr *mqlModprobeRemove) id() (string, error) {
	file := mr.File.Data
	lineNum := strconv.FormatInt(mr.LineNumber.Data, 10)
	return file + ":" + lineNum + ":remove", nil
}

func (mb *mqlModprobeBlacklist) id() (string, error) {
	file := mb.File.Data
	lineNum := strconv.FormatInt(mb.LineNumber.Data, 10)
	return file + ":" + lineNum + ":blacklist", nil
}

func (mo *mqlModprobeOption) id() (string, error) {
	file := mo.File.Data
	lineNum := strconv.FormatInt(mo.LineNumber.Data, 10)
	return file + ":" + lineNum + ":option", nil
}

func (ma *mqlModprobeAlias) id() (string, error) {
	file := ma.File.Data
	lineNum := strconv.FormatInt(ma.LineNumber.Data, 10)
	return file + ":" + lineNum + ":alias", nil
}

func (ms *mqlModprobeSoftdep) id() (string, error) {
	file := ms.File.Data
	lineNum := strconv.FormatInt(ms.LineNumber.Data, 10)
	return file + ":" + lineNum + ":softdep", nil
}

// files returns the modprobe configuration files modprobe reads, in the
// order it applies them. See listModprobeConfigFiles for the search rules.
func (m *mqlModprobe) files() ([]any, error) {
	paths, err := listModprobeConfigFiles(m.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(paths))
	for _, p := range paths {
		f, err := CreateResource(m.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

// installs parses all modprobe files and returns install directives
func (m *mqlModprobe) installs(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allInstalls []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		installs, err := parseInstalls(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allInstalls = append(allInstalls, installs...)
	}

	return allInstalls, nil
}

// removes parses all modprobe files and returns remove directives
func (m *mqlModprobe) removes(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allRemoves []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		removes, err := parseRemoves(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allRemoves = append(allRemoves, removes...)
	}

	return allRemoves, nil
}

// blacklists parses all modprobe files and returns blacklist directives
func (m *mqlModprobe) blacklists(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allBlacklists []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		blacklists, err := parseBlacklists(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allBlacklists = append(allBlacklists, blacklists...)
	}

	return allBlacklists, nil
}

// options parses all modprobe files and returns options directives
func (m *mqlModprobe) options(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allOptions []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		options, err := parseOptions(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allOptions = append(allOptions, options...)
	}

	return allOptions, nil
}

// aliases parses all modprobe files and returns alias directives
func (m *mqlModprobe) aliases(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allAliases []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		aliases, err := parseAliases(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allAliases = append(allAliases, aliases...)
	}

	return allAliases, nil
}

// softdeps parses all modprobe files and returns softdep directives
func (m *mqlModprobe) softdeps(files []any) ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	var allSoftdeps []any

	for i := range files {
		file := files[i].(*mqlFile)

		content, err := readFileContent(conn, file.Path.Data)
		if err != nil {
			return nil, err
		}

		softdeps, err := parseSoftdeps(m.MqlRuntime, file.Path.Data, content)
		if err != nil {
			return nil, err
		}

		allSoftdeps = append(allSoftdeps, softdeps...)
	}

	return allSoftdeps, nil
}

// params parses the parameters string into a map
func (mo *mqlModprobeOption) params() (map[string]any, error) {
	return parseModprobeOptionParams(mo.Parameters.Data), nil
}

// parseModprobeOptionParams turns an options parameter string into
// key/value pairs. A bare flag such as `verbose` maps to "true", the value
// the kernel assigns a boolean parameter given without one. Quotes around a
// value, or around a whole `key=value` token, are removed.
func parseModprobeOptionParams(parameters string) map[string]any {
	params := make(map[string]any)
	for _, part := range parseModprobeParams(parameters) {
		part = unquoteModprobeParam(part)
		if idx := strings.Index(part, "="); idx != -1 {
			params[part[:idx]] = unquoteModprobeParam(part[idx+1:])
		} else {
			params[part] = "true"
		}
	}
	return params
}

// unquoteModprobeParam removes one pair of matching surrounding quotes.
func unquoteModprobeParam(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// parseModprobeParams splits a parameter string respecting quoted values
func parseModprobeParams(s string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]

		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
			current.WriteByte(c)
		} else if inQuote && c == quoteChar {
			inQuote = false
			quoteChar = 0
			current.WriteByte(c)
		} else if !inQuote && (c == ' ' || c == '\t') {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// readFileContent reads a file's content and properly closes the file handle
func readFileContent(conn shared.Connection, path string) (string, error) {
	f, err := conn.FileSystem().Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

// parseInstalls parses install directives from modprobe content
func parseInstalls(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var installs []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse install directive
		matches := installRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := matches[1]
		command := strings.TrimSpace(matches[2])

		entry, err := CreateResource(runtime, "modprobe.install", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"module":     llx.StringData(module),
			"command":    llx.StringData(command),
		})
		if err != nil {
			return nil, err
		}

		installs = append(installs, entry.(*mqlModprobeInstall))
	}

	return installs, nil
}

// parseRemoves parses remove directives from modprobe content
func parseRemoves(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var removes []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse remove directive
		matches := removeRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := matches[1]
		command := strings.TrimSpace(matches[2])

		entry, err := CreateResource(runtime, "modprobe.remove", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"module":     llx.StringData(module),
			"command":    llx.StringData(command),
		})
		if err != nil {
			return nil, err
		}

		removes = append(removes, entry.(*mqlModprobeRemove))
	}

	return removes, nil
}

// parseBlacklists parses blacklist directives from modprobe content
func parseBlacklists(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var blacklists []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse blacklist directive
		matches := blacklistRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := matches[1]

		entry, err := CreateResource(runtime, "modprobe.blacklist", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"module":     llx.StringData(module),
		})
		if err != nil {
			return nil, err
		}

		blacklists = append(blacklists, entry.(*mqlModprobeBlacklist))
	}

	return blacklists, nil
}

// parseOptions parses options directives from modprobe content
func parseOptions(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var options []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse options directive
		matches := optionsRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := matches[1]
		parameters := strings.TrimSpace(matches[2])

		entry, err := CreateResource(runtime, "modprobe.option", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"module":     llx.StringData(module),
			"parameters": llx.StringData(parameters),
		})
		if err != nil {
			return nil, err
		}

		options = append(options, entry.(*mqlModprobeOption))
	}

	return options, nil
}

// parseAliases parses alias directives from modprobe content
func parseAliases(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var aliases []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse alias directive
		matches := aliasRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		aliasName := matches[1]
		module := matches[2]

		entry, err := CreateResource(runtime, "modprobe.alias", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"alias":      llx.StringData(aliasName),
			"module":     llx.StringData(module),
		})
		if err != nil {
			return nil, err
		}

		aliases = append(aliases, entry.(*mqlModprobeAlias))
	}

	return aliases, nil
}

// parseSoftdeps parses softdep directives from modprobe content
func parseSoftdeps(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	var softdeps []any
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		actualLineNum := lineNum + 1

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse softdep directive
		matches := softdepRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := matches[1]
		rest := strings.TrimSpace(matches[2])

		// Parse pre: and post: dependencies
		var pre []string
		var post []string

		// Split on "pre:" and "post:"
		parts := strings.Fields(rest)
		currentSection := ""

		for _, part := range parts {
			if part == "pre:" {
				currentSection = "pre"
				continue
			} else if part == "post:" {
				currentSection = "post"
				continue
			}

			switch currentSection {
			case "pre":
				pre = append(pre, part)
			case "post":
				post = append(post, part)
			}
		}

		// Convert to []any
		preAny := make([]any, len(pre))
		for i, p := range pre {
			preAny[i] = p
		}

		postAny := make([]any, len(post))
		for i, p := range post {
			postAny[i] = p
		}

		entry, err := CreateResource(runtime, "modprobe.softdep", map[string]*llx.RawData{
			"file":       llx.StringData(filePath),
			"lineNumber": llx.IntData(int64(actualLineNum)),
			"module":     llx.StringData(module),
			"pre":        llx.ArrayData(preAny, types.String),
			"post":       llx.ArrayData(postAny, types.String),
		})
		if err != nil {
			return nil, err
		}

		softdeps = append(softdeps, entry.(*mqlModprobeSoftdep))
	}

	return softdeps, nil
}

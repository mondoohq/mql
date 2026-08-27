// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/types"
)

const (
	aptSourcesList  = "/etc/apt/sources.list"
	aptSourcesListD = "/etc/apt/sources.list.d"
)

// aptRepo is the parsed, provider-independent representation of a single
// APT repository entry. A deb822 stanza with multiple Types/URIs/Suites
// expands into one aptRepo per combination so every entry carries a
// single type, url, and distribution.
type aptRepo struct {
	Type         string
	URL          string
	Distribution string
	Components   []string
	Trusted      bool
	SignedBy     string
	Enabled      bool
	SourceFile   string
}

func (a *mqlApt) id() (string, error) {
	return "apt", nil
}

func (a *mqlApt) repos() ([]any, error) {
	files, err := a.sourceFiles()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, f := range files {
		content, err := fileContentOrEmpty(f)
		if err != nil {
			return nil, err
		}

		var parsed []aptRepo
		if strings.HasSuffix(f.Path.Data, ".sources") {
			parsed = parseAptDeb822(content)
		} else {
			parsed = parseAptOneLine(content)
		}

		for i := range parsed {
			parsed[i].SourceFile = f.Path.Data
			mqlRepo, err := a.newRepo(f, parsed[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRepo)
		}
	}

	return res, nil
}

// sourceFiles collects the main sources.list plus every *.list and
// *.sources fragment under /etc/apt/sources.list.d/.
func (a *mqlApt) sourceFiles() ([]*mqlFile, error) {
	var out []*mqlFile

	main, err := CreateResource(a.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(aptSourcesList),
	})
	if err != nil {
		return nil, err
	}
	mainFile := main.(*mqlFile)
	if exists := mainFile.GetExists(); exists.Error == nil && exists.Data {
		out = append(out, mainFile)
	}

	// No name filter here. files.find's `name` becomes `find -name`, an fnmatch
	// glob, so the regex this used to pass matched nothing and every fragment
	// under sources.list.d was silently dropped. `regex` would reach
	// `find -regex`, but that matches the whole path and its dialect differs
	// between GNU and BSD find, so the extension check is done here instead
	// where it behaves the same everywhere.
	o, err := CreateResource(a.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from":  llx.StringData(aptSourcesListD),
		"type":  llx.StringData("file"),
		"depth": llx.IntData(1),
	})
	if err != nil {
		return nil, err
	}
	list := o.(*mqlFilesFind).GetList()
	if list.Error == nil {
		for _, item := range list.Data {
			mf, ok := item.(*mqlFile)
			if !ok {
				continue
			}
			if !isAptSourceFile(mf.Path.Data) {
				continue
			}
			out = append(out, mf)
		}
	}

	return out, nil
}

// isAptSourceFile reports whether a path under sources.list.d is one apt would
// read. apt honours exactly two extensions: .list for the one-line format and
// .sources for deb822. Everything else in the directory, notably the .save and
// .distUpgrade backups apt itself leaves behind, is ignored.
func isAptSourceFile(path string) bool {
	return strings.HasSuffix(path, ".list") || strings.HasSuffix(path, ".sources")
}

func (a *mqlApt) newRepo(file *mqlFile, repo aptRepo) (*mqlAptRepo, error) {
	id := fmt.Sprintf("%s\x00%s %s %s", repo.SourceFile, repo.Type, repo.URL, repo.Distribution)

	components := make([]any, len(repo.Components))
	for i := range repo.Components {
		components[i] = repo.Components[i]
	}

	r, err := CreateResource(a.MqlRuntime, "apt.repo", map[string]*llx.RawData{
		"__id":         llx.StringData(id),
		"type":         llx.StringData(repo.Type),
		"url":          llx.StringData(repo.URL),
		"distribution": llx.StringData(repo.Distribution),
		"components":   llx.ArrayData(components, types.String),
		"trusted":      llx.BoolData(repo.Trusted),
		"signedBy":     llx.StringData(repo.SignedBy),
		"enabled":      llx.BoolData(repo.Enabled),
		"file":         llx.ResourceData(file, "file"),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAptRepo), nil
}

// parseAptOneLine parses the classic one-line sources format. Each entry
// looks like:
//
//	deb [trusted=yes signed-by=/k.gpg] http://host/path suite comp1 comp2
//
// Lines commented out with a leading `#` that still parse as a deb entry
// are returned with Enabled=false so audits can flag disabled-but-present
// repositories; all other comments are ignored.
func parseAptOneLine(content string) []aptRepo {
	res := []aptRepo{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		enabled := true
		if strings.HasPrefix(line, "#") {
			enabled = false
			line = strings.TrimSpace(strings.TrimLeft(line, "#"))
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		repoType := fields[0]
		if repoType != "deb" && repoType != "deb-src" {
			continue
		}
		rest := fields[1:]

		repo := aptRepo{Type: repoType, Enabled: enabled}

		// optional [key=value ...] options block immediately after the type
		if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
			var opts []string
			for len(rest) > 0 {
				tok := rest[0]
				rest = rest[1:]
				opts = append(opts, strings.Trim(tok, "[]"))
				if strings.HasSuffix(tok, "]") {
					break
				}
			}
			applyAptOptions(&repo, opts)
		}

		if len(rest) < 2 {
			// need at least a URI and a suite to be a valid entry
			continue
		}
		repo.URL = rest[0]
		repo.Distribution = rest[1]
		repo.Components = append([]string{}, rest[2:]...)

		res = append(res, repo)
	}
	return res
}

// applyAptOptions interprets one-line `key=value` options, of which
// `trusted` and `signed-by` carry security meaning.
func applyAptOptions(repo *aptRepo, opts []string) {
	for _, opt := range opts {
		kv := strings.SplitN(opt, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "trusted":
			repo.Trusted = aptBool(val)
		case "signed-by":
			repo.SignedBy = val
		}
	}
}

// parseAptDeb822 parses the deb822 multi-line `.sources` format. Stanzas
// are separated by blank lines; Types, URIs, and Suites may each list
// several space-separated values, which expand into the cartesian set of
// individual repositories.
func parseAptDeb822(content string) []aptRepo {
	res := []aptRepo{}

	stanzas := splitDeb822Stanzas(content)
	for _, stanza := range stanzas {
		fields := parseDeb822Fields(stanza)
		if len(fields) == 0 {
			continue
		}

		types := strings.Fields(fields["types"])
		uris := strings.Fields(fields["uris"])
		suites := strings.Fields(fields["suites"])
		if len(types) == 0 || len(uris) == 0 || len(suites) == 0 {
			continue
		}

		components := strings.Fields(fields["components"])
		signedBy := strings.TrimSpace(fields["signed-by"])
		trusted := aptBool(fields["trusted"])
		// Enabled defaults to true; only an explicit "no"/"false" disables.
		enabled := true
		if v, ok := fields["enabled"]; ok {
			enabled = aptBool(v)
		}

		for _, t := range types {
			for _, u := range uris {
				for _, s := range suites {
					res = append(res, aptRepo{
						Type:         t,
						URL:          u,
						Distribution: s,
						Components:   append([]string{}, components...),
						Trusted:      trusted,
						SignedBy:     signedBy,
						Enabled:      enabled,
					})
				}
			}
		}
	}

	return res
}

// splitDeb822Stanzas splits a deb822 document into stanzas separated by
// one or more blank lines, dropping comment lines.
func splitDeb822Stanzas(content string) []string {
	var stanzas []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			stanzas = append(stanzas, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return stanzas
}

// parseDeb822Fields parses a single stanza into a lower-cased field map.
// Continuation lines (leading whitespace) are appended to the previous
// field's value.
func parseDeb822Fields(stanza string) map[string]string {
	fields := map[string]string{}
	lastKey := ""
	for _, line := range strings.Split(stanza, "\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			fields[lastKey] += " " + strings.TrimSpace(line)
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		fields[key] = strings.TrimSpace(kv[1])
		lastKey = key
	}
	return fields
}

// aptBool interprets apt boolean option values (yes/no, true/false,
// 1/0). Unrecognized or empty values are false.
func aptBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1":
		return true
	default:
		return false
	}
}

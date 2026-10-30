// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path"
	"sort"
	"strconv"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

var (
	// polkitActionDirs are the directories polkit reads action definitions from.
	polkitActionDirs = []string{
		"/usr/share/polkit-1/actions",
		"/usr/local/share/polkit-1/actions",
		"/etc/polkit-1/actions",
	}

	// polkitRuleDirs are the JavaScript rule directories in precedence order: an
	// equally named file in an earlier directory shadows the later ones.
	polkitRuleDirs = []string{
		"/etc/polkit-1/rules.d",
		"/run/polkit-1/rules.d",
		"/usr/local/share/polkit-1/rules.d",
		"/usr/share/polkit-1/rules.d",
	}

	// polkitLocalAuthorityDirs are the roots of the legacy local-authority tree.
	// Each holds numbered subdirectories of .pkla files.
	polkitLocalAuthorityDirs = []string{
		"/etc/polkit-1/localauthority",
		"/var/lib/polkit-1/localauthority",
	}

	polkitLocalAuthorityConfDir = "/etc/polkit-1/localauthority.conf.d"

	// polkitBinaries are the files only a polkit installation provides: the
	// daemon and its command-line tools. Action and rule directories are not
	// evidence, since systemd, NetworkManager, and other packages ship .policy
	// and .rules files into them whether or not polkit is installed.
	polkitBinaries = []string{
		"/usr/lib/polkit-1/polkitd",
		"/usr/libexec/polkit-1/polkitd",
		"/usr/libexec/polkitd",
		"/usr/lib/policykit-1/polkitd",
		"/usr/local/lib/polkit-1/polkitd",
		"/usr/local/libexec/polkit-1/polkitd",
		"/usr/bin/pkaction",
		"/usr/bin/pkexec",
		"/bin/pkaction",
		"/bin/pkexec",
		"/usr/local/bin/pkaction",
		"/usr/local/bin/pkexec",
	}
)

func (p *mqlPolkit) id() (string, error) {
	return "polkit", nil
}

func (p *mqlPolkit) fs() (afero.Fs, error) {
	conn, ok := p.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("polkit is not supported on this connection")
	}
	return conn.FileSystem(), nil
}

func (p *mqlPolkit) installed() (bool, error) {
	fs, err := p.fs()
	if err != nil {
		return false, err
	}

	for _, candidate := range polkitBinaries {
		exists, err := afero.Exists(fs, candidate)
		if err != nil {
			log.Debug().Err(err).Str("path", candidate).Msg("polkit> cannot check path")
			continue
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}

func (p *mqlPolkit) version() (string, error) {
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("pkaction --version"),
	})
	if err != nil {
		return "", err
	}
	cmd := o.(*mqlCommand)

	// a backend that cannot run commands, such as an image scan, leaves the
	// version unknown rather than wrong
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		log.Debug().Err(exit.Error).Msg("polkit> cannot run pkaction")
		p.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if exit.Data != 0 {
		p.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return "", stdout.Error
	}

	version := parsePolkitVersion(stdout.Data)
	if version == "" {
		p.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return version, nil
}

func (p *mqlPolkit) actions() ([]any, error) {
	fs, err := p.fs()
	if err != nil {
		return nil, err
	}

	res := []any{}
	seen := map[string]struct{}{}

	for _, dir := range polkitActionDirs {
		matches, err := afero.Glob(fs, path.Join(dir, "*.policy"))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)

		for _, match := range matches {
			file, err := newFile(p.MqlRuntime, match)
			if err != nil {
				return nil, err
			}

			content, err := fileContentOrEmpty(file)
			if err != nil {
				return nil, err
			}
			if content == "" {
				continue
			}

			entries, err := parsePolkitPolicy(content)
			if err != nil {
				// one vendor file with malformed XML must not sink the whole list
				log.Debug().Err(err).Str("file", match).Msg("polkit> cannot parse action policy file")
				continue
			}

			for i := range entries {
				entry := entries[i]

				// the action id is the cache key, so a duplicate across
				// directories has to be dropped rather than collide
				if _, taken := seen[entry.ID]; taken {
					continue
				}
				seen[entry.ID] = struct{}{}

				resource, err := CreateResource(p.MqlRuntime, "polkit.action", map[string]*llx.RawData{
					"__id":          llx.StringData(entry.ID),
					"id":            llx.StringData(entry.ID),
					"description":   llx.StringData(entry.Description),
					"message":       llx.StringData(entry.Message),
					"vendor":        llx.StringData(entry.Vendor),
					"vendorUrl":     llx.StringData(entry.VendorURL),
					"iconName":      llx.StringData(entry.IconName),
					"allowAny":      llx.StringData(entry.AllowAny),
					"allowInactive": llx.StringData(entry.AllowInactive),
					"allowActive":   llx.StringData(entry.AllowActive),
					"annotations":   llx.MapData(convert.MapToInterfaceMap(entry.Annotations), types.String),
					"file":          llx.ResourceData(file, "file"),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
		}
	}

	return res, nil
}

// polkitRuleFiles lists the *.rules files of every rules directory, one sorted
// slice per directory in precedence order.
func polkitRuleFiles(fs afero.Fs) ([][]string, error) {
	dirFiles := make([][]string, 0, len(polkitRuleDirs))
	for _, dir := range polkitRuleDirs {
		matches, err := globDir(fs, dir, "*.rules", false)
		if err != nil {
			// v13 skipped a rules directory it could not list
			if !plugin.StructuredErrors() {
				log.Debug().Err(err).Str("dir", dir).Msg("polkit> cannot list rules directory")
				continue
			}
			return nil, err
		}
		dirFiles = append(dirFiles, matches)
	}
	return dirFiles, nil
}

// polkitPklaFiles lists the .pkla files in the numbered subdirectories of
// every local-authority root, sorted.
func polkitPklaFiles(fs afero.Fs) ([]string, error) {
	paths := []string{}
	for _, root := range polkitLocalAuthorityDirs {
		subdirs, err := globDir(fs, root, "*", true)
		if err != nil {
			// v13 skipped a local-authority tree it could not list
			if !plugin.StructuredErrors() {
				log.Debug().Err(err).Str("dir", root).Msg("polkit> cannot list local authority directory")
				continue
			}
			return nil, err
		}
		for _, dir := range subdirs {
			matches, err := globDir(fs, dir, "*.pkla", false)
			if err != nil {
				if !plugin.StructuredErrors() {
					log.Debug().Err(err).Str("dir", dir).Msg("polkit> cannot list local authority directory")
					continue
				}
				return nil, err
			}
			paths = append(paths, matches...)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (p *mqlPolkit) rules() ([]any, error) {
	fs, err := p.fs()
	if err != nil {
		return nil, err
	}

	dirFiles, err := polkitRuleFiles(fs)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, ruleFile := range orderPolkitRuleFiles(dirFiles) {
		file, err := newFile(p.MqlRuntime, ruleFile.Path)
		if err != nil {
			return nil, err
		}

		content, err := fileContentOrEmpty(file)
		if err != nil {
			return nil, err
		}

		facts := polkitRuleFactsFrom(content)

		resource, err := CreateResource(p.MqlRuntime, "polkit.rule", map[string]*llx.RawData{
			"__id":      llx.StringData(ruleFile.Path),
			"order":     llx.IntData(int64(ruleFile.Order)),
			"adminRule": llx.BoolData(facts.AdminRule),
			"actionIds": llx.ArrayData(convert.SliceAnyToInterface(facts.ActionIDs), types.String),
			"results":   llx.ArrayData(convert.SliceAnyToInterface(facts.Results), types.String),
			"file":      llx.ResourceData(file, "file"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}

	return res, nil
}

func (p *mqlPolkit) localAuthorityRules() ([]any, error) {
	fs, err := p.fs()
	if err != nil {
		return nil, err
	}

	paths, err := polkitPklaFiles(fs)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, pklaPath := range paths {
		file, err := newFile(p.MqlRuntime, pklaPath)
		if err != nil {
			return nil, err
		}

		content, err := fileContentOrEmpty(file)
		if err != nil {
			return nil, err
		}
		if content == "" {
			continue
		}

		entries := parsePolkitPkla(content)
		for i := range entries {
			entry := entries[i]

			// section names can repeat inside one file, so the index keeps the
			// cache key unique
			id := pklaPath + "/" + strconv.Itoa(i) + "/" + entry.Name

			resource, err := CreateResource(p.MqlRuntime, "polkit.localAuthorityRule", map[string]*llx.RawData{
				"__id":           llx.StringData(id),
				"name":           llx.StringData(entry.Name),
				"identities":     llx.ArrayData(convert.SliceAnyToInterface(entry.Identities), types.String),
				"actions":        llx.ArrayData(convert.SliceAnyToInterface(entry.Actions), types.String),
				"resultAny":      llx.StringData(entry.ResultAny),
				"resultInactive": llx.StringData(entry.ResultInactive),
				"resultActive":   llx.StringData(entry.ResultActive),
				"file":           llx.ResourceData(file, "file"),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}

	return res, nil
}

func (p *mqlPolkit) adminIdentities() ([]any, error) {
	fs, err := p.fs()
	if err != nil {
		return nil, err
	}

	matches, err := afero.Glob(fs, path.Join(polkitLocalAuthorityConfDir, "*.conf"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	identities := []string{}
	for _, match := range matches {
		file, err := newFile(p.MqlRuntime, match)
		if err != nil {
			return nil, err
		}

		content, err := fileContentOrEmpty(file)
		if err != nil {
			return nil, err
		}

		// a later file overrides an earlier one, so keep the last assignment
		if parsed := parsePolkitLocalAuthorityConf(content); parsed != nil {
			identities = parsed
		}
	}

	return convert.SliceAnyToInterface(identities), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// nodeStreamPrefixGlob matches the global prefix of every Node stream Amazon
// Linux installs side by side (nodejs, nodejs20, nodejs22, nodejs24): `npm-22
// root -g` is /usr/lib/nodejs22/lib/node_modules.
const nodeStreamPrefixGlob = "/usr/lib/nodejs*/lib"

// selectedNodeModules is the alternatives link to the node_modules of the
// selected Node stream on Amazon Linux. /usr/lib already reads it.
const selectedNodeModules = "/usr/lib/node_modules"

// expandNodeStreamPrefixes replaces nodeStreamPrefixGlob in the search paths
// with the stream prefixes on the system, leaving out the one whose
// node_modules selectedNodeModules resolves to, so that the selected stream's
// global packages are not reported twice. When the link cannot be resolved,
// every stream is kept: a package listed twice is better than one missing.
func expandNodeStreamPrefixes(fs afero.Fs, paths []string, resolve func(string) (string, bool)) []string {
	res := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != nodeStreamPrefixGlob {
			res = append(res, p)
			continue
		}
		matches, err := afero.Glob(fs, p)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not search for node stream prefixes")
			continue
		}
		if len(matches) == 0 {
			continue
		}
		selected := ""
		if target, ok := resolve(selectedNodeModules); ok {
			selected = path.Clean(target)
		}
		for _, m := range matches {
			if selected != "" && path.Join(m, "node_modules") == selected {
				continue
			}
			res = append(res, m)
		}
	}
	return res
}

// resolveConnectionPath follows every symlink in p on the connection's
// filesystem.
func resolveConnectionPath(conn shared.Connection) func(string) (string, bool) {
	return func(p string) (string, bool) {
		r, ok := resolveTruststorePaths(conn, []string{p})[p]
		return r, ok
	}
}

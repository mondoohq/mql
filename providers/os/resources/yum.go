// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/yum"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
)

var supportedPlatforms = []string{"amazonlinux"}

func (y *mqlYum) id() (string, error) {
	return "yum", nil
}

func (y *mqlYum) repos() ([]any, error) {
	conn := y.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if !platform.IsFamily("redhat") && !stringx.Contains(supportedPlatforms, platform.Name) {
		return nil, errors.New("yum.repos is only supported on redhat-based platforms")
	}

	o, err := CreateResource(y.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("yum -v repolist all"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return nil, errors.New("could not retrieve yum repo list")
	}

	repos, err := yum.ParseRepos(strings.NewReader(cmd.Stdout.Data))
	if err != nil {
		return nil, err
	}

	mqlRepos := make([]any, len(repos))
	for i, repo := range repos {
		f, err := CreateResource(y.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(repo.Filename),
		})
		if err != nil {
			return nil, err
		}

		mqlRepo, err := CreateResource(y.MqlRuntime, "yum.repo", map[string]*llx.RawData{
			"id":       llx.StringData(repo.Id),
			"name":     llx.StringData(repo.Name),
			"status":   llx.StringData(repo.Status),
			"baseurl":  llx.ArrayData(llx.TArr2Raw(repo.Baseurl), types.String),
			"expire":   llx.StringData(repo.Expire),
			"file":     llx.ResourceData(f, "file"),
			"revision": llx.StringData(repo.Revision),
			"pkgs":     llx.StringData(repo.Pkgs),
			"size":     llx.StringData(repo.Size),
			"mirrors":  llx.StringData(repo.Mirrors),
		})
		if err != nil {
			return nil, err
		}
		mqlRepos[i] = mqlRepo
	}

	return mqlRepos, nil
}

var rhel67release = regexp.MustCompile(`^[67].*$`)

// dnf reads custom variables from one file per variable in these directories;
// the file name is the variable name and the first line of the file its value.
// A later directory overrides an earlier one, and every file variable overrides
// the built-in substitutions (arch, basearch, releasever).
// see VARS_DIRS in libdnf/conf/Const.hpp and libdnf5/conf/const.hpp
var (
	dnf4VarsDirs = []string{"/etc/yum/vars", "/etc/dnf/vars"}
	dnf5VarsDirs = []string{"/usr/share/dnf5/vars.d", "/etc/dnf/vars"}
)

const dnf5Binary = "/usr/bin/dnf5"

func (y *mqlYum) vars() (map[string]any, error) {
	conn := y.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if !platform.IsFamily("redhat") && !stringx.Contains(supportedPlatforms, platform.Name) {
		return nil, errors.New("yum.vars is only supported on redhat-based platforms")
	}

	res := map[string]any{}
	builtins, err := y.builtinVars(platform.IsFamily("redhat"), platform.Version)
	if err != nil {
		// The built-in substitutions come from dnf's Python API, which dnf5 hosts
		// and image scans do not have. The variables on disk are still readable.
		log.Debug().Err(err).Msg("yum.vars> could not retrieve built-in variables")
	}
	for k, v := range builtins {
		res[k] = v
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}
	dirs := dnf4VarsDirs
	if ok, _ := afs.Exists(dnf5Binary); ok {
		dirs = dnf5VarsDirs
	}
	fileVars, err := readYumVarsDirs(afs, dirs)
	if err != nil {
		return nil, err
	}
	for k, v := range fileVars {
		res[k] = v
	}

	return res, nil
}

// builtinVars returns the built-in substitutions dnf (or yum on RHEL 6/7)
// computes for this host, by asking its Python API.
func (y *mqlYum) builtinVars(isRedhat bool, version string) (map[string]string, error) {
	// use dnf script as default
	script := fmt.Sprintf(yum.DnfVarsCommand, yum.PythonRhel)
	if !isRedhat {
		// eg. amazon linux does not ship with /usr/libexec/platform-python
		script = fmt.Sprintf(yum.DnfVarsCommand, yum.Python3)
	}

	// fallback for older versions like 6 and 7 version to use yum script
	if rhel67release.MatchString(version) {
		script = yum.Rhel6VarsCommand
	}

	o, err := CreateResource(y.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(script),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		return nil, errors.New("could not retrieve yum variables")
	}

	return yum.ParseVariables(strings.NewReader(cmd.Stdout.Data))
}

// readYumVarsDirs reads the variables defined on disk in dirs, least important
// first, the way dnf does: each regular file directly in a directory is one
// variable, named after the file, whose value is the file's first line.
func readYumVarsDirs(afs *afero.Afero, dirs []string) (map[string]string, error) {
	res := map[string]string{}
	for _, dir := range dirs {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			// the connection's virtual filesystem may not return *os.PathError,
			// so match the wrapped sentinel rather than using os.IsNotExist
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := afs.ReadFile(path.Join(dir, e.Name()))
			if err != nil {
				// dnf warns and skips a variable file it cannot read
				log.Debug().Err(err).Str("dir", dir).Str("name", e.Name()).Msg("yum.vars> skipping unreadable variable file")
				continue
			}
			value, _, _ := strings.Cut(string(data), "\n")
			res[e.Name()] = value
		}
	}
	return res, nil
}

func (y *mqlYumRepo) id() (string, error) {
	return y.Id.Data, nil
}

func initYumRepo(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["id"]
	if nameRaw == nil {
		return args, nil, nil
	}

	name, ok := nameRaw.Value.(string)
	if !ok {
		return args, nil, nil
	}

	o, err := CreateResource(runtime, "yum", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	yumResource := o.(*mqlYum)

	repos := yumResource.GetRepos()
	if repos.Error != nil {
		return nil, nil, repos.Error
	}

	for i := range repos.Data {
		selected := repos.Data[i].(*mqlYumRepo)
		if selected.Id.Data == name {
			return nil, selected, nil
		}
	}

	// if the repo cannot be found we return an error
	return nil, nil, errors.New("could not find yum repo " + name)
}

func (y *mqlYumRepo) enabled() (bool, error) {
	status := y.GetStatus()
	if status.Error != nil {
		return false, status.Error
	}

	return strings.ToLower(status.Data) == "enabled", nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yum

// To support static analysis, we need to extend the current implementation:
//
// - read repo info from file system as is
// - read variables from file system as is

// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-using_yum_variables
// /etc/yum.conf
// /etc/yum.repos.d/*.repo

// References:
// - https://unix.stackexchange.com/questions/19701/yum-how-can-i-view-variables-like-releasever-basearch-yum0
// - https://docs.centos.org/en-US/8-docs/managing-userspace-components/assembly_using-appstream/

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const (
	// RhelYumRepoListCommand runs in the C locale: dnf 4 and yum 3 translate
	// the labels ("Paketquellenkennung" for "Repo-id") and the status
	// ("aktiviert"), which ParseRepos reads in English.
	RhelYumRepoListCommand = "LC_ALL=C yum -v repolist all"
	DnfVarsCommand         = "%s -c 'import dnf, json; db = dnf.dnf.Base(); print(json.dumps(db.conf.substitutions))'"
	PythonRhel             = "/usr/libexec/platform-python"
	Python3                = "python3"
	Rhel6VarsCommand       = "python -c 'import yum, json; yb = yum.YumBase(); print json.dumps(yb.conf.yumvar)'"
)

// Dnf5RepoInfoCommand lists repositories on dnf5, which has no verbose
// repolist; `repo info` prints the same details under different labels.
// See libdnf5-cli/output/repo_info.cpp. It runs in the C locale for the same
// reason as RhelYumRepoListCommand.
const Dnf5RepoInfoCommand = "LC_ALL=C dnf5 repo info --all"

type YumRepo struct {
	Id       string
	Name     string
	Status   string
	Revision string
	Updated  string
	Pkgs     string
	Size     string
	Mirrors  string
	Expire   string
	Filename string
	Baseurl  []string
	Filter   string
}

var (
	yumrepoline = regexp.MustCompile(`^\s*([^:\s]*)(?:\s)*:\s(.*)$`)
	yumbaseurl  = regexp.MustCompile(`^(.*?)(?:\(.*\))*$`)
)

const (
	Id       = "Repo-id"
	Name     = "Repo-name"
	Status   = "Repo-status"
	Revision = "Repo-revision"
	Updated  = "Repo-updated"
	Pkgs     = "Repo-pkgs"
	Size     = "Repo-size"
	Mirrors  = "Repo-mirrors"
	Metalink = "Repo-metalink"
	Baseurl  = "Repo-baseurl"
	Expire   = "Repo-expire"
	Filter   = "Filter"
	Filename = "Repo-filename"
)

// ParseVariables reads the JSON object the Python snippets print. yum 3 (RHEL
// 7) prints its plugin banner first, on stdout:
//
//	Loaded plugins: amazon-id, product-id, versionlock
//	{"g03var": "g03value", "basearch": "x86_64", "arch": "ia32e", ...}
//
// so the object is read from the first line that starts one.
func ParseVariables(r io.Reader) (map[string]string, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	start := 0
	for start < len(content) && content[start] != '{' {
		next := bytes.IndexByte(content[start:], '\n')
		if next < 0 {
			start = len(content)
			break
		}
		start += next + 1
	}
	if start >= len(content) {
		return nil, errors.New("no variables in the output")
	}

	data := map[string]string{}
	if err := json.NewDecoder(bytes.NewReader(content[start:])).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

// Dnf5DumpVariablesCommand prints the variables dnf5 substitutes in repository
// configuration, the built-in ones included. dnf5 has no Python API to ask.
const Dnf5DumpVariablesCommand = "dnf5 --dump-variables"

// ParseDnf5Variables parses `dnf5 --dump-variables`:
//
//	======== Variables: ========
//	arch = x86_64
//	basearch = x86_64
//	releasever = 44
//	releasever_major =
func ParseDnf5Variables(r io.Reader) (map[string]string, error) {
	res := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "=") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		res[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, errors.New("no variables in the dnf5 output")
	}
	return res, nil
}

// Parses the output of yum -v repolist all
// It requires yum to be installed
//
// yum 3 (RHEL 7) differs from dnf in two ways. It prints the id of a repo
// whose URL uses $releasever or $basearch with those appended
// (`Repo-id : rhel-7-server-rhui-rpms/7Server/x86_64`); a repo id cannot
// contain a slash, so the id is what comes before the first one. And it wraps
// a value longer than the line onto continuation lines that have no key:
//
//	Repo-name    : Red Hat Developer Tools RPMs for Red Hat Enterprise Linux 7
//	             : Server from RHUI
func ParseRepos(r io.Reader) ([]*YumRepo, error) {
	res := []*YumRepo{}

	var entry *YumRepo
	add := func(new *YumRepo) {
		if entry == nil {
			return
		}
		res = append(res, new)
	}
	// lastKey is the key of the previous line, which a continuation extends
	lastKey := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := yumrepoline.FindStringSubmatch(line)
		if len(m) == 3 {
			key := strings.TrimSpace(m[1])
			value := strings.TrimSpace(m[2])

			if key == "" {
				if entry == nil {
					continue
				}
				switch lastKey {
				case Name:
					entry.Name = strings.TrimSpace(entry.Name + " " + value)
				case Baseurl:
					entry.Baseurl = append(entry.Baseurl, parseYumBaseurls(value)...)
				}
				continue
			}
			lastKey = key
			if key != Id && entry == nil {
				continue
			}

			switch key {
			case Id:
				add(entry)
				id, _, _ := strings.Cut(value, "/")
				entry = &YumRepo{Id: id}
			case Name:
				entry.Name = value
			case Status:
				entry.Status = value
			case Revision:
				entry.Revision = value
			case Updated:
				entry.Updated = value
			case Pkgs:
				entry.Pkgs = value
			case Size:
				entry.Size = value
			case Mirrors, Metalink:
				// dnf prints either the metalink or the mirrorlist of a repo
				entry.Mirrors = value
			case Baseurl:
				entry.Baseurl = parseYumBaseurls(value)
			case Expire:
				entry.Expire = value
			case Filter:
				entry.Filter = value
			case Filename:
				entry.Filename = value
			}
		}
	}

	// add last entry
	add(entry)

	return res, nil
}

// parseYumBaseurls splits a Repo-baseurl value: comma-separated URLs, where a
// URL taken from a mirror list is followed by "(N more)".
func parseYumBaseurls(value string) []string {
	res := []string{}
	m := yumbaseurl.FindStringSubmatch(value)
	if len(m) < 2 {
		return res
	}
	for _, u := range strings.Split(m[1], ",") {
		if u = strings.TrimSpace(u); u != "" {
			res = append(res, u)
		}
	}
	return res
}

// labels printed by `dnf5 repo info`
const (
	dnf5Id         = "Repo ID"
	dnf5Name       = "Name"
	dnf5Status     = "Status"
	dnf5Expire     = "Metadata expire"
	dnf5Filename   = "Config file"
	dnf5Baseurl    = "Base URL"
	dnf5Metalink   = "Metalink"
	dnf5Mirrorlist = "Mirrorlist"
	dnf5Pkgs       = "Total packages"
	dnf5Size       = "Size"
	dnf5Revision   = "Revision"
	dnf5Updated    = "Updated"
)

var (
	// the key is everything up to the first colon; values such as URLs keep theirs
	dnf5RepoLine = regexp.MustCompile(`^\s*([^:]+?)\s*:\s?(.*)$`)
	// a Base URL resolved from a metalink or mirrorlist ends in "(N more)"
	dnf5MoreMirrors = regexp.MustCompile(`\s*\(\d+ more\)$`)
)

// ParseDnf5Repos parses the output of `dnf5 repo info --all`.
func ParseDnf5Repos(r io.Reader) ([]*YumRepo, error) {
	res := []*YumRepo{}

	var entry *YumRepo
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		m := dnf5RepoLine.FindStringSubmatch(scanner.Text())
		if len(m) != 3 {
			continue
		}
		key := m[1]
		value := strings.TrimSpace(m[2])

		if key == dnf5Id {
			entry = &YumRepo{Id: value}
			res = append(res, entry)
			continue
		}
		if entry == nil {
			continue
		}

		switch key {
		case dnf5Name:
			entry.Name = value
		case dnf5Status:
			entry.Status = value
		case dnf5Expire:
			entry.Expire = value
		case dnf5Filename:
			entry.Filename = value
		case dnf5Baseurl:
			// configured base URLs are space-separated; a URL taken from a
			// mirror list is the first mirror followed by "(N more)"
			entry.Baseurl = strings.Fields(dnf5MoreMirrors.ReplaceAllString(value, ""))
		case dnf5Metalink, dnf5Mirrorlist:
			entry.Mirrors = value
		case dnf5Pkgs:
			entry.Pkgs = value
		case dnf5Size:
			entry.Size = value
		case dnf5Revision:
			entry.Revision = value
		case dnf5Updated:
			entry.Updated = value
		}
	}

	return res, scanner.Err()
}

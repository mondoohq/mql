// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// membershipState is whether an identity provider's membership was read.
type membershipState int

const (
	// membershipNotRead means the provider is not looked for on this platform.
	membershipNotRead membershipState = iota
	// membershipRead means the membership was read, member or not.
	membershipRead
	// membershipUnreadable means the provider is looked for on this platform,
	// but its source could not be read, so membership is unknown.
	membershipUnreadable
)

// adMembership is the device's Active Directory domain membership. A zero
// value means the device is not a member.
type adMembership struct {
	domain string
	forest string
}

func (m adMembership) member() bool { return m.domain != "" }

// adResult is the outcome of reading the Active Directory membership.
type adResult struct {
	state      membershipState
	membership adMembership
}

var (
	adNotRead    = adResult{state: membershipNotRead}
	adUnreadable = adResult{state: membershipUnreadable}
)

func adMember(domain, forest string) adResult {
	return adResult{state: membershipRead, membership: adMembership{
		domain: strings.ToLower(strings.TrimSpace(domain)),
		forest: strings.ToLower(strings.TrimSpace(forest)),
	}}
}

// readActiveDirectory reads the device's Active Directory membership from the
// local configuration of its platform. Nothing here contacts a domain
// controller: a device that is off the network reports the domain it is
// joined to all the same.
func readActiveDirectory(conn shared.Connection, pf *inventory.Platform) adResult {
	if pf == nil {
		return adNotRead
	}
	switch {
	case pf.IsFamily(inventory.FAMILY_WINDOWS):
		return readWindowsActiveDirectory(conn)
	case pf.IsFamily(inventory.FAMILY_DARWIN):
		return readMacosActiveDirectory(conn.FileSystem())
	case pf.IsFamily(inventory.FAMILY_LINUX):
		return readLinuxActiveDirectory(conn.FileSystem())
	}
	return adNotRead
}

// readWindowsActiveDirectory asks the local security authority for the
// machine's domain role, domain and forest. Domain membership is kept by the
// LSA rather than in a documented registry value, so a disk image scan, which
// cannot run anything, leaves it unknown.
func readWindowsActiveDirectory(conn shared.Connection) adResult {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return adUnreadable
	}
	info, err := detwin.GetActiveDirectoryInfo(conn)
	if err != nil || info == nil {
		log.Debug().Err(err).Msg("could not read the Active Directory domain membership")
		return adUnreadable
	}
	if !info.Member {
		return adResult{state: membershipRead}
	}
	return adMember(info.Domain, info.Forest)
}

// macosADConfigDir holds one property list per Active Directory binding,
// written by the Active Directory plugin of opendirectoryd when the Mac is
// bound with dsconfigad or Directory Utility, and removed on unbind.
const macosADConfigDir = "/Library/Preferences/OpenDirectory/Configurations/Active Directory"

// readMacosActiveDirectory reads the Active Directory binding from the
// opendirectoryd configuration. The binding's domain and forest are under
// "module options" > "ActiveDirectory", as dsconfigad -show reports them.
func readMacosActiveDirectory(fsys afero.Fs) adResult {
	entries, err := afero.ReadDir(fsys, macosADConfigDir)
	if err != nil {
		if adFileMissing(err) {
			return adResult{state: membershipRead}
		}
		log.Debug().Err(err).Msg("could not list the Active Directory bindings")
		return adUnreadable
	}

	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".plist") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	unreadable := false
	for _, name := range names {
		data, err := afero.ReadFile(fsys, path.Join(macosADConfigDir, name))
		if err != nil {
			log.Debug().Err(err).Str("file", name).Msg("could not read an Active Directory binding")
			unreadable = true
			continue
		}
		domain, forest, err := parseMacosADBinding(data)
		if err != nil {
			log.Debug().Err(err).Str("file", name).Msg("could not parse an Active Directory binding")
			unreadable = true
			continue
		}
		if domain != "" {
			return adMember(domain, forest)
		}
	}
	if unreadable {
		return adUnreadable
	}
	return adResult{state: membershipRead}
}

// parseMacosADBinding returns the domain and forest of an Active Directory
// binding. "domain" is the domain the Mac was bound to; "trust domain", the
// domain holding the computer account, stands in when it is missing.
func parseMacosADBinding(data []byte) (string, string, error) {
	d, err := plist.Decode(bytes.NewReader(data))
	if err != nil {
		return "", "", err
	}
	opts, _ := d["module options"].(map[string]any)
	ad, _ := opts["ActiveDirectory"].(map[string]any)
	str := func(k string) string {
		s, _ := ad[k].(string)
		return strings.TrimSpace(s)
	}
	domain := str("domain")
	if domain == "" {
		domain = str("trust domain")
	}
	return domain, str("forest"), nil
}

const (
	sssdConfPath   = "/etc/sssd/sssd.conf"
	sssdConfDDir   = "/etc/sssd/conf.d"
	sambaConfPath  = "/etc/samba/smb.conf"
	sssdADProvider = "ad"
)

// readLinuxActiveDirectory reads the Active Directory membership from the
// client configuration a join writes: SSSD with the ad provider, which is
// what realmd and adcli configure by default, or Samba's winbind, which realmd
// configures when asked to. Neither names the forest, so it is not reported.
//
// sssd.conf is readable by root only. A scan without root cannot tell, and
// reports the membership as unknown rather than absent.
func readLinuxActiveDirectory(fsys afero.Fs) adResult {
	unreadable := false

	sssd, err := readSssdConfig(fsys)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the SSSD configuration")
		unreadable = true
	}
	if domain := sssdADDomain(sssd); domain != "" {
		return adMember(domain, "")
	}

	smb, err := afero.ReadFile(fsys, sambaConfPath)
	switch {
	case err == nil:
		if domain := sambaADDomain(parseConfSections(string(smb), true)); domain != "" {
			return adMember(domain, "")
		}
	case !adFileMissing(err):
		log.Debug().Err(err).Msg("could not read the Samba configuration")
		unreadable = true
	}

	if unreadable {
		return adUnreadable
	}
	return adResult{state: membershipRead}
}

// readSssdConfig reads sssd.conf and the snippets in conf.d, which SSSD merges
// in alphabetical order, each one overriding what came before. Snippets must
// end in .conf and must not be hidden. Missing files are not an error; any
// other read failure is, and what was read so far is still returned.
func readSssdConfig(fsys afero.Fs) (confSections, error) {
	res := confSections{}
	var errs []error

	data, err := afero.ReadFile(fsys, sssdConfPath)
	switch {
	case err == nil:
		res.merge(parseConfSections(string(data), false))
	case !adFileMissing(err):
		errs = append(errs, err)
	}

	entries, err := afero.ReadDir(fsys, sssdConfDDir)
	if err != nil && !adFileMissing(err) {
		errs = append(errs, err)
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := afero.ReadFile(fsys, path.Join(sssdConfDDir, name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res.merge(parseConfSections(string(data), false))
	}
	return res, errors.Join(errs...)
}

// sssdADDomain returns the Active Directory domain of the first active SSSD
// domain that uses the ad identity provider, or "". A domain is active when
// it is listed in domains of the [sssd] section, or has enabled = true in its
// own section, and enabled = false in its own section switches it off even
// when it is listed (confdb_get_enabled_domain_list). Its Active Directory
// domain is ad_domain, which defaults to the SSSD domain's name.
func sssdADDomain(c confSections) string {
	adDomain := func(name string) string {
		sec, ok := c["domain/"+name]
		if !ok || !strings.EqualFold(sec["id_provider"], sssdADProvider) {
			return ""
		}
		if strings.EqualFold(sec["enabled"], "false") {
			return ""
		}
		if d := sec["ad_domain"]; d != "" {
			return d
		}
		return name
	}

	for _, name := range strings.Split(c["sssd"]["domains"], ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if d := adDomain(name); d != "" {
			return d
		}
	}

	names := []string{}
	for sec := range c {
		if name, ok := strings.CutPrefix(sec, "domain/"); ok && strings.EqualFold(c[sec]["enabled"], "true") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if d := adDomain(name); d != "" {
			return d
		}
	}
	return ""
}

// sambaADDomain returns the Active Directory domain Samba belongs to, or "".
// Its realm is the domain's DNS name in upper case. Samba is in an Active
// Directory domain when it runs with security = ads, or leaves security unset
// (auto) with a server role that implies it: a member server resolves auto to
// ads, and an Active Directory domain controller needs no security line at
// all. An explicit security = domain is an NT4-style membership, not Active
// Directory. Samba ignores case and spaces in parameter names.
func sambaADDomain(c confSections) string {
	global := map[string]string{}
	for k, v := range c["global"] {
		global[strings.ReplaceAll(k, " ", "")] = v
	}
	realm := global["realm"]
	if realm == "" {
		return ""
	}

	switch strings.ToLower(global["security"]) {
	case "ads":
		return realm
	case "", "auto":
		switch strings.ToLower(strings.Join(strings.Fields(global["serverrole"]), " ")) {
		case "member server", "member", "active directory domain controller", "dc":
			return realm
		}
	}
	return ""
}

// confSections is an ini-style configuration: section name to lower-cased
// option name to value.
type confSections map[string]map[string]string

func (c confSections) merge(other confSections) {
	for name, opts := range other {
		sec, ok := c[name]
		if !ok {
			sec = map[string]string{}
			c[name] = sec
		}
		for k, v := range opts {
			sec[k] = v
		}
	}
}

// parseConfSections parses the ini dialect SSSD and Samba share: sections in
// brackets, "name = value" options, and lines starting with # or ; as
// comments. Option names are case-insensitive in both. Samba section names
// are too, so foldSections lower-cases them; SSSD domain names keep their
// case.
func parseConfSections(raw string, foldSections bool) confSections {
	res := confSections{}
	cur := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			if end := strings.Index(line, "]"); end > 0 {
				cur = strings.TrimSpace(line[1:end])
				if foldSections {
					cur = strings.ToLower(cur)
				}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		sec, ok := res[cur]
		if !ok {
			sec = map[string]string{}
			res[cur] = sec
		}
		sec[k] = strings.TrimSpace(v)
	}
	return res
}

func adFileMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

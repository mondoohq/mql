// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"gopkg.in/ini.v1"
)

type Secpol struct {
	SystemAccess   map[string]any
	EventAudit     map[string]any
	RegistryValues map[string]any
	// principals as secedit exported them: SIDs without the leading "*", plus
	// account names. PrivilegeRightSids reports them all as SIDs.
	PrivilegeRights map[string][]string
}

// SidResolver maps account names to SIDs, with or without secedit's leading "*".
type SidResolver func(names []string) (map[string]string, error)

// ParseSecpol parses a secedit export. Resolving [Privilege Rights] account
// names needs a second command on the target, so it is a separate step
// (PrivilegeRightSids) and a failing lookup costs only that one field.
func ParseSecpol(r io.Reader) (*Secpol, error) {
	res := &Secpol{
		SystemAccess:    map[string]any{},      // except for NewAdministratorName & NewGuestName, parse everything as int64
		EventAudit:      map[string]any{},      // parse to int
		RegistryValues:  map[string]any{},      // keep strings
		PrivilegeRights: map[string][]string{}, // split entries with ,
	}

	cfg, err := ini.Load(r)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse secpol")
	}

	sysAccess, err := cfg.GetSection("System Access")
	if err != nil {
		return nil, err
	}
	keys := sysAccess.Keys()
	for i := range keys {
		entry := keys[i]
		key := entry.Name()
		rawValue := entry.Value()

		if key == "NewAdministratorName" || key == "NewGuestName" {
			res.SystemAccess[key] = rawValue
			continue
		}

		res.SystemAccess[key] = rawValue
	}

	eventAudit, err := cfg.GetSection("Event Audit")
	if err != nil {
		return nil, err
	}
	keys = eventAudit.Keys()
	for i := range keys {
		entry := keys[i]

		rawValue := entry.Value()
		res.EventAudit[entry.Name()] = rawValue
	}

	registryValues, err := cfg.GetSection("Registry Values")
	if err != nil {
		return nil, err
	}
	keys = registryValues.Keys()
	for i := range keys {
		entry := keys[i]
		res.RegistryValues[entry.Name()] = entry.Value()
	}

	privilegeRights, err := cfg.GetSection("Privilege Rights")
	if err != nil {
		return nil, err
	}
	keys = privilegeRights.Keys()
	for i := range keys {
		entry := keys[i]

		rawValues := strings.Split(entry.Value(), ",")
		valuesT := make([]string, 0, len(rawValues))
		for i := range rawValues {
			val := normalizePrivilegeRight(rawValues[i])
			if val == "" {
				continue
			}
			valuesT = append(valuesT, val)
		}
		res.PrivilegeRights[entry.Name()] = valuesT
	}

	return res, nil
}

// AccountNames lists the [Privilege Rights] principals secedit reported as
// names rather than SIDs, sorted so the resolver command stays stable. secedit
// names machine-local accounts, so `Guest` in a deny right is enough to put an
// entry here, on any display language.
func (s *Secpol) AccountNames() []string {
	seen := map[string]struct{}{}
	var names []string
	for _, principals := range s.PrivilegeRights {
		for _, val := range principals {
			if isSecurityIdentifier(val) {
				continue
			}
			if _, ok := seen[val]; ok {
				continue
			}
			seen[val] = struct{}{}
			names = append(names, val)
		}
	}
	sort.Strings(names)
	return names
}

// PrivilegeRightSids reports the principals as SIDs. Account names go to
// resolve; whatever stays unresolved is dropped.
func (s *Secpol) PrivilegeRightSids(resolve SidResolver) (map[string]any, error) {
	lookup := map[string]string{}
	if names := s.AccountNames(); len(names) > 0 && resolve != nil {
		var err error
		lookup, err = resolve(names)
		if err != nil {
			return nil, errors.Wrap(err, "could not resolve privilege right account names")
		}
	}

	res := make(map[string]any, len(s.PrivilegeRights))
	for key, principals := range s.PrivilegeRights {
		res[key] = privilegeRightSids(principals, lookup)
	}
	return res, nil
}

func privilegeRightSids(principals []string, lookup map[string]string) []any {
	sids := make([]string, 0, len(principals))
	seen := map[string]struct{}{}
	for _, val := range principals {
		if !isSecurityIdentifier(val) {
			val = normalizePrivilegeRight(lookup[val])
			if !isSecurityIdentifier(val) {
				continue
			}
		}
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		sids = append(sids, val)
	}
	sort.Strings(sids)

	values := make([]any, len(sids))
	for i := range sids {
		values[i] = sids[i]
	}
	return values
}

func normalizePrivilegeRight(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "*")
}

func isSecurityIdentifier(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return false
	}

	for _, part := range parts[1:] {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}

	return true
}

// SecpolScript exports the local security policy to a temporary file and prints
// it. Account name resolution runs as a separate command (see SidLookupScript):
// combining the export with SID enumeration in one encoded command trips
// Defender's Trojan:Win32/Commando.A!ml heuristic.
// Output crosses a pipe, so pin UTF-8 instead of inheriting it: under a legacy
// code page a local account name such as `Müller` arrives as undecodable bytes
// and the principal is dropped from the right.
const SecpolScript = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$cfg = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
secedit /export /cfg $cfg | Out-Null
Get-Content $cfg
Remove-Item $cfg | Out-Null
`

// SidLookupScript prints one `name<TAB>sid` line per name it can resolve. It
// only runs when secedit reported account names instead of SIDs.
func SidLookupScript(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, "'"+strings.ReplaceAll(name, "'", "''")+"'")
	}
	return fmt.Sprintf(sidLookupScript, strings.Join(quoted, ","))
}

const sidLookupScript = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$names = @(%s)
foreach ($name in $names) {
    $sid = $null
    if ($name -eq 'Guest') {
        try { $sid = (Get-LocalUser -Name 'Guest' -ErrorAction Stop).SID.Value } catch {}
    }
    if ($null -eq $sid) {
        try { $sid = [System.Security.Principal.NTAccount]::new($name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
    }
    if ($null -ne $sid) { Write-Output ($name + [char]9 + $sid) }
}
`

func ParseSidLookup(r io.Reader) (map[string]string, error) {
	res := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name, sid, found := strings.Cut(scanner.Text(), "\t")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		sid = normalizePrivilegeRight(sid)
		if name == "" || !isSecurityIdentifier(sid) {
			continue
		}
		res[name] = sid
	}

	return res, scanner.Err()
}

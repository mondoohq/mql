// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
	"go.mondoo.com/mql/types"
)

const aixSecurityPasswdFile = "/etc/security/passwd"

func (p *mqlAixSecurityPasswd) id() (string, error) {
	return "aix.security.passwd", nil
}

// list reads every record of /etc/security/passwd. The password hash is
// classified and dropped; no field carries it.
func (p *mqlAixSecurityPasswd) list() ([]any, error) {
	if err := requireAix(p.MqlRuntime, "aix.security.passwd"); err != nil {
		return nil, err
	}
	st, err := readAixStanzas(p.MqlRuntime, aixSecurityPasswdFile)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(st.List))
	for _, s := range st.List {
		pw, set := s.Get("password")
		state, algo := aix.PasswordState(pw, set)

		lastUpdate := llx.NilData
		if v, ok := s.Get("lastupdate"); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				t := time.Unix(sec, 0).UTC()
				lastUpdate = llx.TimeData(t)
			}
		}

		flags := []any{}
		if v, ok := s.Get("flags"); ok {
			for _, f := range aix.SplitList(v) {
				flags = append(flags, f)
			}
		}

		r, err := CreateResource(p.MqlRuntime, "aix.security.passwd.entry", map[string]*llx.RawData{
			"__id":          llx.StringData("aix.security.passwd.entry/" + s.Name),
			"name":          llx.StringData(s.Name),
			"state":         llx.StringData(state),
			"hashAlgorithm": llx.StringData(algo),
			"lastUpdate":    lastUpdate,
			"flags":         llx.ArrayData(flags, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (e *mqlAixSecurityPasswdEntry) user() (*mqlUser, error) {
	usr, err := aixLocalUser(e.MqlRuntime, e.Name.Data)
	if err != nil {
		return nil, err
	}
	if usr == nil {
		e.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return usr, nil
}

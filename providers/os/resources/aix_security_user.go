// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
	"go.mondoo.com/mql/types"
)

const aixSecurityUserFile = "/etc/security/user"

type mqlAixSecurityUsersInternal struct {
	parseOnce sync.Once
	parsed    *aix.Stanzas
	parseErr  error
}

func (u *mqlAixSecurityUsers) id() (string, error) {
	return "aix.security.users", nil
}

// load parses the file once; fields are computed concurrently.
func (u *mqlAixSecurityUsers) load() (*aix.Stanzas, error) {
	u.parseOnce.Do(func() {
		if err := requireAix(u.MqlRuntime, "aix.security.users"); err != nil {
			u.parseErr = err
			return
		}
		u.parsed, u.parseErr = readAixStanzas(u.MqlRuntime, aixSecurityUserFile)
	})
	return u.parsed, u.parseErr
}

func (u *mqlAixSecurityUsers) defaults() (map[string]any, error) {
	st, err := u.load()
	if err != nil {
		return nil, err
	}
	if d := st.Get("default"); d != nil {
		return aix.StringMap(d.Attrs), nil
	}
	return map[string]any{}, nil
}

// list returns every local user, the ones without a stanza of their own
// included: they inherit the default stanza, as lsuser ALL reports them.
func (u *mqlAixSecurityUsers) list() ([]any, error) {
	st, err := u.load()
	if err != nil {
		return nil, err
	}
	raw, err := CreateResource(u.MqlRuntime, "users", nil)
	if err != nil {
		return nil, err
	}
	users := raw.(*mqlUsers).GetList()
	if users.Error != nil {
		return nil, users.Error
	}

	res := make([]any, 0, len(users.Data))
	seen := map[string]bool{}
	for _, x := range users.Data {
		name := x.(*mqlUser).Name.Data
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		r, err := newAixSecurityUser(u.MqlRuntime, st, name)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newAixSecurityUser(runtime *plugin.Runtime, st *aix.Stanzas, name string) (*mqlAixSecurityUser, error) {
	eff := st.EffectiveAttrs(name)
	explicit := map[string]string{}
	if own := st.Get(name); own != nil {
		explicit = own.Attrs
	}
	get := func(key string) (string, bool) {
		v, ok := eff[key]
		return v, ok
	}
	str := func(key string) *llx.RawData {
		return aix.StringData(get(key))
	}

	// null when neither stanza sets it: AIX then allows ALL
	sugroups := llx.NilData
	if v, ok := get("sugroups"); ok {
		groups := []any{}
		for _, g := range aix.SplitList(v) {
			groups = append(groups, g)
		}
		sugroups = llx.ArrayData(groups, types.String)
	}

	args := map[string]*llx.RawData{
		"name":          llx.StringData(name),
		"attributes":    llx.MapData(aix.StringMap(eff), types.String),
		"explicit":      llx.MapData(aix.StringMap(explicit), types.String),
		"sugroups":      sugroups,
		"expires":       str("expires"),
		"umask":         str("umask"),
		"registry":      str("registry"),
		"authSystem":    str("SYSTEM"),
		"admin":         aix.BoolData(get("admin")),
		"login":         aix.BoolData(get("login")),
		"rlogin":        aix.BoolData(get("rlogin")),
		"su":            aix.BoolData(get("su")),
		"accountLocked": aix.BoolData(get("account_locked")),
	}
	for _, key := range []string{
		"maxage", "minage", "maxexpired", "minlen", "minalpha", "minloweralpha",
		"minupperalpha", "minother", "mindigit", "minspecialchar", "mindiff",
		"maxrepeats", "histsize", "histexpire", "loginretries", "pwdwarntime",
	} {
		args[key] = aix.IntData(get(key))
	}

	r, err := CreateResource(runtime, "aix.security.user", args)
	if err != nil {
		return nil, err
	}
	return r.(*mqlAixSecurityUser), nil
}

func initAixSecurityUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, fmt.Errorf("aix.security.user requires a name")
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("aix.security.user name must be a string")
	}

	obj, err := CreateResource(runtime, "aix.security.users", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlAixSecurityUsers).GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, x := range list.Data {
		if u := x.(*mqlAixSecurityUser); u.Name.Data == name {
			return nil, u, nil
		}
	}
	return nil, nil, fmt.Errorf("aix.security.user with name %q not found", name)
}

func (u *mqlAixSecurityUser) id() (string, error) {
	return "aix.security.user/" + u.Name.Data, nil
}

func (u *mqlAixSecurityUser) user() (*mqlUser, error) {
	usr, err := aixLocalUser(u.MqlRuntime, u.Name.Data)
	if err != nil {
		return nil, err
	}
	if usr == nil {
		u.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return usr, nil
}

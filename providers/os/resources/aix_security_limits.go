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

const aixLimitsFile = "/etc/security/limits"

type mqlAixSecurityLimitsInternal struct {
	parseOnce sync.Once
	parsed    *aix.Stanzas
	parseErr  error
}

func (l *mqlAixSecurityLimits) id() (string, error) {
	return "aix.security.limits", nil
}

// load parses the file once; fields are computed concurrently.
func (l *mqlAixSecurityLimits) load() (*aix.Stanzas, error) {
	l.parseOnce.Do(func() {
		if err := requireAix(l.MqlRuntime, "aix.security.limits"); err != nil {
			l.parseErr = err
			return
		}
		l.parsed, l.parseErr = readAixStanzas(l.MqlRuntime, aixLimitsFile)
	})
	return l.parsed, l.parseErr
}

func (l *mqlAixSecurityLimits) defaults() (map[string]any, error) {
	st, err := l.load()
	if err != nil {
		return nil, err
	}
	if d := st.Get("default"); d != nil {
		return aix.StringMap(d.Attrs), nil
	}
	return map[string]any{}, nil
}

// list returns the limits of every local user; a user without a stanza
// inherits the default stanza.
func (l *mqlAixSecurityLimits) list() ([]any, error) {
	st, err := l.load()
	if err != nil {
		return nil, err
	}
	raw, err := CreateResource(l.MqlRuntime, "users", nil)
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
		eff := st.EffectiveAttrs(name)
		args := map[string]*llx.RawData{
			"name":       llx.StringData(name),
			"attributes": llx.MapData(aix.StringMap(eff), types.String),
		}
		for field, key := range map[string]string{
			"fsize": "fsize", "fsizeHard": "fsize_hard",
			"core": "core", "coreHard": "core_hard",
			"cpu": "cpu", "cpuHard": "cpu_hard",
			"data": "data", "dataHard": "data_hard",
			"stack": "stack", "stackHard": "stack_hard",
			"rss": "rss", "rssHard": "rss_hard",
			"nofiles": "nofiles", "nofilesHard": "nofiles_hard",
		} {
			v, ok := eff[key]
			args[field] = aix.IntData(v, ok)
		}
		r, err := CreateResource(l.MqlRuntime, "aix.security.limit", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func initAixSecurityLimit(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, fmt.Errorf("aix.security.limit requires a name")
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("aix.security.limit name must be a string")
	}
	obj, err := CreateResource(runtime, "aix.security.limits", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlAixSecurityLimits).GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, x := range list.Data {
		if lim := x.(*mqlAixSecurityLimit); lim.Name.Data == name {
			return nil, lim, nil
		}
	}
	return nil, nil, fmt.Errorf("aix.security.limit with name %q not found", name)
}

func (l *mqlAixSecurityLimit) id() (string, error) {
	return "aix.security.limit/" + l.Name.Data, nil
}

func (l *mqlAixSecurityLimit) user() (*mqlUser, error) {
	usr, err := aixLocalUser(l.MqlRuntime, l.Name.Data)
	if err != nil {
		return nil, err
	}
	if usr == nil {
		l.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return usr, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

const aixLoginCfgFile = "/etc/security/login.cfg"

type mqlAixSecurityLoginCfgInternal struct {
	parseOnce sync.Once
	parsed    *aix.Stanzas
	parseErr  error
}

func (l *mqlAixSecurityLoginCfg) id() (string, error) {
	return "aix.security.loginCfg", nil
}

// load parses the file once; fields are computed concurrently.
func (l *mqlAixSecurityLoginCfg) load() (*aix.Stanzas, error) {
	l.parseOnce.Do(func() {
		if err := requireAix(l.MqlRuntime, "aix.security.loginCfg"); err != nil {
			l.parseErr = err
			return
		}
		l.parsed, l.parseErr = readAixStanzas(l.MqlRuntime, aixLoginCfgFile)
	})
	return l.parsed, l.parseErr
}

// attr returns an attribute of one stanza. login.cfg has no inheritance
// between its usw and default stanzas.
func (l *mqlAixSecurityLoginCfg) attr(stanza, key string) (string, bool, error) {
	st, err := l.load()
	if err != nil {
		return "", false, err
	}
	s := st.Get(stanza)
	if s == nil {
		return "", false, nil
	}
	v, ok := s.Get(key)
	return v, ok, nil
}

func (l *mqlAixSecurityLoginCfg) file() (*mqlFile, error) {
	if err := requireAix(l.MqlRuntime, "aix.security.loginCfg"); err != nil {
		return nil, err
	}
	f, err := CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(aixLoginCfgFile),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (l *mqlAixSecurityLoginCfg) stanzas() (map[string]any, error) {
	st, err := l.load()
	if err != nil {
		return nil, err
	}
	res := make(map[string]any, len(st.List))
	for _, s := range st.List {
		res[s.Name] = aix.StringMap(s.Attrs)
	}
	return res, nil
}

func (l *mqlAixSecurityLoginCfg) shells() ([]any, error) {
	v, ok, err := l.attr("usw", "shells")
	if err != nil {
		return nil, err
	}
	if !ok {
		l.Shells.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, s := range aix.SplitList(v) {
		res = append(res, s)
	}
	return res, nil
}

func (l *mqlAixSecurityLoginCfg) authType() (string, error) {
	v, ok, err := l.attr("usw", "auth_type")
	if err != nil {
		return "", err
	}
	return aix.StringField(&l.AuthType, v, ok)
}

func (l *mqlAixSecurityLoginCfg) pwdAlgorithm() (string, error) {
	v, ok, err := l.attr("usw", "pwd_algorithm")
	if err != nil {
		return "", err
	}
	return aix.StringField(&l.PwdAlgorithm, v, ok)
}

func (l *mqlAixSecurityLoginCfg) herald() (string, error) {
	v, ok, err := l.attr("default", "herald")
	if err != nil {
		return "", err
	}
	return aix.StringField(&l.Herald, v, ok)
}

func (l *mqlAixSecurityLoginCfg) maxlogins() (int64, error) {
	v, ok, err := l.attr("usw", "maxlogins")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Maxlogins, v, ok)
}

func (l *mqlAixSecurityLoginCfg) logintimeout() (int64, error) {
	v, ok, err := l.attr("usw", "logintimeout")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Logintimeout, v, ok)
}

func (l *mqlAixSecurityLoginCfg) logindelay() (int64, error) {
	v, ok, err := l.attr("default", "logindelay")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Logindelay, v, ok)
}

func (l *mqlAixSecurityLoginCfg) logindisable() (int64, error) {
	v, ok, err := l.attr("default", "logindisable")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Logindisable, v, ok)
}

func (l *mqlAixSecurityLoginCfg) logininterval() (int64, error) {
	v, ok, err := l.attr("default", "logininterval")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Logininterval, v, ok)
}

func (l *mqlAixSecurityLoginCfg) loginreenable() (int64, error) {
	v, ok, err := l.attr("default", "loginreenable")
	if err != nil {
		return 0, err
	}
	return aix.IntField(&l.Loginreenable, v, ok)
}

func (l *mqlAixSecurityLoginCfg) sakEnabled() (bool, error) {
	v, ok, err := l.attr("default", "sak_enabled")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&l.SakEnabled, v, ok)
}

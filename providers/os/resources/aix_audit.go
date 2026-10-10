// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

const aixAuditConfigFile = "/etc/security/audit/config"

type mqlAixAuditInternal struct {
	parseOnce sync.Once
	parsed    *aix.Stanzas
	parseErr  error
}

func (a *mqlAixAudit) id() (string, error) {
	return "aix.audit", nil
}

// load parses the file once; fields are computed concurrently.
func (a *mqlAixAudit) load() (*aix.Stanzas, error) {
	a.parseOnce.Do(func() {
		if err := requireAix(a.MqlRuntime, "aix.audit"); err != nil {
			a.parseErr = err
			return
		}
		a.parsed, a.parseErr = readAixStanzas(a.MqlRuntime, aixAuditConfigFile)
	})
	return a.parsed, a.parseErr
}

// running asks audit query, which prints "auditing on" or "auditing off".
func (a *mqlAixAudit) running() (bool, error) {
	if err := requireAix(a.MqlRuntime, "aix.audit"); err != nil {
		return false, err
	}
	out, _, err := runAixCommand(a.MqlRuntime, "audit query")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "auditing" {
			return f[1] == "on", nil
		}
	}
	a.Running.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (a *mqlAixAudit) mode(key string) (string, bool, error) {
	st, err := a.load()
	if err != nil {
		return "", false, err
	}
	s := st.Get("start")
	if s == nil {
		return "", false, nil
	}
	v, ok := s.Get(key)
	return v, ok, nil
}

func (a *mqlAixAudit) binMode() (bool, error) {
	v, ok, err := a.mode("binmode")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&a.BinMode, v, ok)
}

func (a *mqlAixAudit) streamMode() (bool, error) {
	v, ok, err := a.mode("streammode")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&a.StreamMode, v, ok)
}

// listStanza returns a stanza whose attributes are comma separated lists.
func (a *mqlAixAudit) listStanza(name string) (map[string]any, error) {
	st, err := a.load()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	s := st.Get(name)
	if s == nil {
		return res, nil
	}
	for _, k := range s.Keys {
		items := []any{}
		for _, item := range aix.SplitList(s.Attrs[k]) {
			items = append(items, item)
		}
		res[k] = items
	}
	return res, nil
}

func (a *mqlAixAudit) classes() (map[string]any, error) {
	return a.listStanza("classes")
}

func (a *mqlAixAudit) users() (map[string]any, error) {
	return a.listStanza("users")
}

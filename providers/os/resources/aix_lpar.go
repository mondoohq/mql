// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

type mqlAixLparInternal struct {
	once   sync.Once
	values map[string]string
	err    error
}

func (l *mqlAixLpar) id() (string, error) {
	return "aix.lpar", nil
}

// load runs lparstat once; fields are computed concurrently.
func (l *mqlAixLpar) load() (map[string]string, error) {
	l.once.Do(func() {
		if l.err = requireAix(l.MqlRuntime, "aix.lpar"); l.err != nil {
			return
		}
		out, _, err := runAixCommand(l.MqlRuntime, aix.LparstatCommand)
		if err != nil {
			l.err = err
			return
		}
		l.values = aix.ParseLparstat(out)
	})
	return l.values, l.err
}

func (l *mqlAixLpar) value(key string) (string, bool, error) {
	v, err := l.load()
	if err != nil {
		return "", false, err
	}
	s, ok := v[key]
	return s, ok, nil
}

func (l *mqlAixLpar) stringField(tv *plugin.TValue[string], key string) (string, error) {
	v, ok, err := l.value(key)
	if err != nil {
		return "", err
	}
	return aix.StringField(tv, v, ok)
}

func (l *mqlAixLpar) intField(tv *plugin.TValue[int64], key string) (int64, error) {
	v, ok, err := l.value(key)
	if err != nil {
		return 0, err
	}
	return aix.IntField(tv, v, ok)
}

func (l *mqlAixLpar) partitionName() (string, error) {
	return l.stringField(&l.PartitionName, "Partition Name")
}

func (l *mqlAixLpar) partitionNumber() (int64, error) {
	return l.intField(&l.PartitionNumber, "Partition Number")
}

func (l *mqlAixLpar) compute_type() (string, error) {
	return l.stringField(&l.Type, "Type")
}

func (l *mqlAixLpar) mode() (string, error) {
	return l.stringField(&l.Mode, "Mode")
}

func (l *mqlAixLpar) entitledCapacity() (float64, error) {
	v, ok, err := l.value("Entitled Capacity")
	if err != nil {
		return 0, err
	}
	if ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, nil
		}
	}
	l.EntitledCapacity.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

func (l *mqlAixLpar) onlineVirtualCpus() (int64, error) {
	return l.intField(&l.OnlineVirtualCpus, "Online Virtual CPUs")
}

func (l *mqlAixLpar) maxVirtualCpus() (int64, error) {
	return l.intField(&l.MaxVirtualCpus, "Maximum Virtual CPUs")
}

func (l *mqlAixLpar) smtThreads() (int64, error) {
	v, ok, err := l.value("Type")
	if err != nil {
		return 0, err
	}
	if ok {
		if n, valid := aix.LparSmtThreads(v); valid {
			return n, nil
		}
	}
	l.SmtThreads.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

func (l *mqlAixLpar) sharedPoolId() (int64, error) {
	return l.intField(&l.SharedPoolId, "Shared Pool ID")
}

func (l *mqlAixLpar) onlineMemoryBytes() (int64, error) {
	v, ok, err := l.value("Online Memory")
	if err != nil {
		return 0, err
	}
	if ok {
		if n, valid := aix.LparMemoryBytes(v); valid {
			return n, nil
		}
	}
	l.OnlineMemoryBytes.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

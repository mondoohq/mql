// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file exposes the blocks that decide who reaches the router and what
// it trusts: the key chains of the routing protocols, the vty lines, and the
// RPKI caches. They are read from the same parsed file as the rest of
// frr.config, so they cost no extra read.

func (s *mqlFrrConfig) keyChains(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	chains := s.cfg.KeyChains()
	res := make([]any, 0, len(chains))
	for i := range chains {
		c := &chains[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.keyChain", map[string]*llx.RawData{
			"__id":      llx.StringData(s.__id + "#keyChain/" + c.Name),
			"name":      llx.StringData(c.Name),
			"keys":      llx.ArrayData(frr.KeyChainKeysAsDicts(c.Keys), types.Dict),
			"file":      llx.StringData(c.File),
			"startLine": llx.IntData(int64(c.StartLine)),
			"raw":       llx.StringData(c.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) vtyLines(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	lines := s.cfg.VtyLines()
	res := make([]any, 0, len(lines))
	for i := range lines {
		l := &lines[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.vtyLine", map[string]*llx.RawData{
			"__id":            llx.StringData(s.__id + "#vtyLine/" + strconv.Itoa(l.StartLine)),
			"accessClass":     llx.StringData(l.AccessClass),
			"accessClassIpv6": llx.StringData(l.AccessClassIPv6),
			"execTimeout":     llx.StringData(l.ExecTimeout),
			"loginEnabled":    llx.BoolData(l.LoginEnabled),
			"passwordSet":     llx.BoolData(l.PasswordSet),
			"params":          llx.MapData(stringMapToAny(l.Params), types.String),
			"file":            llx.StringData(l.File),
			"startLine":       llx.IntData(int64(l.StartLine)),
			"raw":             llx.StringData(l.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) rpki(file *mqlFile) (*mqlFrrConfigRpkiSettings, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	r := s.cfg.RPKIBlock()
	obj, err := CreateResource(s.MqlRuntime, "frr.config.rpkiSettings", map[string]*llx.RawData{
		"__id":           llx.StringData(s.__id + "#rpki"),
		"configured":     llx.BoolData(r.Configured),
		"pollingPeriod":  llx.IntData(r.PollingPeriod),
		"expireInterval": llx.IntData(r.ExpireInterval),
		"retryInterval":  llx.IntData(r.RetryInterval),
		"caches":         llx.ArrayData(frr.RPKICachesAsDicts(r.Caches), types.Dict),
		"params":         llx.MapData(stringMapToAny(r.Params), types.String),
		"file":           llx.StringData(r.File),
		"startLine":      llx.IntData(int64(r.StartLine)),
		"raw":            llx.StringData(r.Raw),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlFrrConfigRpkiSettings), nil
}

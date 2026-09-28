// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleNftJSON = `{
  "nftables": [
    {"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
    {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "filter", "name": "my_chain", "handle": 3}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {"left": {"meta": {"key": "iifname"}}, "right": "lo", "op": "=="}}, {"accept": null}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": [{"match": {"left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}], "comment": "allow established"}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 6, "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22, "op": "=="}}, {"accept": null}], "comment": "allow ssh"}},
    {"set": {"family": "inet", "table": "filter", "name": "allowed_ips", "handle": 10, "type": "ipv4_addr", "flags": ["interval"], "elem": ["10.0.0.1", {"prefix": {"addr": "192.168.1.0", "len": 24}}]}},
    {"set": {"family": "inet", "table": "filter", "name": "blocked_ports", "handle": 11, "type": "inet_service", "elem": [80, 443, 8080]}},
    {"table": {"family": "ip", "name": "nat", "handle": 2}},
    {"chain": {"family": "ip", "table": "nat", "name": "postrouting", "handle": 1, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
    {"rule": {"family": "ip", "table": "nat", "chain": "postrouting", "handle": 2, "expr": [{"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "192.168.1.0", "len": 24}}, "op": "=="}}, {"masquerade": null}]}},
    {"set": {"family": "ip", "table": "nat", "name": "nat_targets", "handle": 12, "type": "ipv4_addr", "map": "ipv4_addr", "elem": [{"concat": ["10.0.0.1", "192.168.1.1"]}]}}
  ]
}`

func TestParseNftRuleset(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)
	require.NotNil(t, ruleset)

	var tableCount, chainCount, ruleCount, setCount int
	for _, obj := range ruleset.Nftables {
		if obj.Table != nil {
			tableCount++
		}
		if obj.Chain != nil {
			chainCount++
		}
		if obj.Rule != nil {
			ruleCount++
		}
		if obj.Set != nil {
			setCount++
		}
	}
	assert.Equal(t, 2, tableCount)
	assert.Equal(t, 4, chainCount)
	assert.Equal(t, 4, ruleCount)
	assert.Equal(t, 3, setCount)
}

func TestParseNftRuleset_Metainfo(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)

	var meta *nftMetainfo
	for _, obj := range ruleset.Nftables {
		if obj.Metainfo != nil {
			meta = obj.Metainfo
			break
		}
	}
	require.NotNil(t, meta)
	assert.Equal(t, "1.0.2", meta.Version)
	assert.Equal(t, "Lester Gooch", meta.ReleaseName)
	assert.Equal(t, 1, meta.JSONSchemaVersion)
}

func TestParseNftRuleset_Tables(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)

	var tables []*nftTable
	for _, obj := range ruleset.Nftables {
		if obj.Table != nil {
			tables = append(tables, obj.Table)
		}
	}

	require.Len(t, tables, 2)

	assert.Equal(t, "inet", tables[0].Family)
	assert.Equal(t, "filter", tables[0].Name)
	assert.Equal(t, int64(1), tables[0].Handle)

	assert.Equal(t, "ip", tables[1].Family)
	assert.Equal(t, "nat", tables[1].Name)
	assert.Equal(t, int64(2), tables[1].Handle)
}

func TestParseNftRuleset_BaseChain(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)

	var chains []*nftChain
	for _, obj := range ruleset.Nftables {
		if obj.Chain != nil {
			chains = append(chains, obj.Chain)
		}
	}

	require.Len(t, chains, 4)

	// input chain - base chain
	assert.Equal(t, "input", chains[0].Name)
	assert.Equal(t, "filter", chains[0].Type)
	assert.Equal(t, "input", chains[0].Hook)
	assert.Equal(t, int64(0), chains[0].Prio)
	assert.Equal(t, "accept", chains[0].Policy)

	// forward chain - base chain with drop policy
	assert.Equal(t, "forward", chains[1].Name)
	assert.Equal(t, "drop", chains[1].Policy)

	// my_chain - regular chain (no type/hook/prio/policy)
	assert.Equal(t, "my_chain", chains[2].Name)
	assert.Equal(t, "", chains[2].Type)
	assert.Equal(t, "", chains[2].Hook)
	assert.Equal(t, int64(0), chains[2].Prio)
	assert.Equal(t, "", chains[2].Policy)

	// postrouting - nat base chain
	assert.Equal(t, "postrouting", chains[3].Name)
	assert.Equal(t, "nat", chains[3].Type)
	assert.Equal(t, "postrouting", chains[3].Hook)
	assert.Equal(t, int64(100), chains[3].Prio)
}

func TestParseNftRuleset_Rules(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)

	var rules []*nftRule
	for _, obj := range ruleset.Nftables {
		if obj.Rule != nil {
			rules = append(rules, obj.Rule)
		}
	}

	require.Len(t, rules, 4)

	// First rule: loopback accept
	assert.Equal(t, "inet", rules[0].Family)
	assert.Equal(t, "filter", rules[0].Table)
	assert.Equal(t, "input", rules[0].Chain)
	assert.Equal(t, int64(4), rules[0].Handle)
	assert.Len(t, rules[0].Expr, 2)
	assert.Equal(t, "", rules[0].Comment)

	// Second rule: established/related with comment
	assert.Equal(t, int64(5), rules[1].Handle)
	assert.Equal(t, "allow established", rules[1].Comment)

	// Third rule: allow ssh — verify integer port number is preserved as int64
	assert.Equal(t, int64(6), rules[2].Handle)
	assert.Equal(t, "allow ssh", rules[2].Comment)
	require.Len(t, rules[2].Expr, 2)
	matchExpr, ok := rules[2].Expr[0].(map[string]any)
	require.True(t, ok)
	matchInner, ok := matchExpr["match"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, int64(22), matchInner["right"])

	// NAT rule
	assert.Equal(t, "ip", rules[3].Family)
	assert.Equal(t, "nat", rules[3].Table)
	assert.Equal(t, "postrouting", rules[3].Chain)
	assert.Equal(t, int64(2), rules[3].Handle)
	assert.Len(t, rules[3].Expr, 2)
}

func TestParseNftRuleset_Sets(t *testing.T) {
	ruleset, err := parseNftRuleset([]byte(sampleNftJSON))
	require.NoError(t, err)

	var sets []*nftSet
	for _, obj := range ruleset.Nftables {
		if obj.Set != nil {
			sets = append(sets, obj.Set)
		}
	}

	require.Len(t, sets, 3)

	// allowed_ips set
	assert.Equal(t, "inet", sets[0].Family)
	assert.Equal(t, "filter", sets[0].Table)
	assert.Equal(t, "allowed_ips", sets[0].Name)
	assert.Equal(t, int64(10), sets[0].Handle)
	assert.Equal(t, "ipv4_addr", sets[0].parseKeyType())
	assert.Equal(t, "", sets[0].Map)
	assert.Equal(t, []string{"interval"}, sets[0].parseSetFlags())

	elems := sets[0].parseSetElements()
	require.Len(t, elems, 2)
	assert.Equal(t, "10.0.0.1", elems[0])
	assert.Equal(t, "192.168.1.0/24", elems[1])

	// blocked_ports set
	assert.Equal(t, "blocked_ports", sets[1].Name)
	assert.Equal(t, "inet_service", sets[1].parseKeyType())
	portElems := sets[1].parseSetElements()
	require.Len(t, portElems, 3)
	assert.Equal(t, "80", portElems[0])
	assert.Equal(t, "443", portElems[1])
	assert.Equal(t, "8080", portElems[2])

	// nat_targets map
	assert.Equal(t, "nat_targets", sets[2].Name)
	assert.Equal(t, "ipv4_addr", sets[2].parseKeyType())
	assert.Equal(t, "ipv4_addr", sets[2].Map)
	mapElems := sets[2].parseSetElements()
	require.Len(t, mapElems, 1)
	assert.Equal(t, "10.0.0.1 . 192.168.1.1", mapElems[0])
}

func TestParseNftRuleset_EmptyRuleset(t *testing.T) {
	data := `{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}]}`
	ruleset, err := parseNftRuleset([]byte(data))
	require.NoError(t, err)
	require.NotNil(t, ruleset)

	var tableCount int
	for _, obj := range ruleset.Nftables {
		if obj.Table != nil {
			tableCount++
		}
	}
	assert.Equal(t, 0, tableCount)
}

func TestParseNftRuleset_InvalidJSON(t *testing.T) {
	_, err := parseNftRuleset([]byte("not json"))
	require.Error(t, err)
}

func TestNftTableParseFlags(t *testing.T) {
	t.Run("no flags", func(t *testing.T) {
		tbl := &nftTable{}
		assert.Nil(t, tbl.parseFlags())
	})

	t.Run("null flags", func(t *testing.T) {
		tbl := &nftTable{Flags: json.RawMessage(`null`)}
		assert.Nil(t, tbl.parseFlags())
	})

	t.Run("single string flag", func(t *testing.T) {
		tbl := &nftTable{Flags: json.RawMessage(`"dormant"`)}
		assert.Equal(t, []string{"dormant"}, tbl.parseFlags())
	})

	t.Run("array flags", func(t *testing.T) {
		tbl := &nftTable{Flags: json.RawMessage(`["dormant", "owner"]`)}
		assert.Equal(t, []string{"dormant", "owner"}, tbl.parseFlags())
	})
}

func TestNftSetParseKeyType(t *testing.T) {
	t.Run("simple type", func(t *testing.T) {
		s := &nftSet{Type: json.RawMessage(`"ipv4_addr"`)}
		assert.Equal(t, "ipv4_addr", s.parseKeyType())
	})

	t.Run("concatenated type", func(t *testing.T) {
		s := &nftSet{Type: json.RawMessage(`["ipv4_addr", "inet_service"]`)}
		assert.Equal(t, "ipv4_addr . inet_service", s.parseKeyType())
	})

	t.Run("nil type", func(t *testing.T) {
		s := &nftSet{}
		assert.Equal(t, "", s.parseKeyType())
	})
}

func TestNftSetParseFlags(t *testing.T) {
	t.Run("array flags", func(t *testing.T) {
		s := &nftSet{Flags: json.RawMessage(`["interval", "timeout"]`)}
		assert.Equal(t, []string{"interval", "timeout"}, s.parseSetFlags())
	})

	t.Run("single string flag", func(t *testing.T) {
		s := &nftSet{Flags: json.RawMessage(`"constant"`)}
		assert.Equal(t, []string{"constant"}, s.parseSetFlags())
	})

	t.Run("no flags", func(t *testing.T) {
		s := &nftSet{}
		assert.Nil(t, s.parseSetFlags())
	})
}

func TestNftElemToString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"string", "10.0.0.1", "10.0.0.1"},
		{"integer", float64(80), "80"},
		{"float", float64(3.14), "3.14"},
		{"bool", true, "true"},
		{"prefix", map[string]any{"prefix": map[string]any{"addr": "10.0.0.0", "len": float64(8)}}, "10.0.0.0/8"},
		{"range", map[string]any{"range": []any{"1024", "65535"}}, "1024-65535"},
		{"concat", map[string]any{"concat": []any{"10.0.0.1", float64(80)}}, "10.0.0.1 . 80"},
		{"val wrapper", map[string]any{"val": "10.0.0.1"}, "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, nftElemToString(tt.input))
		})
	}
}

func TestNftSetParseElements_Range(t *testing.T) {
	s := &nftSet{Elem: json.RawMessage(`[{"range": [1024, 65535]}]`)}
	elems := s.parseSetElements()
	require.Len(t, elems, 1)
	assert.Equal(t, "1024-65535", elems[0])
}

func TestNftSetParseElements_Empty(t *testing.T) {
	s := &nftSet{}
	assert.Nil(t, s.parseSetElements())

	s2 := &nftSet{Elem: json.RawMessage(`null`)}
	assert.Nil(t, s2.parseSetElements())
}

func TestParseNftVersion(t *testing.T) {
	tests := []struct {
		out  string
		want string
	}{
		// `nft --version` captured on the sweep hosts
		{"nftables v0.8.2 (Joe Btfsplk)\n", "0.8.2"},            // Ubuntu 18.04
		{"nftables v0.9.0 (Fearless Fosdick)\n", "0.9.0"},       // Debian 10
		{"nftables v1.0.2 (Lester Gooch)\n", "1.0.2"},           // Ubuntu 22.04
		{"nftables v1.0.9 (Old Doc Yak #3)\n", "1.0.9"},         // AlmaLinux 9, RHEL 9
		{"nftables v1.1.3 (Commodore Bullmoose #4)\n", "1.1.3"}, // Debian 13
		{"", ""},
		{"something unexpected\n", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, parseNftVersion(tt.out), tt.out)
	}
}

func TestNftVersionSupportsJSON(t *testing.T) {
	tests := []struct {
		version   string
		supported bool
		ok        bool
	}{
		{"0.8.2", false, true},
		{"0.9.0", false, true},
		{"0.9.1", true, true},
		{"0.9.3", true, true},
		{"1.0.2", true, true},
		{"1.1.3", true, true},
		{"0.10", true, true},
		{"1.0.6-rc1", true, true},
		{"0.9", false, true},
		{"", false, false},
		{"abc", false, false},
		{"x.y.z", false, false},
	}
	for _, tt := range tests {
		supported, ok := nftVersionSupportsJSON(tt.version)
		assert.Equal(t, tt.ok, ok, tt.version)
		assert.Equal(t, tt.supported, supported, tt.version)
	}
}

func TestNftUnsupportedVersionError(t *testing.T) {
	err := nftUnsupportedVersionError("0.8.2")
	assert.EqualError(t, err, "nft 0.8.2 cannot list the ruleset as JSON; reading nftables tables, chains, rules, and sets requires nft 0.9.1 or later")
}

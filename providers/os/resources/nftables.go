// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// nftRuleset is the top-level JSON envelope from `nft -j list ruleset`.
type nftRuleset struct {
	Nftables []nftObject `json:"nftables"`
}

// nftObject represents one element in the nftables array.
// Exactly one field will be non-nil per object.
type nftObject struct {
	Metainfo *nftMetainfo `json:"metainfo,omitempty"`
	Table    *nftTable    `json:"table,omitempty"`
	Chain    *nftChain    `json:"chain,omitempty"`
	Rule     *nftRule     `json:"rule,omitempty"`
	Set      *nftSet      `json:"set,omitempty"`
}

type nftMetainfo struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JSONSchemaVersion int    `json:"json_schema_version"`
}

type nftTable struct {
	Family string          `json:"family"`
	Name   string          `json:"name"`
	Handle int64           `json:"handle"`
	Flags  json.RawMessage `json:"flags,omitempty"`
}

// parseFlags normalizes nftables table flags from JSON.
// Flags can be a single string or an array of strings depending on the nft version.
func (t *nftTable) parseFlags() []string {
	if t.Flags == nil || string(t.Flags) == "null" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(t.Flags, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(t.Flags, &s); err == nil {
		return []string{s}
	}
	return nil
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int64  `json:"handle"`
	Type   string `json:"type,omitempty"`
	Hook   string `json:"hook,omitempty"`
	Prio   int64  `json:"prio,omitempty"`
	Policy string `json:"policy,omitempty"`
}

type nftRule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int64  `json:"handle"`
	Expr    []any  `json:"expr,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type nftSet struct {
	Family  string          `json:"family"`
	Table   string          `json:"table"`
	Name    string          `json:"name"`
	Handle  int64           `json:"handle"`
	Type    json.RawMessage `json:"type"`
	Map     string          `json:"map,omitempty"`
	Flags   json.RawMessage `json:"flags,omitempty"`
	Elem    json.RawMessage `json:"elem,omitempty"`
	Timeout int64           `json:"timeout,omitempty"`
}

// parseKeyType extracts the key type from the "type" field.
// Type can be a string ("ipv4_addr") or an array for concatenated types (["ipv4_addr", "inet_service"]).
func (s *nftSet) parseKeyType() string {
	if s.Type == nil {
		return ""
	}
	var str string
	if err := json.Unmarshal(s.Type, &str); err == nil {
		return str
	}
	var arr []string
	if err := json.Unmarshal(s.Type, &arr); err == nil {
		return strings.Join(arr, " . ")
	}
	return ""
}

// parseSetFlags parses the flags field (same format as table flags).
func (s *nftSet) parseSetFlags() []string {
	if s.Flags == nil || string(s.Flags) == "null" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(s.Flags, &arr); err == nil {
		return arr
	}
	var str string
	if err := json.Unmarshal(s.Flags, &str); err == nil {
		return []string{str}
	}
	return nil
}

// parseSetElements extracts set elements as string representations.
// Elements can be simple values or complex structures (ranges, prefixes, etc.).
func (s *nftSet) parseSetElements() []string {
	if s.Elem == nil || string(s.Elem) == "null" {
		return nil
	}
	var elems []any
	if err := json.Unmarshal(s.Elem, &elems); err != nil {
		return nil
	}
	var result []string
	for _, elem := range elems {
		result = append(result, nftElemToString(elem))
	}
	return result
}

// nftElemToString converts a single set element to its string representation.
func nftElemToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case map[string]any:
		// Handle prefix: {"prefix": {"addr": "10.0.0.0", "len": 8}}
		if prefix, ok := x["prefix"].(map[string]any); ok {
			addr, _ := prefix["addr"].(string)
			length, _ := prefix["len"].(float64)
			return addr + "/" + strconv.FormatInt(int64(length), 10)
		}
		// Handle range: {"range": ["start", "end"]}
		if rng, ok := x["range"].([]any); ok && len(rng) == 2 {
			return nftElemToString(rng[0]) + "-" + nftElemToString(rng[1])
		}
		// Handle concat: {"concat": ["val1", "val2"]}
		if concat, ok := x["concat"].([]any); ok {
			parts := make([]string, len(concat))
			for i, c := range concat {
				parts[i] = nftElemToString(c)
			}
			return strings.Join(parts, " . ")
		}
		// Handle elem with map value: {"elem": {"val": x, "timeout": n, ...}}
		if val, ok := x["val"]; ok {
			return nftElemToString(val)
		}
		// Fallback: JSON encode
		b, _ := json.Marshal(x)
		return string(b)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseNftRuleset(data []byte) (*nftRuleset, error) {
	var ruleset nftRuleset
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&ruleset); err != nil {
		return nil, fmt.Errorf("failed to parse nftables JSON: %w", err)
	}
	// Convert json.Number values in rule expressions to native Go types
	// so they are compatible with llx dict handling (which expects int64/float64).
	for i := range ruleset.Nftables {
		if r := ruleset.Nftables[i].Rule; r != nil {
			for j := range r.Expr {
				r.Expr[j] = convertJSONNumbers(r.Expr[j])
			}
		}
	}
	return &ruleset, nil
}

// convertJSONNumbers recursively walks a value decoded with UseNumber()
// and replaces json.Number with int64 (preferred) or float64.
func convertJSONNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		for k, val := range x {
			x[k] = convertJSONNumbers(val)
		}
		return x
	case []any:
		for i, val := range x {
			x[i] = convertJSONNumbers(val)
		}
		return x
	default:
		return v
	}
}

type mqlNftablesInternal struct {
	fetched      bool
	cacheRuleset *nftRuleset
	lock         sync.Mutex
}

func (n *mqlNftables) id() (string, error) {
	return "nftables", nil
}

func (t *mqlNftablesTable) id() (string, error) {
	return t.Family.Data + "/" + t.Name.Data, nil
}

func (c *mqlNftablesChain) id() (string, error) {
	return c.Family.Data + "/" + c.Table.Data + "/" + c.Name.Data, nil
}

func (r *mqlNftablesRule) id() (string, error) {
	return r.Family.Data + "/" + r.Table.Data + "/" + r.Chain.Data + "/" + strconv.FormatInt(r.Handle.Data, 10), nil
}

func (s *mqlNftablesSet) id() (string, error) {
	return s.Family.Data + "/" + s.Table.Data + "/" + s.Name.Data, nil
}

func (c *mqlNftablesChain) tableRef() (*mqlNftablesTable, error) {
	return nftLookupTable(c.MqlRuntime, c.Family.Data, c.Table.Data)
}

func (r *mqlNftablesRule) tableRef() (*mqlNftablesTable, error) {
	return nftLookupTable(r.MqlRuntime, r.Family.Data, r.Table.Data)
}

func (r *mqlNftablesRule) chainRef() (*mqlNftablesChain, error) {
	raw, err := NewResource(r.MqlRuntime, "nftables.chain", map[string]*llx.RawData{
		"family": llx.StringData(r.Family.Data),
		"table":  llx.StringData(r.Table.Data),
		"name":   llx.StringData(r.Chain.Data),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlNftablesChain), nil
}

func (s *mqlNftablesSet) tableRef() (*mqlNftablesTable, error) {
	return nftLookupTable(s.MqlRuntime, s.Family.Data, s.Table.Data)
}

func nftLookupTable(runtime *plugin.Runtime, family, name string) (*mqlNftablesTable, error) {
	raw, err := NewResource(runtime, "nftables.table", map[string]*llx.RawData{
		"family": llx.StringData(family),
		"name":   llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlNftablesTable), nil
}

// fetchRuleset lazily fetches and caches the nft JSON ruleset.
func (n *mqlNftables) fetchRuleset() (*nftRuleset, error) {
	if n.fetched {
		return n.cacheRuleset, nil
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.fetched {
		return n.cacheRuleset, nil
	}

	conn, ok := n.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		n.fetched = true
		return nil, nil
	}

	o, err := CreateResource(n.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("nft -j list ruleset"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		return nil, fmt.Errorf("nft command failed (exit %d): %s", run.exitcode, run.stderr)
	}

	ruleset, err := parseNftRuleset([]byte(run.stdout))
	if err != nil {
		return nil, err
	}
	n.cacheRuleset = ruleset
	n.fetched = true
	return ruleset, nil
}

func (n *mqlNftables) version() (string, error) {
	ruleset, err := n.fetchRuleset()
	if err != nil {
		return "", err
	}
	if ruleset == nil {
		return "", nil
	}
	for _, obj := range ruleset.Nftables {
		if obj.Metainfo != nil {
			return obj.Metainfo.Version, nil
		}
	}
	return "", nil
}

func (n *mqlNftables) tables() ([]any, error) {
	ruleset, err := n.fetchRuleset()
	if err != nil {
		return nil, err
	}
	if ruleset == nil {
		return nil, nil
	}

	tables := []any{}
	for _, obj := range ruleset.Nftables {
		if obj.Table == nil {
			continue
		}
		t := obj.Table

		parsedFlags := t.parseFlags()
		flags := make([]any, len(parsedFlags))
		for i, f := range parsedFlags {
			flags[i] = f
		}

		// Collect chains for this table
		chains := []any{}
		for _, o := range ruleset.Nftables {
			if o.Chain == nil || o.Chain.Family != t.Family || o.Chain.Table != t.Name {
				continue
			}
			ch := o.Chain

			chainRules, err := nftCollectRules(n.MqlRuntime, ruleset, t.Family, t.Name, ch.Name)
			if err != nil {
				return nil, err
			}

			isBase := ch.Type != ""
			chainRes, err := CreateResource(n.MqlRuntime, "nftables.chain", map[string]*llx.RawData{
				"family":      llx.StringData(ch.Family),
				"table":       llx.StringData(ch.Table),
				"name":        llx.StringData(ch.Name),
				"handle":      llx.IntData(ch.Handle),
				"type":        llx.StringData(ch.Type),
				"hook":        llx.StringData(ch.Hook),
				"prio":        llx.IntData(ch.Prio),
				"policy":      llx.StringData(ch.Policy),
				"isBaseChain": llx.BoolData(isBase),
				"rules":       llx.ArrayData(chainRules, types.Resource("nftables.rule")),
			})
			if err != nil {
				return nil, err
			}
			chains = append(chains, chainRes)
		}

		// Collect all rules for this table across all chains
		tableRules, err := nftCollectRules(n.MqlRuntime, ruleset, t.Family, t.Name, "")
		if err != nil {
			return nil, err
		}

		// Collect sets for this table
		tableSets, err := nftCollectSets(n.MqlRuntime, ruleset, t.Family, t.Name)
		if err != nil {
			return nil, err
		}

		tableRes, err := CreateResource(n.MqlRuntime, "nftables.table", map[string]*llx.RawData{
			"family": llx.StringData(t.Family),
			"name":   llx.StringData(t.Name),
			"handle": llx.IntData(t.Handle),
			"flags":  llx.ArrayData(flags, types.String),
			"chains": llx.ArrayData(chains, types.Resource("nftables.chain")),
			"rules":  llx.ArrayData(tableRules, types.Resource("nftables.rule")),
			"sets":   llx.ArrayData(tableSets, types.Resource("nftables.set")),
		})
		if err != nil {
			return nil, err
		}
		tables = append(tables, tableRes)
	}

	return tables, nil
}

func (n *mqlNftables) chains() ([]any, error) {
	tablesRaw := n.GetTables()
	if tablesRaw.Error != nil {
		return nil, tablesRaw.Error
	}
	var allChains []any
	for _, tRaw := range tablesRaw.Data {
		t := tRaw.(*mqlNftablesTable)
		chainsVal := t.GetChains()
		if chainsVal.Error != nil {
			return nil, chainsVal.Error
		}
		allChains = append(allChains, chainsVal.Data...)
	}
	return allChains, nil
}

func (n *mqlNftables) rules() ([]any, error) {
	tablesRaw := n.GetTables()
	if tablesRaw.Error != nil {
		return nil, tablesRaw.Error
	}
	var allRules []any
	for _, tRaw := range tablesRaw.Data {
		t := tRaw.(*mqlNftablesTable)
		rulesVal := t.GetRules()
		if rulesVal.Error != nil {
			return nil, rulesVal.Error
		}
		allRules = append(allRules, rulesVal.Data...)
	}
	return allRules, nil
}

func (n *mqlNftables) sets() ([]any, error) {
	tablesRaw := n.GetTables()
	if tablesRaw.Error != nil {
		return nil, tablesRaw.Error
	}
	var allSets []any
	for _, tRaw := range tablesRaw.Data {
		t := tRaw.(*mqlNftablesTable)
		setsVal := t.GetSets()
		if setsVal.Error != nil {
			return nil, setsVal.Error
		}
		allSets = append(allSets, setsVal.Data...)
	}
	return allSets, nil
}

// nftCollectRules creates rule resources filtered by family/table and optionally chain.
// If chain is empty, all rules for the table are returned.
func nftCollectRules(runtime *plugin.Runtime, ruleset *nftRuleset, family, table, chain string) ([]any, error) {
	var rules []any
	for _, obj := range ruleset.Nftables {
		if obj.Rule == nil {
			continue
		}
		r := obj.Rule
		if r.Family != family || r.Table != table {
			continue
		}
		if chain != "" && r.Chain != chain {
			continue
		}

		exprDicts := make([]any, len(r.Expr))
		copy(exprDicts, r.Expr)

		ruleRes, err := CreateResource(runtime, "nftables.rule", map[string]*llx.RawData{
			"family":  llx.StringData(r.Family),
			"table":   llx.StringData(r.Table),
			"chain":   llx.StringData(r.Chain),
			"handle":  llx.IntData(r.Handle),
			"expr":    llx.ArrayData(exprDicts, types.Dict),
			"comment": llx.StringData(r.Comment),
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, ruleRes)
	}
	return rules, nil
}

// nftCollectSets creates set resources filtered by family/table.
func nftCollectSets(runtime *plugin.Runtime, ruleset *nftRuleset, family, table string) ([]any, error) {
	var sets []any
	for _, obj := range ruleset.Nftables {
		if obj.Set == nil {
			continue
		}
		s := obj.Set
		if s.Family != family || s.Table != table {
			continue
		}

		setRes, err := nftCreateSetResource(runtime, s)
		if err != nil {
			return nil, err
		}
		sets = append(sets, setRes)
	}
	return sets, nil
}

// nftCreateSetResource builds a single nftables.set MQL resource from a parsed nftSet.
func nftCreateSetResource(runtime *plugin.Runtime, s *nftSet) (any, error) {
	keyType := s.parseKeyType()
	valueType := s.Map

	parsedFlags := s.parseSetFlags()
	flags := make([]any, len(parsedFlags))
	for i, f := range parsedFlags {
		flags[i] = f
	}

	parsedElems := s.parseSetElements()
	elements := make([]any, len(parsedElems))
	for i, e := range parsedElems {
		elements[i] = e
	}

	isMap := valueType != ""

	return CreateResource(runtime, "nftables.set", map[string]*llx.RawData{
		"family":    llx.StringData(s.Family),
		"table":     llx.StringData(s.Table),
		"name":      llx.StringData(s.Name),
		"handle":    llx.IntData(s.Handle),
		"keyType":   llx.StringData(keyType),
		"valueType": llx.StringData(valueType),
		"flags":     llx.ArrayData(flags, types.String),
		"elements":  llx.ArrayData(elements, types.String),
		"isMap":     llx.BoolData(isMap),
		"timeout":   llx.IntData(s.Timeout),
	})
}

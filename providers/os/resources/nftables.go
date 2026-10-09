// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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

	// textVersion is set when the ruleset was read from the text output of
	// an nft release that cannot list it as JSON. Text output carries no
	// structured rule expressions, so rules are not available.
	textVersion string
}

// nftObject represents one element in the nftables array.
// Exactly one field will be non-nil per object.
type nftObject struct {
	Metainfo *nftMetainfo `json:"metainfo,omitempty"`
	Table    *nftTable    `json:"table,omitempty"`
	Chain    *nftChain    `json:"chain,omitempty"`
	Rule     *nftRule     `json:"rule,omitempty"`
	Set      *nftSet      `json:"set,omitempty"`
	// Map is a named map (`map portmap { type inet_service : verdict }`).
	// nft emits it under its own "map" key with the same shape as a set
	// plus the value type in nftSet.Map.
	Map *nftSet `json:"map,omitempty"`
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

	// noHandle is set when the text output printed no handle.
	noHandle bool
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

	// noHandle is set when the text output printed no handle.
	noHandle bool
	// noPrio is set when the text output printed a priority that does not
	// resolve to a number.
	noPrio bool
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

	// noHandle is set when the text output printed no handle.
	noHandle bool
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
		// A map element is a [key, value] pair, rendered as nft prints it:
		// "9001 : drop".
		if pair, ok := elem.([]any); ok && len(pair) == 2 {
			result = append(result, nftElemToString(pair[0])+" : "+nftElemToString(pair[1]))
			continue
		}
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
		// Handle an element carrying per-element attributes:
		// {"elem": {"val": x, "timeout": n, "expires": n, ...}}
		if inner, ok := x["elem"].(map[string]any); ok {
			if val, ok := inner["val"]; ok {
				return nftElemToString(val)
			}
		}
		if val, ok := x["val"]; ok {
			return nftElemToString(val)
		}
		// Handle a verdict map value: {"drop": null}, {"accept": null},
		// {"jump": {"target": "chain"}}, {"goto": {"target": "chain"}}.
		if len(x) == 1 {
			for verdict, arg := range x {
				if arg == nil {
					return verdict
				}
				if m, ok := arg.(map[string]any); ok {
					if target, ok := m["target"].(string); ok {
						return verdict + " " + target
					}
				}
			}
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

// nftTextHeader matches the opening line of a table, chain, set, or map
// block in `nft -a list ruleset` output, with the handle comment that nft
// 0.9.0 prints and 0.8.x omits on table, chain, and set lines.
var nftTextHeader = regexp.MustCompile(`^(table|chain|set|map)\s+(.+?)\s*\{(?:\s*# handle (\d+))?$`)

// parseNftText reads the ruleset from the text output of
// `nft -a -nn list ruleset`, for nft releases that cannot list it as JSON.
// It yields tables, chains, sets, and maps. Rules are skipped, because the
// text form of a rule cannot be turned into the expression list of the JSON
// output without the full nft grammar.
func parseNftText(out string) (*nftRuleset, error) {
	ruleset := &nftRuleset{}
	var (
		table *nftTable
		chain *nftChain
		set   *nftSet
		// skip counts the open braces of a block this parser does not read,
		// such as a flowtable or a named counter.
		skip int
		// elems collects an `elements = { ... }` list that spans lines.
		elems     strings.Builder
		inElems   bool
		setIsMap  bool
		lineCount int
	)

	for _, raw := range strings.Split(out, "\n") {
		lineCount++
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if skip > 0 {
			skip += strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inElems {
			elems.WriteString(" ")
			elems.WriteString(line)
			if nftTextClosesBrace(elems.String()) {
				inElems = false
				set.Elem = nftTextElements(elems.String())
			}
			continue
		}

		switch {
		case set != nil:
			if line == "}" {
				obj := nftObject{Set: set}
				if setIsMap {
					obj = nftObject{Map: set}
				}
				ruleset.Nftables = append(ruleset.Nftables, obj)
				set = nil
				continue
			}
			key, val, _ := strings.Cut(line, " ")
			val = strings.TrimSpace(val)
			switch key {
			case "type":
				keyType, valueType, isMap := strings.Cut(val, " : ")
				set.Type, _ = json.Marshal(strings.TrimSpace(keyType))
				if isMap {
					set.Map = strings.TrimSpace(valueType)
				}
			case "flags":
				set.Flags = nftTextFlags(val)
			case "timeout":
				secs, err := parseNftTime(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: set %s: %w", lineCount, set.Name, err)
				}
				set.Timeout = secs
			case "elements":
				elems.Reset()
				elems.WriteString(strings.TrimSpace(strings.TrimPrefix(val, "=")))
				if nftTextClosesBrace(elems.String()) {
					set.Elem = nftTextElements(elems.String())
				} else {
					inElems = true
				}
			}

		case chain != nil:
			// A rule line never consists of a lone brace, so this closes the
			// chain even when rules carry anonymous sets in braces.
			if line == "}" {
				ruleset.Nftables = append(ruleset.Nftables, nftObject{Chain: chain})
				chain = nil
				continue
			}
			if strings.HasPrefix(line, "type ") && chain.Type == "" {
				nftTextBaseChain(chain, line)
			}

		case table != nil:
			if line == "}" {
				table = nil
				continue
			}
			m := nftTextHeader.FindStringSubmatch(line)
			if m == nil {
				if v, ok := strings.CutPrefix(line, "flags "); ok {
					table.Flags = nftTextFlags(v)
					continue
				}
				if open := strings.Count(line, "{") - strings.Count(line, "}"); open > 0 {
					skip = open
				}
				continue
			}
			handle, noHandle := nftTextHandle(m[3])
			switch m[1] {
			case "chain":
				chain = &nftChain{Family: table.Family, Table: table.Name, Name: m[2], Handle: handle, noHandle: noHandle}
			case "set", "map":
				set = &nftSet{Family: table.Family, Table: table.Name, Name: m[2], Handle: handle, noHandle: noHandle}
				setIsMap = m[1] == "map"
			default:
				return nil, fmt.Errorf("line %d: unexpected %q inside table %s", lineCount, line, table.Name)
			}

		default:
			m := nftTextHeader.FindStringSubmatch(line)
			if m == nil || m[1] != "table" {
				return nil, fmt.Errorf("line %d: expected a table, got %q", lineCount, line)
			}
			family, name, ok := strings.Cut(m[2], " ")
			if !ok {
				return nil, fmt.Errorf("line %d: table without a family: %q", lineCount, line)
			}
			handle, noHandle := nftTextHandle(m[3])
			table = &nftTable{Family: family, Name: strings.TrimSpace(name), Handle: handle, noHandle: noHandle}
			ruleset.Nftables = append(ruleset.Nftables, nftObject{Table: table})
		}
	}

	if table != nil || chain != nil || set != nil || skip > 0 || inElems {
		return nil, errors.New("nft text output ended inside an open block")
	}
	return ruleset, nil
}

func nftTextHandle(s string) (handle int64, noHandle bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, true
	}
	return n, false
}

// nftTextFlags reads a comma-separated flags line ("interval,timeout") into
// the JSON form the flag parsers expect.
func nftTextFlags(s string) json.RawMessage {
	var flags []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			flags = append(flags, f)
		}
	}
	b, _ := json.Marshal(flags)
	return b
}

// nftTextBaseChain reads the line that makes a chain a base chain:
// "type filter hook input priority 0; policy drop;". A netdev chain names
// its device as well: "type filter hook ingress device eth0 priority 0;".
func nftTextBaseChain(chain *nftChain, line string) {
	fields := strings.Fields(strings.ReplaceAll(line, ";", " "))
	for i := 0; i+1 < len(fields); i++ {
		val := fields[i+1]
		switch fields[i] {
		case "type":
			chain.Type = val
		case "hook":
			chain.Hook = val
		case "policy":
			chain.Policy = val
		case "priority":
			prio, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				chain.noPrio = true
				continue
			}
			chain.Prio = prio
		default:
			continue
		}
		i++
	}
}

// nftTextClosesBrace reports whether an elements list, starting at its
// opening brace, has reached its closing brace outside a quoted string.
func nftTextClosesBrace(s string) bool {
	depth, quoted := 0, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case quoted:
		case r == '{':
			depth++
		case r == '}':
			depth--
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// nftTextElementAttrs are the per-element attributes nft prints after an
// element's value. The JSON path reports the value only.
var nftTextElementAttrs = []string{" timeout ", " expires ", " counter ", " comment "}

// nftTextElements reads "{ 10.0.0.0/8, 22 : accept, 192.0.2.99 timeout 10m }"
// into the JSON element list that parseSetElements renders. Values keep the
// text nft printed, which is the same string the JSON path renders for
// prefixes, ranges, concatenations, and map entries.
func nftTextElements(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	if i := strings.LastIndex(s, "}"); i >= 0 {
		s = s[:i]
	}

	var elems []any
	var cur strings.Builder
	quoted := false
	flush := func() {
		if e := nftTextElement(cur.String()); e != "" {
			elems = append(elems, e)
		}
		cur.Reset()
	}
	for _, r := range s {
		if r == '"' {
			quoted = !quoted
		}
		if r == ',' && !quoted {
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()

	b, _ := json.Marshal(elems)
	return b
}

func nftTextElement(e string) string {
	e = strings.Join(strings.Fields(e), " ")
	key, val, isMap := strings.Cut(e, " : ")
	for _, attr := range nftTextElementAttrs {
		if i := strings.Index(key+" ", attr); i >= 0 {
			key = key[:i]
		}
	}
	if isMap {
		return key + " : " + val
	}
	return key
}

// nftTimeUnits are the units of an nft time value ("1d2h30m10s500ms"),
// longest suffix first so "ms" is not read as minutes.
var nftTimeUnits = []struct {
	suffix string
	millis int64
}{
	{"ms", 1},
	{"d", 24 * 60 * 60 * 1000},
	{"h", 60 * 60 * 1000},
	{"m", 60 * 1000},
	{"s", 1000},
}

// parseNftTime reads an nft time value into whole seconds, the unit of the
// JSON timeout field.
func parseNftTime(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty nft time")
	}
	rest := s
	var millis int64
	for rest != "" {
		i := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
		if i <= 0 {
			return 0, fmt.Errorf("cannot read nft time %q", s)
		}
		n, err := strconv.ParseInt(rest[:i], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot read nft time %q", s)
		}
		rest = rest[i:]
		found := false
		for _, u := range nftTimeUnits {
			if strings.HasPrefix(rest, u.suffix) {
				millis += n * u.millis
				rest = rest[len(u.suffix):]
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("cannot read nft time %q", s)
		}
	}
	return millis / 1000, nil
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

	versionFetched bool
	cacheVersion   string
	versionLock    sync.Mutex
}

// nftMinJSONVersion is the first nft release whose `nft -j list ruleset`
// output this resource can read. nft 0.8.x has no -j option at all. nft 0.9.0
// has an early JSON output that predates the metainfo object and aborts with
// an assertion (stmt_print_json: Assertion `__out' failed) on statements it
// cannot serialize, such as the counter and jump rules iptables-nft writes.
// nft 0.9.1 reworked the JSON schema and added metainfo to all output.
var nftMinJSONVersion = [3]int{0, 9, 1}

// parseNftVersion extracts the version from `nft --version` output, which is
// "nftables v<version> (<release name>)" on every release from 0.8 to 1.1.
func parseNftVersion(out string) string {
	for _, field := range strings.Fields(out) {
		if len(field) > 1 && field[0] == 'v' && field[1] >= '0' && field[1] <= '9' {
			return field[1:]
		}
	}
	return ""
}

// nftVersionSupportsJSON reports whether an nft version can produce the JSON
// ruleset this resource parses. ok is false when the version cannot be parsed,
// in which case the caller should try the JSON command anyway.
func nftVersionSupportsJSON(version string) (supported bool, ok bool) {
	parts := strings.SplitN(version, ".", 4)
	if len(parts) < 2 {
		return false, false
	}
	var v [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		// tolerate suffixes such as "1.0.6-rc1"
		num := parts[i]
		if j := strings.IndexFunc(num, func(r rune) bool { return r < '0' || r > '9' }); j >= 0 {
			num = num[:j]
		}
		n, err := strconv.Atoi(num)
		if err != nil {
			return false, false
		}
		v[i] = n
	}
	for i := range v {
		if v[i] != nftMinJSONVersion[i] {
			return v[i] > nftMinJSONVersion[i], true
		}
	}
	return true, true
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

// fetchVersion lazily runs `nft --version`, which works on every nft release,
// unlike the JSON ruleset.
func (n *mqlNftables) fetchVersion() (string, error) {
	n.versionLock.Lock()
	defer n.versionLock.Unlock()
	if n.versionFetched {
		return n.cacheVersion, nil
	}

	conn, ok := n.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		n.versionFetched = true
		return "", nil
	}

	o, err := CreateResource(n.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("nft --version"),
	})
	if err != nil {
		return "", err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return "", fmt.Errorf("nft command failed (exit %d): %s", exit.Data, cmd.Stderr.Data)
	}
	n.cacheVersion = parseNftVersion(cmd.Stdout.Data)
	n.versionFetched = true
	return n.cacheVersion, nil
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

	// Older nft either rejects -j or crashes on it, so check the version first
	// and read the text output instead.
	version, err := n.fetchVersion()
	if err != nil {
		return nil, err
	}
	command := "nft -j list ruleset"
	supported, ok := nftVersionSupportsJSON(version)
	textOnly := ok && !supported
	if textOnly {
		// -nn prints ports as numbers, as the JSON output does, instead of
		// service names.
		command = "nft -a -nn list ruleset"
	}

	o, err := CreateResource(n.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(command),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return nil, fmt.Errorf("nft command failed (exit %d): %s", exit.Data, cmd.Stderr.Data)
	}

	var ruleset *nftRuleset
	if textOnly {
		ruleset, err = parseNftText(cmd.Stdout.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nft %s ruleset text: %w", version, err)
		}
		ruleset.textVersion = version
	} else {
		ruleset, err = parseNftRuleset([]byte(cmd.Stdout.Data))
		if err != nil {
			return nil, err
		}
	}
	if !ruleset.hasTables() {
		if err := n.checkEmptyRulesetReadable(); err != nil {
			return nil, err
		}
	}
	n.cacheRuleset = ruleset
	n.fetched = true
	return ruleset, nil
}

// checkEmptyRulesetReadable tells an empty ruleset from one nft could not
// read. Listing the ruleset needs CAP_NET_ADMIN. nft 1.0 and later fail with
// "Operation not permitted" without it, but nft 0.9 (Ubuntu 20.04) swallows
// the netlink refusal and prints only the metainfo header with exit code 0,
// which looks exactly like a host without any tables. When the capability
// set cannot be read the empty ruleset is trusted as before.
//
// /proc/self is the cat process, not the scanner. cat runs through the same
// command resource as nft, on the same connection and with the same sudo
// wrapping, so its capability set stands in for the one nft ran with.
func (n *mqlNftables) checkEmptyRulesetReadable() error {
	o, err := CreateResource(n.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("cat /proc/self/status"),
	})
	if err != nil {
		return nil
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil || exit.Data != 0 {
		return nil
	}
	if has, ok := hasEffectiveCapNetAdmin(cmd.Stdout.Data); ok && !has {
		return llx.Forbidden(errors.New("nft listed an empty ruleset, but the scan runs without CAP_NET_ADMIN, so the ruleset could not be read (you must be root)"))
	}
	return nil
}

// capNetAdmin is CAP_NET_ADMIN's bit in the Linux capability sets.
const capNetAdmin = 12

// hasEffectiveCapNetAdmin reads the CapEff line of /proc/<pid>/status and
// reports whether CAP_NET_ADMIN is in the effective set. ok is false when
// the line is missing or unparsable.
func hasEffectiveCapNetAdmin(status string) (has bool, ok bool) {
	for _, line := range strings.Split(status, "\n") {
		v, found := strings.CutPrefix(line, "CapEff:")
		if !found {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return false, false
		}
		return caps&(1<<capNetAdmin) != 0, true
	}
	return false, false
}

// hasTables reports whether the listing holds at least one table. A ruleset
// with only the metainfo header is empty.
func (r *nftRuleset) hasTables() bool {
	for _, obj := range r.Nftables {
		if obj.Table != nil {
			return true
		}
	}
	return false
}

// nftRulesUnavailableError is the error on every rules field of a ruleset
// read from text. An empty list would let a check such as
// `nftables.rules.none(...)` pass without any rule having been read.
func nftRulesUnavailableError(version string) error {
	return fmt.Errorf("nft %s cannot list the ruleset as JSON; reading nftables rules requires nft %d.%d.%d or later",
		version, nftMinJSONVersion[0], nftMinJSONVersion[1], nftMinJSONVersion[2])
}

// rulesData returns the rules of one chain, or of a whole table when chain is
// empty, as the value of a rules field.
func (r *nftRuleset) rulesData(runtime *plugin.Runtime, family, table, chain string) (*llx.RawData, error) {
	ruleType := types.Array(types.Resource("nftables.rule"))
	if r.textVersion != "" {
		return &llx.RawData{Type: ruleType, Error: nftRulesUnavailableError(r.textVersion)}, nil
	}
	rules, err := nftCollectRules(runtime, r, family, table, chain)
	if err != nil {
		return nil, err
	}
	return llx.ArrayData(rules, types.Resource("nftables.rule")), nil
}

// nftHandleData is a handle as a field value, null when nft printed none.
func nftHandleData(handle int64, noHandle bool) *llx.RawData {
	if noHandle {
		return llx.NilData
	}
	return llx.IntData(handle)
}

func (n *mqlNftables) version() (string, error) {
	return n.fetchVersion()
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

			chainRules, err := ruleset.rulesData(n.MqlRuntime, t.Family, t.Name, ch.Name)
			if err != nil {
				return nil, err
			}

			prio := llx.IntData(ch.Prio)
			if ch.noPrio {
				prio = llx.NilData
			}

			isBase := ch.Type != ""
			chainRes, err := CreateResource(n.MqlRuntime, "nftables.chain", map[string]*llx.RawData{
				"family":      llx.StringData(ch.Family),
				"table":       llx.StringData(ch.Table),
				"name":        llx.StringData(ch.Name),
				"handle":      nftHandleData(ch.Handle, ch.noHandle),
				"type":        llx.StringData(ch.Type),
				"hook":        llx.StringData(ch.Hook),
				"prio":        prio,
				"policy":      llx.StringData(ch.Policy),
				"isBaseChain": llx.BoolData(isBase),
				"rules":       chainRules,
			})
			if err != nil {
				return nil, err
			}
			chains = append(chains, chainRes)
		}

		// Collect all rules for this table across all chains
		tableRules, err := ruleset.rulesData(n.MqlRuntime, t.Family, t.Name, "")
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
			"handle": nftHandleData(t.Handle, t.noHandle),
			"flags":  llx.ArrayData(flags, types.String),
			"chains": llx.ArrayData(chains, types.Resource("nftables.chain")),
			"rules":  tableRules,
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
		s := obj.Set
		if s == nil {
			s = obj.Map
		}
		if s == nil {
			continue
		}
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
		"handle":    nftHandleData(s.Handle, s.noHandle),
		"keyType":   llx.StringData(keyType),
		"valueType": llx.StringData(valueType),
		"flags":     llx.ArrayData(flags, types.String),
		"elements":  llx.ArrayData(elements, types.String),
		"isMap":     llx.BoolData(isMap),
		"timeout":   llx.IntData(s.Timeout),
	})
}

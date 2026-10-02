// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// Stat represents a structured statistic entry.
type Stat struct {
	LineNumber  int64
	Packets     int64
	Bytes       int64
	Target      string
	Protocol    string
	Opt         string
	Input       string
	Output      string
	Source      string
	Destination string
	Options     string
}

// ChainResult holds the parsed entries and default policy for a single chain.
type ChainResult struct {
	Policy  string // e.g., "ACCEPT", "DROP", "REJECT"
	Entries []Stat
}

func (ie *mqlIptablesEntry) id() (string, error) {
	return strconv.FormatInt(ie.LineNumber.Data, 10) + ie.Chain.Data, nil
}

type mqlIptablesTableInternal struct {
	ipVersion string
}

type mqlIptablesChainInternal struct {
	ipVersion string
}

func (t *mqlIptablesTable) id() (string, error) {
	return t.ipVersion + "/" + t.Name.Data, nil
}

func (c *mqlIptablesChain) id() (string, error) {
	return c.ipVersion + "/" + c.Table.Data + "/" + c.Name.Data, nil
}

// statToRawData converts a Stat into the llx data map for creating an iptables.entry resource.
// The structured option fields (dport, comment, ctstate, …) are left null/empty because the
// legacy `-L`-based parser cannot recover them from the output it sees.
func statToRawData(stat Stat, chain string) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"lineNumber":  llx.IntData(stat.LineNumber),
		"packets":     llx.IntData(stat.Packets),
		"bytes":       llx.IntData(stat.Bytes),
		"target":      llx.StringData(stat.Target),
		"protocol":    llx.StringData(stat.Protocol),
		"opt":         llx.StringData(stat.Opt),
		"in":          llx.StringData(stat.Input),
		"out":         llx.StringData(stat.Output),
		"source":      llx.StringData(stat.Source),
		"destination": llx.StringData(stat.Destination),
		"options":     llx.StringData(stat.Options),
		"chain":       llx.StringData(chain),
	}
	addNullStructuredFields(args)
	return args
}

// addNullStructuredFields seeds every iptables-save-derived field with a
// null/empty value. Regular `.lr` fields must be marked set on the resource
// or MQL refuses to read them, so we always populate them — the legacy `-L`
// parser path just sees nulls everywhere.
func addNullStructuredFields(args map[string]*llx.RawData) {
	args["dport"] = llx.IntDataPtr[int64](nil)
	args["dportRange"] = llx.StringData("")
	args["dports"] = llx.ArrayData(nil, types.String)
	args["sport"] = llx.IntDataPtr[int64](nil)
	args["sportRange"] = llx.StringData("")
	args["sports"] = llx.ArrayData(nil, types.String)
	args["ctstate"] = llx.ArrayData(nil, types.String)
	args["tcpFlags"] = llx.ArrayData(nil, types.String)
	args["comment"] = llx.StringData("")
	args["matchSet"] = llx.StringData("")
	args["rejectWith"] = llx.StringData("")
	args["raw"] = llx.StringData("")
}

// savedRuleToRawData builds an iptables.entry argument map from a SavedRule.
// lineNumber is the rule's 1-based position within its chain. ipv6 controls
// the cosmetic `opt` value and the default source/destination address used
// to mirror the legacy `-L` rendering.
func savedRuleToRawData(rule SavedRule, lineNumber int64, chainID string, ipv6 bool) map[string]*llx.RawData {
	anyAddr := "0.0.0.0/0"
	opt := "--"
	if ipv6 {
		anyAddr = "::/0"
		opt = "  "
	}

	source := rule.Source
	if source == "" {
		source = anyAddr
	}
	destination := rule.Destination
	if destination == "" {
		destination = anyAddr
	}
	in := rule.In
	if in == "" {
		in = "*"
	}
	out := rule.Out
	if out == "" {
		out = "*"
	}

	args := map[string]*llx.RawData{
		"lineNumber":  llx.IntData(lineNumber),
		"packets":     llx.IntData(rule.Packets),
		"bytes":       llx.IntData(rule.Bytes),
		"target":      llx.StringData(rule.Target),
		"protocol":    llx.StringData(rule.Protocol),
		"opt":         llx.StringData(opt),
		"in":          llx.StringData(in),
		"out":         llx.StringData(out),
		"source":      llx.StringData(source),
		"destination": llx.StringData(destination),
		"options":     llx.StringData(rule.Options),
		"chain":       llx.StringData(chainID),
		"dportRange":  llx.StringData(rule.DportRange),
		"sportRange":  llx.StringData(rule.SportRange),
		"dports":      llx.ArrayData(stringsToAny(rule.Dports), types.String),
		"sports":      llx.ArrayData(stringsToAny(rule.Sports), types.String),
		"ctstate":     llx.ArrayData(stringsToAny(rule.Ctstate), types.String),
		"tcpFlags":    llx.ArrayData(stringsToAny(rule.TCPFlags), types.String),
		"comment":     llx.StringData(rule.Comment),
		"matchSet":    llx.StringData(rule.MatchSet),
		"rejectWith":  llx.StringData(rule.RejectWith),
		"raw":         llx.StringData(rule.Raw),
	}

	if rule.HasDport && rule.Dport != 0 {
		v := int64(rule.Dport)
		args["dport"] = llx.IntDataPtr(&v)
	} else {
		args["dport"] = llx.IntDataPtr[int64](nil)
	}
	if rule.HasSport && rule.Sport != 0 {
		v := int64(rule.Sport)
		args["sport"] = llx.IntDataPtr(&v)
	} else {
		args["sport"] = llx.IntDataPtr[int64](nil)
	}

	return args
}

// chainCache stores the result of a single chain query so that both the
// entries and policy fields can be served from one shell command.
// Fields are written inside the sync.Once callback and read after Do returns;
// sync.Once guarantees happens-before visibility of all writes to subsequent callers.
type chainCache struct {
	once    sync.Once
	entries []any
	policy  string
	err     error
}

// savedDumpCache holds a parsed iptables-save dump plus a flag indicating
// whether iptables-save was even available on the target. The flag is
// distinct from `err` so we can fall back silently when the binary is
// missing while still surfacing real parse failures.
type savedDumpCache struct {
	once      sync.Once
	dump      *SavedDump
	available bool
	err       error
}

// mqlIptablesInternal caches chain results to avoid running the same
// iptables command twice when both entries and policy are queried, and
// also caches the iptables-save dump that powers the structured fields.
type mqlIptablesInternal struct {
	inputCache   chainCache
	outputCache  chainCache
	forwardCache chainCache
	tablesOnce   sync.Once
	tablesCache  []any
	tablesErr    error
	saveCache    savedDumpCache
}

// mqlIp6tablesInternal caches chain results to avoid running the same
// ip6tables command twice when both entries and policy are queried, and
// also caches the ip6tables-save dump.
type mqlIp6tablesInternal struct {
	inputCache   chainCache
	outputCache  chainCache
	forwardCache chainCache
	tablesOnce   sync.Once
	tablesCache  []any
	tablesErr    error
	saveCache    savedDumpCache
}

// fetchChain runs an iptables/ip6tables command for a chain, parses the output,
// and creates MQL entry resources. Returns entries, policy, and any error.
func fetchChain(runtime *plugin.Runtime, conn shared.Connection, binary, chainName, mqlChainID string, ipv6 bool) ([]any, string, error) {
	cmd, err := conn.RunCommand(fmt.Sprintf("%s -L %s -v -n -x --line-numbers", binary, chainName))
	if err != nil {
		return nil, "", err
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, "", err
	}
	if cmd.ExitStatus != 0 {
		outErr, _ := io.ReadAll(cmd.Stderr)
		return nil, "", errors.New(string(outErr))
	}

	lines := getLines(string(data))
	result, err := ParseChain(lines, ipv6)
	if err != nil {
		return nil, "", err
	}

	entries := make([]any, 0, len(result.Entries))
	for _, stat := range result.Entries {
		entry, err := CreateResource(runtime, "iptables.entry", statToRawData(stat, mqlChainID))
		if err != nil {
			return nil, "", err
		}
		entries = append(entries, entry.(*mqlIptablesEntry))
	}
	return entries, result.Policy, nil
}

// iptablesTableNames lists the standard tables to query.
var iptablesTableNames = []string{"filter", "nat", "mangle", "raw"}

// fetchAllTables runs `iptables -t <table> -L -v -n -x --line-numbers` for each
// table and returns MQL table resources containing chains and entries.
func fetchAllTables(runtime *plugin.Runtime, conn shared.Connection, binary string, ipv6 bool) ([]any, error) {
	ver := "ipv4"
	if ipv6 {
		ver = "ipv6"
	}

	var tables []any
	for _, tableName := range iptablesTableNames {
		// tableName comes from the compile-time iptablesTableNames constant.
		cmd, err := conn.RunCommand(fmt.Sprintf("%s -t %s -L -v -n -x --line-numbers", binary, tableName))
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			return nil, err
		}
		if cmd.ExitStatus != 0 {
			stderr, _ := io.ReadAll(cmd.Stderr)
			if absent, err := classifyIptablesTableError(binary, tableName, string(stderr)); absent {
				continue
			} else {
				return nil, err
			}
		}

		chains, err := parseAllChains(runtime, string(data), tableName, ver, ipv6)
		if err != nil {
			return nil, err
		}
		if len(chains) == 0 {
			continue
		}

		tableRes, err := CreateResource(runtime, "iptables.table", map[string]*llx.RawData{
			"name":   llx.StringData(tableName),
			"chains": llx.ArrayData(chains, types.Resource("iptables.chain")),
		})
		if err != nil {
			return nil, err
		}
		tableRes.(*mqlIptablesTable).ipVersion = ver
		tables = append(tables, tableRes)
	}
	return tables, nil
}

// classifyIptablesTableError decides what a failed `<binary> -t <table> -L`
// means. It returns absent=true when the table does not exist on this kernel
// (raw or mangle not loaded), which callers skip. Any other failure is an
// error. A permission refusal is reported as forbidden: iptables 1.6 words it
// "can't initialize iptables table `filter': Permission denied (you must be
// root)", which shares its prefix with the table-missing message, so the
// refusal has to be checked first or a non-root scan reads as no tables.
func classifyIptablesTableError(binary, tableName, stderr string) (bool, error) {
	errMsg := strings.TrimSpace(stderr)
	err := fmt.Errorf("%s -t %s failed: %s", binary, tableName, errMsg)
	lower := strings.ToLower(errMsg)
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "you must be root") {
		return false, llx.Forbidden(err)
	}
	if strings.Contains(errMsg, "does not exist") ||
		strings.Contains(errMsg, "No such file or directory") ||
		strings.Contains(errMsg, "can't initialize") {
		return true, nil
	}
	return false, err
}

// parseAllChains parses the full output of `iptables -t <table> -L` which
// contains multiple chain blocks separated by blank lines.
func parseAllChains(runtime *plugin.Runtime, output, tableName, ipVersion string, ipv6 bool) ([]any, error) {
	blocks := splitChainBlocks(output)
	var chains []any

	for _, block := range blocks {
		lines := getLines(block)
		if len(lines) < 2 {
			continue
		}

		chainName := parseChainName(lines[0])
		if chainName == "" {
			continue
		}

		result, err := ParseChain(lines, ipv6)
		if err != nil {
			return nil, err
		}

		chainID := ipVersion + "/" + tableName + "/" + chainName
		entries := make([]any, 0, len(result.Entries))
		for _, stat := range result.Entries {
			entry, err := CreateResource(runtime, "iptables.entry", statToRawData(stat, chainID))
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}

		chainRes, err := CreateResource(runtime, "iptables.chain", map[string]*llx.RawData{
			"table":  llx.StringData(tableName),
			"name":   llx.StringData(chainName),
			"policy": llx.StringData(result.Policy),
			"rules":  llx.ArrayData(entries, types.Resource("iptables.entry")),
		})
		if err != nil {
			return nil, err
		}
		chainRes.(*mqlIptablesChain).ipVersion = ipVersion
		chains = append(chains, chainRes)
	}
	return chains, nil
}

// splitChainBlocks splits the output of `iptables -L` (all chains) into
// individual chain blocks. Each block starts with "Chain ..." and is
// separated by empty lines.
func splitChainBlocks(output string) []string {
	var blocks []string
	var current []string

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Chain ") && len(current) > 0 {
			blocks = append(blocks, strings.Join(current, "\n"))
			current = nil
		}
		if line == "" && len(current) > 0 {
			continue
		}
		if line != "" || len(current) > 0 {
			current = append(current, line)
		}
	}
	if len(current) > 0 {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

// reChainName matches "Chain CHAINNAME (...)" and extracts the chain name.
var reChainName = regexp.MustCompile(`^Chain\s+(\S+)`)

// parseChainName extracts the chain name from a chain header line.
func parseChainName(line string) string {
	m := reChainName.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

// loadSavedDump runs `<binary>-save -c` once and parses the output. The
// `available` flag is false when the save binary is missing or denied so
// callers can fall back to the legacy `-L` parser silently. Real parse
// errors come back through `err`.
func loadSavedDump(conn shared.Connection, binary string) (*SavedDump, bool, error) {
	saveBin := binary + "-save"
	cmd, err := conn.RunCommand(saveBin + " -c")
	if err != nil {
		// Command setup failed before invocation — treat as unavailable.
		return nil, false, nil
	}
	stdout, _ := io.ReadAll(cmd.Stdout)
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		msg := strings.ToLower(strings.TrimSpace(string(stderr)))
		// "command not found" / missing-binary cases → silent fallback.
		if msg == "" ||
			strings.Contains(msg, "not found") ||
			strings.Contains(msg, "no such file") ||
			strings.Contains(msg, "permission denied") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%s exited %d: %s", saveBin, cmd.ExitStatus, msg)
	}
	dump, err := ParseIptablesSave(string(stdout))
	if err != nil {
		return nil, false, err
	}
	// iptables-save 1.6 (Ubuntu 16.04) run without root cannot read
	// /proc/net/ip_tables_names, yet exits 0 with no output. Every kernel
	// with iptables loaded lists at least one table, so an empty dump is not
	// trusted: fall back to `-L`, which reports the refusal.
	if len(dump.Tables) == 0 {
		return nil, false, nil
	}
	return dump, true, nil
}

// applyDump uses a parsed iptables-save dump to populate every cache on
// the receiver. It returns true when the dump was successfully applied so
// callers know to skip the legacy fallback. mqlIptablesInternal /
// mqlIp6tablesInternal share this code through the iptablesAccessor
// interface.
func applyDump(runtime *plugin.Runtime, dump *SavedDump, ipv6 bool, caches dumpTarget) error {
	ver := "ipv4"
	if ipv6 {
		ver = "ipv6"
	}

	// Build full table resources for tables().
	tables := make([]any, 0, len(dump.Tables))
	for _, t := range dump.Tables {
		chains, err := buildChainsFromSaved(runtime, t, ver, ipv6)
		if err != nil {
			return err
		}
		if len(chains) == 0 {
			continue
		}
		tableRes, err := CreateResource(runtime, "iptables.table", map[string]*llx.RawData{
			"name":   llx.StringData(t.Name),
			"chains": llx.ArrayData(chains, types.Resource("iptables.chain")),
		})
		if err != nil {
			return err
		}
		tableRes.(*mqlIptablesTable).ipVersion = ver
		tables = append(tables, tableRes)
	}
	caches.setTables(tables)

	// Populate the shortcut INPUT/OUTPUT/FORWARD caches from the filter table.
	filter := findTable(dump, "filter")
	if filter != nil {
		for _, ch := range filter.Chains {
			entries, err := entriesFromSavedChain(runtime, ch, caches.shortcutChainID(ch.Name), ipv6)
			if err != nil {
				return err
			}
			switch ch.Name {
			case "INPUT":
				caches.setShortcut("INPUT", entries, ch.Policy)
			case "OUTPUT":
				caches.setShortcut("OUTPUT", entries, ch.Policy)
			case "FORWARD":
				caches.setShortcut("FORWARD", entries, ch.Policy)
			}
		}
	}
	return nil
}

// dumpTarget abstracts over mqlIptables and mqlIp6tables so applyDump can
// write into both. The shortcutChainID returns the short chain identifier
// that the legacy entry creation path used (e.g., "input"/"input6") to keep
// `iptables.entry.chain` stable for queries from the shortcut accessors.
type dumpTarget interface {
	setTables(tables []any)
	setShortcut(name string, entries []any, policy string)
	shortcutChainID(name string) string
}

func findTable(dump *SavedDump, name string) *SavedTable {
	for _, t := range dump.Tables {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// buildChainsFromSaved turns a SavedTable's chains into iptables.chain MQL
// resources, each with its iptables.entry rules.
func buildChainsFromSaved(runtime *plugin.Runtime, t *SavedTable, ver string, ipv6 bool) ([]any, error) {
	chains := make([]any, 0, len(t.Chains))
	for _, ch := range t.Chains {
		chainID := ver + "/" + t.Name + "/" + ch.Name
		entries, err := entriesFromSavedChain(runtime, ch, chainID, ipv6)
		if err != nil {
			return nil, err
		}
		chainRes, err := CreateResource(runtime, "iptables.chain", map[string]*llx.RawData{
			"table":  llx.StringData(t.Name),
			"name":   llx.StringData(ch.Name),
			"policy": llx.StringData(ch.Policy),
			"rules":  llx.ArrayData(entries, types.Resource("iptables.entry")),
		})
		if err != nil {
			return nil, err
		}
		chainRes.(*mqlIptablesChain).ipVersion = ver
		chains = append(chains, chainRes)
	}
	return chains, nil
}

// entriesFromSavedChain materializes iptables.entry resources for every rule
// in a chain. The 1-based lineNumber mirrors what `-L --line-numbers` emits.
func entriesFromSavedChain(runtime *plugin.Runtime, ch *SavedChain, chainID string, ipv6 bool) ([]any, error) {
	entries := make([]any, 0, len(ch.Rules))
	for idx, rule := range ch.Rules {
		entry, err := CreateResource(runtime, "iptables.entry", savedRuleToRawData(rule, int64(idx+1), chainID, ipv6))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// --- iptables (IPv4) ---

// loadDump runs iptables-save -c at most once and caches the result.
func (i *mqlIptables) loadDump() (*SavedDump, bool, error) {
	i.saveCache.once.Do(func() {
		conn := i.MqlRuntime.Connection.(shared.Connection)
		i.saveCache.dump, i.saveCache.available, i.saveCache.err = loadSavedDump(conn, "iptables")
		if i.saveCache.available && i.saveCache.err == nil {
			if applyErr := applyDump(i.MqlRuntime, i.saveCache.dump, false, (*iptablesDumpTarget)(i)); applyErr != nil {
				i.saveCache.err = applyErr
				i.saveCache.available = false
			}
		}
	})
	return i.saveCache.dump, i.saveCache.available, i.saveCache.err
}

// iptablesDumpTarget adapts mqlIptables to the dumpTarget interface used by
// applyDump. It writes results directly into the receiver's caches and marks
// the per-chain `once` flags as fired so the legacy fetchers never run.
type iptablesDumpTarget mqlIptables

func (t *iptablesDumpTarget) setTables(tables []any) {
	i := (*mqlIptables)(t)
	i.tablesCache = tables
	i.tablesOnce.Do(func() {}) // mark as fired so tables() returns the cache
}

func (t *iptablesDumpTarget) setShortcut(name string, entries []any, policy string) {
	i := (*mqlIptables)(t)
	var c *chainCache
	switch name {
	case "INPUT":
		c = &i.inputCache
	case "OUTPUT":
		c = &i.outputCache
	case "FORWARD":
		c = &i.forwardCache
	default:
		return
	}
	c.entries = entries
	c.policy = policy
	c.once.Do(func() {})
}

func (t *iptablesDumpTarget) shortcutChainID(name string) string {
	switch name {
	case "INPUT":
		return "input"
	case "OUTPUT":
		return "output"
	case "FORWARD":
		return "forward"
	}
	return name
}

func (i *mqlIptables) fetchInput() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.inputCache.entries, i.inputCache.policy, i.inputCache.err =
		fetchChain(i.MqlRuntime, conn, "iptables", "INPUT", "input", false)
}

func (i *mqlIptables) fetchOutput() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.outputCache.entries, i.outputCache.policy, i.outputCache.err =
		fetchChain(i.MqlRuntime, conn, "iptables", "OUTPUT", "output", false)
}

func (i *mqlIptables) fetchForward() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.forwardCache.entries, i.forwardCache.policy, i.forwardCache.err =
		fetchChain(i.MqlRuntime, conn, "iptables", "FORWARD", "forward", false)
}

func (i *mqlIptables) input() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.inputCache.once.Do(i.fetchInput)
	return i.inputCache.entries, i.inputCache.err
}

func (i *mqlIptables) output() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.outputCache.once.Do(i.fetchOutput)
	return i.outputCache.entries, i.outputCache.err
}

func (i *mqlIptables) forward() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.forwardCache.once.Do(i.fetchForward)
	return i.forwardCache.entries, i.forwardCache.err
}

func (i *mqlIptables) inputPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.inputCache.once.Do(i.fetchInput)
	return i.inputCache.policy, i.inputCache.err
}

func (i *mqlIptables) outputPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.outputCache.once.Do(i.fetchOutput)
	return i.outputCache.policy, i.outputCache.err
}

func (i *mqlIptables) forwardPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.forwardCache.once.Do(i.fetchForward)
	return i.forwardCache.policy, i.forwardCache.err
}

func (i *mqlIptables) tables() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.tablesOnce.Do(func() {
		conn := i.MqlRuntime.Connection.(shared.Connection)
		i.tablesCache, i.tablesErr = fetchAllTables(i.MqlRuntime, conn, "iptables", false)
	})
	return i.tablesCache, i.tablesErr
}

// --- ip6tables (IPv6) ---

func (i *mqlIp6tables) loadDump() (*SavedDump, bool, error) {
	i.saveCache.once.Do(func() {
		conn := i.MqlRuntime.Connection.(shared.Connection)
		i.saveCache.dump, i.saveCache.available, i.saveCache.err = loadSavedDump(conn, "ip6tables")
		if i.saveCache.available && i.saveCache.err == nil {
			if applyErr := applyDump(i.MqlRuntime, i.saveCache.dump, true, (*ip6tablesDumpTarget)(i)); applyErr != nil {
				i.saveCache.err = applyErr
				i.saveCache.available = false
			}
		}
	})
	return i.saveCache.dump, i.saveCache.available, i.saveCache.err
}

type ip6tablesDumpTarget mqlIp6tables

func (t *ip6tablesDumpTarget) setTables(tables []any) {
	i := (*mqlIp6tables)(t)
	i.tablesCache = tables
	i.tablesOnce.Do(func() {})
}

func (t *ip6tablesDumpTarget) setShortcut(name string, entries []any, policy string) {
	i := (*mqlIp6tables)(t)
	var c *chainCache
	switch name {
	case "INPUT":
		c = &i.inputCache
	case "OUTPUT":
		c = &i.outputCache
	case "FORWARD":
		c = &i.forwardCache
	default:
		return
	}
	c.entries = entries
	c.policy = policy
	c.once.Do(func() {})
}

func (t *ip6tablesDumpTarget) shortcutChainID(name string) string {
	switch name {
	case "INPUT":
		return "input6"
	case "OUTPUT":
		return "output6"
	case "FORWARD":
		return "forward6"
	}
	return name
}

func (i *mqlIp6tables) fetchInput() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.inputCache.entries, i.inputCache.policy, i.inputCache.err =
		fetchChain(i.MqlRuntime, conn, "ip6tables", "INPUT", "input6", true)
}

func (i *mqlIp6tables) fetchOutput() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.outputCache.entries, i.outputCache.policy, i.outputCache.err =
		fetchChain(i.MqlRuntime, conn, "ip6tables", "OUTPUT", "output6", true)
}

func (i *mqlIp6tables) fetchForward() {
	conn := i.MqlRuntime.Connection.(shared.Connection)
	i.forwardCache.entries, i.forwardCache.policy, i.forwardCache.err =
		fetchChain(i.MqlRuntime, conn, "ip6tables", "FORWARD", "forward6", true)
}

func (i *mqlIp6tables) input() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.inputCache.once.Do(i.fetchInput)
	return i.inputCache.entries, i.inputCache.err
}

func (i *mqlIp6tables) output() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.outputCache.once.Do(i.fetchOutput)
	return i.outputCache.entries, i.outputCache.err
}

func (i *mqlIp6tables) forward() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.forwardCache.once.Do(i.fetchForward)
	return i.forwardCache.entries, i.forwardCache.err
}

func (i *mqlIp6tables) inputPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.inputCache.once.Do(i.fetchInput)
	return i.inputCache.policy, i.inputCache.err
}

func (i *mqlIp6tables) outputPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.outputCache.once.Do(i.fetchOutput)
	return i.outputCache.policy, i.outputCache.err
}

func (i *mqlIp6tables) forwardPolicy() (string, error) {
	if _, _, err := i.loadDump(); err != nil {
		return "", err
	}
	i.forwardCache.once.Do(i.fetchForward)
	return i.forwardCache.policy, i.forwardCache.err
}

func (i *mqlIp6tables) tables() ([]any, error) {
	if _, _, err := i.loadDump(); err != nil {
		return nil, err
	}
	i.tablesOnce.Do(func() {
		conn := i.MqlRuntime.Connection.(shared.Connection)
		i.tablesCache, i.tablesErr = fetchAllTables(i.MqlRuntime, conn, "ip6tables", true)
	})
	return i.tablesCache, i.tablesErr
}

// Credit to github.com/coreos/go-iptables for some of the parsing logic
func getLines(data string) []string {
	rules := strings.Split(data, "\n")

	// strip trailing newline
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}

	return rules
}

// reChainPolicy matches the chain header line, e.g.:
//
//	"Chain INPUT (policy DROP 227 packets, 12904 bytes)"
var reChainPolicy = regexp.MustCompile(`^Chain\s+\S+\s+\(policy\s+([A-Z]+)`)

// ParseChainPolicy extracts the default policy from the first line of
// iptables/ip6tables -L output. Returns "" for user-defined chains or
// missing headers.
func ParseChainPolicy(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	if m := reChainPolicy.FindStringSubmatch(lines[0]); m != nil {
		return m[1]
	}
	return ""
}

// ParseChain parses the full output of an iptables/ip6tables -L command,
// returning both the chain's default policy and its rule entries.
func ParseChain(lines []string, ipv6 bool) (ChainResult, error) {
	result := ChainResult{
		Policy: ParseChainPolicy(lines),
	}
	var err error
	result.Entries, err = ParseStat(lines, ipv6)
	return result, err
}

// ParseStat parses the tabular rule entries from iptables/ip6tables -L output.
// Lines 0-1 (chain header + column names) are skipped.
func ParseStat(lines []string, ipv6 bool) ([]Stat, error) {
	entries := []Stat{}
	for i, line := range lines {
		// Skip over chain name and field header
		if i < 2 {
			continue
		}

		// Fields:
		// 0=linenumber 1=pkts 2=bytes 3=target 4=prot 5=opt 6=in 7=out 8=source 9=destination 10=options
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)

		// A rule needs at least the columns up to "source" (index 8); the IPv6
		// opt-field heuristic below also reads fields[7]. Skip short/blank lines
		// rather than indexing out of range and panicking on malformed output.
		if len(fields) < 9 {
			continue
		}

		// The ip6tables verbose output cannot be naively split due to the default "opt"
		// field containing 2 single spaces.
		if ipv6 {
			// Check if field 7 is "out" or "source" address
			dest := fields[7]
			ip, _, _ := net.ParseCIDR(dest)
			if ip == nil {
				ip = net.ParseIP(dest)
			}

			// If we detected a CIDR or IP, the "opt" field is empty.. insert it.
			if ip != nil {
				f := []string{}
				f = append(f, fields[:5]...)
				f = append(f, "  ") // Empty "opt" field for ip6tables
				f = append(f, fields[5:]...)
				fields = f
			}
		}
		ln, err := strconv.ParseInt(fields[0], 0, 64)
		if err != nil {
			return entries, fmt.Errorf("could not parse line number: %w", err)
		}
		pkts, err := strconv.ParseInt(fields[1], 0, 64)
		if err != nil {
			return entries, fmt.Errorf("could not parse packets: %w", err)
		}
		bts, err := strconv.ParseInt(fields[2], 0, 64)
		if err != nil {
			return entries, fmt.Errorf("could not parse bytes: %w", err)
		}
		var opts string
		// combine options if they exist
		if len(fields) > 10 {
			o := fields[10:]
			opts = strings.Join(o, " ")
		}
		entry := Stat{
			LineNumber: ln,
			Packets:    pkts,
			Bytes:      bts,
			Target:     fields[3],
			Protocol:   fields[4],
			Opt:        fields[5],
			Input:      fields[6],
			Output:     fields[7],
			Source:     fields[8],
			Options:    opts,
		}

		if len(fields) > 9 {
			entry.Destination = fields[9]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Reading a key over PowerShell costs one PowerShell process, and a Windows
// benchmark reads a hundred or more keys, nearly all of them under a few policy
// roots. Prefetch reads every key under such a root with one script the first
// time a key under it is read, and answers the reads under that root from what
// it fetched. Reads it cannot answer exactly fall back to the single-key script.

// PrefetchRoots are the parts of the registry a prefetch reads as one unit. A
// `*` stands for every subkey at that level, so
// `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\*\Parameters` reads the
// Parameters key of every service in one script.
//
// They are what Windows benchmarks read: Group Policy settings, the security
// options under Lsa, Winlogon and Session Manager, the print spooler and
// remote registry settings, service parameters, and the same policy keys in
// each user's hive. Keep them small: a root is read in full, whether a scan
// reads one key under it or fifty. (Internet Settings, for one, is read for two
// keys but holds thousands of values, so it is left to single reads.)
var PrefetchRoots = []string{
	`HKEY_LOCAL_MACHINE\SOFTWARE\Policies`,
	`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
	`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies`,
	`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\*\Parameters`,
	`HKEY_USERS\*\Software\Policies`,
	`HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Policies`,
}

// PrefetchMaxOutput caps the output of one prefetch, in characters. Past it the
// script stops and the root is marked incomplete: keys it read are still
// answered, every other read under the root falls back to a single read.
const PrefetchMaxOutput = 4 << 20

// prefetchScript reads the keys under one root. Its arguments are the part of
// the root before a `*` ($b), the part after it ($s, empty for a root without
// `*`) and the output cap ($m).
//
// Every key's values are read as getRegistryKeyItemScript reads them and
// written in the JSON form that script writes, so both decode through
// ParsePowershellRegistryKeyItems to the same values. The differences are in
// how, not what:
//   - The data comes from RegistryKey.GetValue, without a provider call per
//     value, and is shaped as Get-ItemProperty shapes it: a REG_DWORD is a
//     UInt32 and a REG_QWORD a UInt64 (GetValue returns them signed), and a
//     REG_MULTI_SZ is what Select-Object -ExpandProperty makes of it (no
//     element is null, one element is the string itself).
//   - The type comes from RegistryKey.GetValueKind, in the process, instead of
//     from reg.exe, which would cost a process per key. GetValueKind names the
//     stored type for the kinds it knows. A key with a value of any other kind
//     (REG_DWORD_BIG_ENDIAN, REG_LINK, the resource lists, and REG_NONE, which
//     GetValueKind reports the same as REG_LINK) is reported as unknown, so it
//     is read by the single-key script, which reads those from reg.exe.
//   - Both are method calls, which Constrained Language Mode refuses. The
//     script then reports that (L) and reads nothing: every key is read by the
//     single-key script, which works in that mode.
//
// Each output line is one record:
//
//	K"path"   a key that exists; the next line is V and its values
//	V[...]    the key's values, as getRegistryKeyItemScript writes them
//	U"path"   a key that could not be read: reads at or under it fall back
//	M         $b does not exist
//	T         the output cap was reached
//	L         the language mode refuses the script's method calls
//	D         done; without it the output is incomplete and nothing is used
const prefetchScript = `$b=%s;$s=%s;$m=%d
if($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage'){'L';exit}
$KT=@{1='REG_SZ';2='REG_EXPAND_SZ';3='REG_BINARY';4='REG_DWORD';7='REG_MULTI_SZ';11='REG_QWORD'}
$z=0
function J($x){$y=$x.Replace('\','\\');if($y -cmatch '^[\x20-\x21\x23-\x7e]*$'){return '"'+$y+'"'}
[regex]::Replace((ConvertTo-Json -Compress $x),'[^\x20-\x7e]',{'\u{0:x4}' -f [int][char]$args[0].Value})}
function E($k){
$n=$k.Name
try{
$o=@(foreach($v in $k.Property){
$f=$v;if('(default)'.Equals($v)){$f=''}
$t=$KT[[int]$k.GetValueKind($f)]
if($t -eq $null){throw 'kind'}
if($t -eq 'REG_EXPAND_SZ'){$d=$k.GetValue($f,$null,'DoNotExpandEnvironmentNames')}else{$d=$k.GetValue($f)}
if($t -eq 'REG_DWORD'){$d=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$d),0)}
if($t -eq 'REG_QWORD'){$d=[BitConverter]::ToUInt64([BitConverter]::GetBytes([long]$d),0)}
if($d -is [string[]]){if($d.Count -eq 0){$d=$null}elseif($d.Count -eq 1){$d=$d[0]}}
[pscustomobject]@{key=$v;value=[pscustomobject]@{data=$d;kind=$null;type=$t;hex=$null}}
})
$r='K'+(J $n)+"` + "`" + `n"+'V'+(ConvertTo-Json -Depth 3 -Compress $o)
}catch{$r='U'+(J $n)}
$script:z+=$r.Length
$r
}
function W($r){
try{$k=Get-Item -LiteralPath $r -EA Stop}catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){'U'+(J $r)};return}
E $k
$ev=$null
foreach($c in @(Get-ChildItem -LiteralPath $k.PSPath -Recurse -EA SilentlyContinue -EV ev)){
if($script:z -gt $m){'T';return}
E $c
}
foreach($e in $ev){'U'+(J ([string]$e.TargetObject))}
}
$RB='Registry::'+$b
if(-not $s){W $RB}else{
$ev=$null
try{$ch=@(Get-ChildItem -LiteralPath $RB -EA Stop -EV ev)}catch{if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'M'}else{'U'+(J $b)};$ch=@()}
foreach($c in $ch){
if($script:z -gt $m){'T';break}
if(@($c.GetSubKeyNames()) -contains $s.Split('\')[0]){W ($RB+'\'+$c.PSChildName+'\'+$s)}
}
}
'D'
`

// PrefetchScript returns the script that reads the keys under one of the
// PrefetchRoots.
func PrefetchScript(root string, maxOutput int) string {
	base, sub, _ := strings.Cut(root, `\*`)
	sub = strings.TrimPrefix(sub, `\`)
	return fmt.Sprintf(prefetchScript, powershell.SingleQuote(base), powershell.SingleQuote(sub), maxOutput)
}

// FoldRegistryPath returns the form of a registry path the prefetch compares:
// lower case, with the HKLM, HKCU and HKU abbreviations spelled out. It returns
// false for a path whose meaning to PowerShell it cannot be sure of: a path
// with empty components (a leading, trailing or doubled separator), a forward
// slash (PowerShell reads it as a separator, the registry as part of a name) or
// a wildcard character (the single-key script reads the path with -Path, which
// expands wildcards).
func FoldRegistryPath(path string) ([]string, bool) {
	if path == "" || strings.ContainsAny(path, "/*?[]`") {
		return nil, false
	}
	parts := strings.Split(strings.ToLower(path), `\`)
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
	}
	switch parts[0] {
	case "hklm":
		parts[0] = "hkey_local_machine"
	case "hkcu":
		parts[0] = "hkey_current_user"
	case "hku":
		parts[0] = "hkey_users"
	}
	return parts, true
}

// PrefetchLookup is the answer a prefetch gives for one key.
type PrefetchLookup int

const (
	// PrefetchUnknown means the prefetch cannot answer: read the key alone.
	PrefetchUnknown PrefetchLookup = iota
	// PrefetchFound means the key exists; its values are returned.
	PrefetchFound
	// PrefetchMissing means the key does not exist.
	PrefetchMissing
)

// RunScript runs a PowerShell script on the target and returns its standard
// output. A non-nil error or a non-zero exit code fails the prefetch.
type RunScript func(script string) (stdout io.Reader, exitCode int, err error)

// Prefetch holds the keys read under the PrefetchRoots over one connection. It
// reads each root at most once, the first time a key under it is looked up.
type Prefetch struct {
	run   RunScript
	units []*prefetchUnit

	mu       sync.Mutex
	disabled bool
}

// NewPrefetch returns a prefetch that reads the given roots (PrefetchRoots when
// nil) by running scripts with run.
func NewPrefetch(run RunScript, roots []string) *Prefetch {
	if roots == nil {
		roots = PrefetchRoots
	}
	p := &Prefetch{run: run}
	for _, r := range roots {
		// FoldRegistryPath refuses the `*`, so fold the root with a stand-in
		// and put the `*` back.
		folded, ok := FoldRegistryPath(strings.ReplaceAll(r, `*`, `x`))
		if !ok {
			panic("invalid registry prefetch root " + r)
		}
		for i, c := range strings.Split(r, `\`) {
			if c == "*" {
				folded[i] = "*"
			}
		}
		p.units = append(p.units, &prefetchUnit{spelling: r, root: folded})
	}
	return p
}

// prefetchUnit is one root, and what its script returned.
type prefetchUnit struct {
	spelling string   // the root as PrefetchRoots spells it
	root     []string // folded

	once       sync.Once
	failed     bool
	incomplete bool              // truncated, or an error outside any key we can name
	keys       map[string]string // folded path -> values JSON
	unknown    [][]string        // keys that could not be read
}

// Lookup answers a read of the key at path from the prefetch, reading the
// key's root first when no read under it happened yet. Found returns the key's
// values as the single-key script reads them.
func (p *Prefetch) Lookup(path string) (PrefetchLookup, []RegistryKeyItem) {
	parts, ok := FoldRegistryPath(path)
	if !ok {
		return PrefetchUnknown, nil
	}
	u := p.unitFor(parts)
	if u == nil {
		return PrefetchUnknown, nil
	}
	u.once.Do(func() { p.fetch(u) })
	return u.lookup(parts)
}

func (p *Prefetch) unitFor(parts []string) *prefetchUnit {
	p.mu.Lock()
	disabled := p.disabled
	p.mu.Unlock()
	if disabled {
		return nil
	}
	for _, u := range p.units {
		if coveredBy(parts, u.root) {
			return u
		}
	}
	return nil
}

// coveredBy reports whether the key parts is the root or under it.
func coveredBy(parts, root []string) bool {
	if len(parts) < len(root) {
		return false
	}
	for i, c := range root {
		if c != "*" && c != parts[i] {
			return false
		}
	}
	return true
}

func (p *Prefetch) fetch(u *prefetchUnit) {
	stdout, exit, err := p.run(PrefetchScript(u.spelling, PrefetchMaxOutput))
	if err != nil || exit != 0 {
		u.failed = true
		return
	}
	languageMode, err := u.parse(stdout)
	if languageMode {
		// Constrained Language Mode: no root can be prefetched on this
		// connection, so stop trying.
		p.mu.Lock()
		p.disabled = true
		p.mu.Unlock()
	}
	if err != nil {
		u.failed = true
	}
}

// parse reads the script's records. It reports whether the script refused to
// run under the language mode.
func (u *prefetchUnit) parse(r io.Reader) (bool, error) {
	u.keys = map[string]string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), PrefetchMaxOutput+1024*1024)
	pendingKey := ""
	done := false
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		rec, arg := line[0], line[1:]
		if pendingKey != "" && rec != 'V' {
			return false, fmt.Errorf("registry prefetch: key %s has no values record", pendingKey)
		}
		switch rec {
		case 'L':
			return true, fmt.Errorf("registry prefetch: refused by the language mode")
		case 'D':
			done = true
		case 'T':
			u.incomplete = true
		case 'M':
			// the part before `*` does not exist, so nothing under it does
		case 'K':
			name, err := decodeRecordString(arg)
			if err != nil {
				return false, err
			}
			parts, ok := FoldRegistryPath(name)
			if !ok {
				// A name with a character FoldRegistryPath refuses. Reads of
				// it, or of a key under it, carry the same character and are
				// never answered from here, so it is skipped.
				pendingKey = "-"
				continue
			}
			if !coveredBy(parts, u.root) {
				return false, fmt.Errorf("registry prefetch: key %s is not under %s", name, strings.Join(u.root, `\`))
			}
			pendingKey = strings.Join(parts, `\`)
		case 'V':
			if pendingKey == "" {
				return false, fmt.Errorf("registry prefetch: values record without a key")
			}
			if pendingKey != "-" {
				u.keys[pendingKey] = arg
			}
			pendingKey = ""
		case 'U':
			name, err := decodeRecordString(arg)
			if err != nil {
				return false, err
			}
			if _, after, ok := strings.Cut(name, "::"); ok {
				name = after
			}
			parts, ok := FoldRegistryPath(name)
			if !ok || len(parts) < 2 {
				u.incomplete = true
				continue
			}
			u.unknown = append(u.unknown, parts)
		default:
			// PowerShell writes nothing else to stdout; anything that is not
			// a record means the output cannot be trusted.
			return false, fmt.Errorf("registry prefetch: unexpected output %q", truncate(line, 80))
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	if pendingKey != "" {
		return false, fmt.Errorf("registry prefetch: key %s has no values record", pendingKey)
	}
	if !done {
		return false, fmt.Errorf("registry prefetch: output ended early")
	}
	return false, nil
}

func decodeRecordString(s string) (string, error) {
	var res string
	if err := json.Unmarshal([]byte(s), &res); err != nil {
		return "", fmt.Errorf("registry prefetch: bad record %q: %w", truncate(s, 80), err)
	}
	return res, nil
}

// truncate shortens s to at most n runes, so it never splits a character.
func truncate(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos] + "…"
		}
		i++
	}
	return s
}

func (u *prefetchUnit) lookup(parts []string) (PrefetchLookup, []RegistryKeyItem) {
	if u.failed {
		return PrefetchUnknown, nil
	}
	if values, ok := u.keys[strings.Join(parts, `\`)]; ok {
		items, err := ParsePowershellRegistryKeyItems(strings.NewReader(values))
		if err != nil {
			// the single-key script reports this key's error as it always has
			return PrefetchUnknown, nil
		}
		return PrefetchFound, items
	}

	// Not found. That is an answer only when the root was read completely down
	// to where this key would be.
	if u.incomplete {
		return PrefetchUnknown, nil
	}
	for _, unknown := range u.unknown {
		if isPrefixOf(unknown, parts) {
			return PrefetchUnknown, nil
		}
	}
	return PrefetchMissing, nil
}

// isPrefixOf reports whether the key prefix is parts or one of its parents.
func isPrefixOf(prefix, parts []string) bool {
	if len(prefix) > len(parts) {
		return false
	}
	for i := range prefix {
		if prefix[i] != parts[i] {
			return false
		}
	}
	return true
}

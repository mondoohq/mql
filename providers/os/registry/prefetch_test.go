// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestFoldRegistryPath(t *testing.T) {
	same := []string{
		`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft`,
		`HKLM\Software\Policies\Microsoft`,
		`hkey_local_machine\software\policies\microsoft`,
	}
	want, ok := FoldRegistryPath(same[0])
	require.True(t, ok)
	for _, p := range same {
		got, ok := FoldRegistryPath(p)
		require.True(t, ok, p)
		assert.Equal(t, want, got, p)
	}

	users, ok := FoldRegistryPath(`HKU\S-1-5-18\Software`)
	require.True(t, ok)
	assert.Equal(t, []string{"hkey_users", "s-1-5-18", "software"}, users)

	// forms PowerShell may read differently: never answered from a prefetch
	for _, p := range []string{
		``,
		`HKLM\SOFTWARE\`,
		`\HKLM\SOFTWARE`,
		`HKLM\\SOFTWARE`,
		`HKLM/SOFTWARE`,
		`HKLM\SOFTWARE\*`,
		`HKLM\SOFTWARE\Micro?oft`,
		`HKLM\SOFTWARE\[ab]`,
	} {
		_, ok := FoldRegistryPath(p)
		assert.False(t, ok, p)
	}
}

func TestPrefetchScriptFitsCommandLine(t *testing.T) {
	for _, root := range PrefetchRoots {
		script := PrefetchScript(root, PrefetchMaxOutput)
		assert.True(t, powershell.FitsCommandLine(script), "%s: %d characters", root, len(script))
	}
}

func TestPrefetchScriptArguments(t *testing.T) {
	script := PrefetchScript(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\*\Parameters`, 100)
	assert.True(t, strings.HasPrefix(script, `$b='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services';$s='Parameters';$m=100`), script)

	script = PrefetchScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies`, 100)
	assert.True(t, strings.HasPrefix(script, `$b='HKEY_LOCAL_MACHINE\SOFTWARE\Policies';$s='';$m=100`), script)
}

// fakeRun answers every prefetch script with the same output and counts runs.
type fakeRun struct {
	out   string
	exit  int
	err   error
	runs  atomic.Int32
	calls []string
	mu    sync.Mutex
}

func (f *fakeRun) run(script string) (io.Reader, int, error) {
	f.runs.Add(1)
	f.mu.Lock()
	f.calls = append(f.calls, script)
	f.mu.Unlock()
	return strings.NewReader(f.out), f.exit, f.err
}

const policiesOutput = `K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies"
V
K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft"
V
K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
V[{"key":"EnableSmartScreen","value":{"data":1,"kind":null,"type":"REG_DWORD","hex":null}},{"key":"ShellSmartScreenLevel","value":{"data":"Block","kind":null,"type":"REG_SZ","hex":null}}]
K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging"
V[{"key":"LogFilePath","value":{"data":"%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log","kind":null,"type":"REG_EXPAND_SZ","hex":null}},{"key":"Big","value":{"data":5000000000,"kind":null,"type":"REG_QWORD","hex":null}}]
U"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Locked"
U"Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Other\\Locked"
D
`

func TestPrefetchLookup(t *testing.T) {
	f := &fakeRun{out: policiesOutput}
	p := NewPrefetch(f.run, nil)

	// found, in any spelling
	res, items := p.Lookup(`HKLM\Software\Policies\Microsoft\Windows\System`)
	require.Equal(t, PrefetchFound, res)
	require.Len(t, items, 2)
	assert.Equal(t, "EnableSmartScreen", items[0].Key)
	assert.Equal(t, int64(1), items[0].GetRawValue())
	assert.Equal(t, "Block", items[1].String())

	res, items = p.Lookup(`HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\MICROSOFT\WINDOWSFIREWALL\DOMAINPROFILE\LOGGING`)
	require.Equal(t, PrefetchFound, res)
	require.Len(t, items, 2)
	assert.Equal(t, `%SystemRoot%\System32\logfiles\firewall\domainfw.log`, items[0].String())
	assert.Equal(t, "expandstring", items[0].Kind())
	assert.Equal(t, int64(5000000000), items[1].GetRawValue())

	// an existing key without values
	res, items = p.Lookup(`HKLM\SOFTWARE\Policies\Microsoft`)
	require.Equal(t, PrefetchFound, res)
	assert.Empty(t, items)
	assert.NotNil(t, items)

	// a key the root was read without: it does not exist
	res, _ = p.Lookup(`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`)
	assert.Equal(t, PrefetchMissing, res)

	// at or under a key that could not be read: unknown
	for _, path := range []string{
		`HKLM\SOFTWARE\Policies\Locked`,
		`HKLM\SOFTWARE\Policies\Locked\Sub`,
		`HKLM\SOFTWARE\Policies\Other\Locked\Sub`,
	} {
		res, _ = p.Lookup(path)
		assert.Equal(t, PrefetchUnknown, res, path)
	}
	res, _ = p.Lookup(`HKLM\SOFTWARE\Policies\Other\Unlocked`)
	assert.Equal(t, PrefetchMissing, res)

	// outside every root, or a path PowerShell may read differently
	for _, path := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		`HKLM\SOFTWARE`,
		`HKLM\SOFTWARE\Policies\*`,
		`HKLM\SOFTWARE\Policies\`,
	} {
		res, _ = p.Lookup(path)
		assert.Equal(t, PrefetchUnknown, res, path)
	}

	assert.Equal(t, int32(1), f.runs.Load(), "the root is read once")
}

func TestPrefetchLookupEachRootOnce(t *testing.T) {
	f := &fakeRun{out: "D\n"}
	p := NewPrefetch(f.run, nil)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _ := p.Lookup(`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`)
			assert.Equal(t, PrefetchMissing, res)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), f.runs.Load())

	p.Lookup(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`)
	assert.Equal(t, int32(2), f.runs.Load())
}

func TestPrefetchLookupWildcardRoot(t *testing.T) {
	f := &fakeRun{out: `K"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
V[{"key":"SMB1","value":{"data":0,"kind":null,"type":"REG_DWORD","hex":null}}]
U"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Locked\\Parameters"
D
`}
	p := NewPrefetch(f.run, nil)

	res, items := p.Lookup(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters`)
	require.Equal(t, PrefetchFound, res)
	require.Len(t, items, 1)
	assert.Equal(t, int64(0), items[0].GetRawValue())

	res, _ = p.Lookup(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`)
	assert.Equal(t, PrefetchMissing, res)
	res, _ = p.Lookup(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Locked\Parameters`)
	assert.Equal(t, PrefetchUnknown, res)
	// the service key itself is not under the root
	res, _ = p.Lookup(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer`)
	assert.Equal(t, PrefetchUnknown, res)

	require.Len(t, f.calls, 1)
	assert.Contains(t, f.calls[0], `$b='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services';$s='Parameters'`)
}

func TestPrefetchLookupIncomplete(t *testing.T) {
	cases := map[string]*fakeRun{
		"truncated": {out: `K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\A"
V
T
D
`},
		"error outside a named key": {out: `K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\A"
V
U""
D
`},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			p := NewPrefetch(f.run, nil)
			res, _ := p.Lookup(`HKLM\SOFTWARE\Policies\A`)
			assert.Equal(t, PrefetchFound, res, "a key it read is still answered")
			res, _ = p.Lookup(`HKLM\SOFTWARE\Policies\B`)
			assert.Equal(t, PrefetchUnknown, res, "a key it did not read is read alone")
		})
	}
}

func TestPrefetchLookupFailures(t *testing.T) {
	cases := map[string]*fakeRun{
		"error":                  {err: errors.New("connection lost")},
		"exit code":              {exit: 1, out: "D\n"},
		"no done record":         {out: "K\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\A\"\nV\n"},
		"key without values":     {out: "K\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\A\"\nD\n"},
		"unexpected output":      {out: "WARNING: something\nD\n"},
		"key outside the root":   {out: "K\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Other\"\nV\nD\n"},
		"record is not a string": {out: "K42\nV\nD\n"},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			p := NewPrefetch(f.run, nil)
			res, _ := p.Lookup(`HKLM\SOFTWARE\Policies\A`)
			assert.Equal(t, PrefetchUnknown, res)
			res, _ = p.Lookup(`HKLM\SOFTWARE\Policies\B`)
			assert.Equal(t, PrefetchUnknown, res)
			assert.Equal(t, int32(1), f.runs.Load(), "a failed root is not read again")
		})
	}
}

func TestPrefetchLanguageModeDisables(t *testing.T) {
	f := &fakeRun{out: "L\n"}
	p := NewPrefetch(f.run, nil)
	res, _ := p.Lookup(`HKLM\SOFTWARE\Policies\A`)
	assert.Equal(t, PrefetchUnknown, res)
	res, _ = p.Lookup(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`)
	assert.Equal(t, PrefetchUnknown, res)
	assert.Equal(t, int32(1), f.runs.Load(), "no other root is tried")
}

// A key whose value the decoder cannot read is left to the single-key read,
// which reports that value's error as it always has.
func TestPrefetchLookupUndecodableValues(t *testing.T) {
	f := &fakeRun{out: `K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\A"
V[{"key":"x","value":{"data":"notanumber","kind":null,"type":"REG_DWORD","hex":null}}]
D
`}
	p := NewPrefetch(f.run, nil)
	res, _ := p.Lookup(`HKLM\SOFTWARE\Policies\A`)
	assert.Equal(t, PrefetchUnknown, res)
}

// The values record is the single-key script's output, so it decodes to the
// same items: the same JSON through the same parser.
func TestPrefetchValuesDecodeLikeSingleRead(t *testing.T) {
	values := `[{"key":"Sz","value":{"data":"hello","kind":null,"type":"REG_SZ","hex":null}},` +
		`{"key":"ExpandSz","value":{"data":"%SystemRoot%\\x","kind":null,"type":"REG_EXPAND_SZ","hex":null}},` +
		`{"key":"Dword","value":{"data":42,"kind":null,"type":"REG_DWORD","hex":null}},` +
		`{"key":"Qword","value":{"data":18446744073709551615,"kind":null,"type":"REG_QWORD","hex":null}},` +
		`{"key":"MultiSz","value":{"data":["a","b"],"kind":null,"type":"REG_MULTI_SZ","hex":null}},` +
		`{"key":"MultiSzOne","value":{"data":"a","kind":null,"type":"REG_MULTI_SZ","hex":null}},` +
		`{"key":"Binary","value":{"data":[222,173],"kind":null,"type":"REG_BINARY","hex":null}},` +
		`{"key":"None","value":{"data":[1],"kind":null,"type":"REG_NONE","hex":null}},` +
		`{"key":"(default)","value":{"data":"d","kind":null,"type":"REG_SZ","hex":null}}]`
	single, err := ParsePowershellRegistryKeyItems(strings.NewReader(values))
	require.NoError(t, err)

	f := &fakeRun{out: "K\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Policies\\\\A\"\nV" + values + "\nD\n"}
	res, batched := NewPrefetch(f.run, nil).Lookup(`HKLM\SOFTWARE\Policies\A`)
	require.Equal(t, PrefetchFound, res)
	require.Equal(t, single, batched)
}

func TestTruncateKeepsWholeRunes(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 3))
	assert.Equal(t, "ab…", truncate("abc", 2))
	assert.Equal(t, "Grüß…", truncate("Grüße", 4))
	assert.True(t, utf8.ValidString(truncate(strings.Repeat("ü", 100), 80)))
}

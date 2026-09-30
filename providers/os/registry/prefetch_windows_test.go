// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package registry

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// runPowerShellFile runs a script the way the remote path does, but from a
// file, and returns its output and exit code.
func runPowerShellFile(t *testing.T, script string) (stdout, stderr string, exit int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.ps1")
	require.NoError(t, os.WriteFile(path, []byte("$ProgressPreference='SilentlyContinue'\n"+script), 0o600))
	var out, errOut bytes.Buffer
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), errOut.String(), exitErr.ExitCode()
	}
	require.NoError(t, err)
	return out.String(), errOut.String(), 0
}

// writePrefetchTestTree writes a scratch tree under HKEY_CURRENT_USER with
// values of every kind the prefetch reads itself, a key with the kinds it
// leaves to the single-key script, a key without values, and nested keys.
func writePrefetchTestTree(t *testing.T) string {
	t.Helper()
	sub := fmt.Sprintf(`Software\mql-prefetch-test-%d`, os.Getpid())
	create := func(path string) registry.Key {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
		require.NoError(t, err)
		t.Cleanup(func() { k.Close() })
		return k
	}
	t.Cleanup(func() {
		for _, p := range []string{`\Svc1\Sub\Deep`, `\Svc1\Sub`, `\Svc1`, `\Svc2`, `\Values\Empty`, `\Values`, `\Exotic`, `\B\C`, `\B\None`, `\B`, ``} {
			_ = registry.DeleteKey(registry.CURRENT_USER, sub+p)
		}
	})

	root := create(sub)
	require.NoError(t, root.SetStringValue("", "default value"))
	require.NoError(t, root.SetDWordValue("RootDword", 1))

	v := create(sub + `\Values`)
	require.NoError(t, v.SetStringValue("Sz", "hello"))
	require.NoError(t, v.SetStringValue("SzUnicode", "grüße ✓"))
	require.NoError(t, v.SetExpandStringValue("ExpandSz", `%SystemRoot%\system32\logfiles\firewall\domainfw.log`))
	require.NoError(t, v.SetDWordValue("Dword", 42))
	require.NoError(t, v.SetDWordValue("DwordMax", 0xffffffff))
	require.NoError(t, v.SetQWordValue("Qword", 5000000000))
	require.NoError(t, v.SetQWordValue("QwordMax", 0xffffffffffffffff))
	require.NoError(t, v.SetStringsValue("MultiSz", []string{"alpha", "beta"}))
	require.NoError(t, v.SetStringsValue("MultiSzOne", []string{"alpha"}))
	require.NoError(t, v.SetStringsValue("MultiSzEmpty", []string{}))
	require.NoError(t, v.SetBinaryValue("Binary", []byte{0xde, 0xad, 0xbe, 0xef}))
	require.NoError(t, v.SetBinaryValue("BinaryEmpty", []byte{}))
	require.NoError(t, v.SetStringValue("Name With Spaces", "x"))
	create(sub + `\Values\Empty`)

	e := create(sub + `\Exotic`)
	require.NoError(t, e.SetDWordValue("Dword", 1))
	setRawValue(t, e, "Link", registry.LINK, []byte{0x41, 0, 0x42, 0})
	n := create(sub + `\B\None`)
	setRawValue(t, n, "None", registry.NONE, []byte{1, 2})

	c := create(sub + `\B\C`)
	require.NoError(t, c.SetStringValue("Nested", "yes"))

	s1 := create(sub + `\Svc1\Sub\Deep`)
	require.NoError(t, s1.SetDWordValue("Level", 3))
	create(sub + `\Svc2`)

	return `HKEY_CURRENT_USER\` + sub
}

// TestPrefetchMatchesSingleReads reads a scratch tree with the prefetch script
// and every key of it, plus keys that don't exist, with the single-key script
// the remote path runs. Every key the prefetch answers must answer the same:
// the same existence and the same values, decoded the same way.
func TestPrefetchMatchesSingleReads(t *testing.T) {
	base := writePrefetchTestTree(t)

	var scripts int
	run := func(script string) (io.Reader, int, error) {
		scripts++
		out, _, exit := runPowerShellFile(t, script)
		return strings.NewReader(out), exit, nil
	}
	// the wildcard root first: the other one covers it
	p := NewPrefetch(run, []string{base + `\*\Sub`, base})

	answered := map[PrefetchLookup]int{}
	check := func(path string) PrefetchLookup {
		res, batched := p.Lookup(path)
		answered[res]++
		if res == PrefetchUnknown {
			return res
		}
		stdout, stderr, exit := runPowerShellFile(t, GetRegistryKeyItemScript(path))
		if res == PrefetchMissing {
			require.NotEqual(t, 0, exit, "%s: the prefetch says missing, the single read found it", path)
			require.True(t, strings.Contains(stderr, "not exist") || strings.Contains(stderr, "ObjectNotFound"), "%s: %s", path, stderr)
			return res
		}
		require.Equal(t, 0, exit, "%s: the prefetch found it, the single read did not: %s", path, stderr)
		single, err := ParsePowershellRegistryKeyItems(strings.NewReader(stdout))
		require.NoError(t, err, path)
		require.Len(t, batched, len(single), path)
		for i := range single {
			s, b := single[i], batched[i]
			assert.Equal(t, s.Key, b.Key, path)
			assert.NoError(t, s.Value.Err, "%s %s", path, s.Key)
			assert.NoError(t, b.Value.Err, "%s %s", path, b.Key)
			assert.Equal(t, s.Value.Kind, b.Value.Kind, "%s %s kind", path, s.Key)
			assert.Equal(t, s.Kind(), b.Kind(), "%s %s type", path, s.Key)
			assert.Equal(t, s.String(), b.String(), "%s %s value", path, s.Key)
			assert.Equal(t, s.GetRawValue(), b.GetRawValue(), "%s %s data", path, s.Key)
		}
		return res
	}

	for _, path := range []string{
		base,
		base + `\Values`,
		strings.ToUpper(base + `\Values`),
		base + `\Values\Empty`,
		base + `\B`,
		base + `\B\C`,
		base + `\Svc1`,
		base + `\Svc1\Sub`,
		base + `\Svc1\Sub\Deep`,
	} {
		assert.Equal(t, PrefetchFound, check(path), path)
	}
	for _, path := range []string{
		base + `\Missing`,
		base + `\Values\Missing`,
		base + `\Svc2\Sub`,
		base + `\Nope\Sub`,
		base + `\Svc1\Sub\Missing`,
	} {
		assert.Equal(t, PrefetchMissing, check(path), path)
	}
	// REG_LINK and REG_NONE are left to the single-key script, which reads
	// them from reg.exe
	assert.Equal(t, PrefetchUnknown, check(base+`\Exotic`))
	assert.Equal(t, PrefetchUnknown, check(base+`\B\None`))
	assert.Equal(t, 2, scripts, "one script per root")

	// a wildcard root with a suffix of more than one key
	deep := NewPrefetch(run, []string{base + `\*\Sub\Deep`})
	res, items := deep.Lookup(base + `\Svc1\Sub\Deep`)
	require.Equal(t, PrefetchFound, res)
	require.Len(t, items, 1)
	assert.Equal(t, int64(3), items[0].GetRawValue())
	res, _ = deep.Lookup(base + `\Svc2\Sub\Deep`)
	assert.Equal(t, PrefetchMissing, res)

	// a root that does not exist
	missing := NewPrefetch(run, []string{base + `\NotThere`, base + `\NotThere\*\Sub`})
	res, _ = missing.Lookup(base + `\NotThere\X`)
	assert.Equal(t, PrefetchMissing, res)
	res, _ = missing.Lookup(base + `\NotThere\X\Sub`)
	assert.Equal(t, PrefetchMissing, res)
}

// TestPrefetchTruncated caps the output below the tree's size: the keys the
// script read are answered, the others are left to single reads.
func TestPrefetchTruncated(t *testing.T) {
	base := writePrefetchTestTree(t)
	var out string
	run := func(script string) (io.Reader, int, error) {
		script = strings.Replace(script, fmt.Sprintf(";$m=%d", PrefetchMaxOutput), ";$m=10", 1)
		stdout, _, exit := runPowerShellFile(t, script)
		out = stdout
		return strings.NewReader(stdout), exit, nil
	}
	p := NewPrefetch(run, []string{base})
	res, _ := p.Lookup(base)
	assert.Equal(t, PrefetchFound, res)
	assert.Contains(t, out, "\nT")
	res, _ = p.Lookup(base + `\Missing`)
	assert.Equal(t, PrefetchUnknown, res)
}

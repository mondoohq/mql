// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"os"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// denyOpenFs refuses to open the named paths with EACCES, the way /proc/sys
// refuses a reader that is not root on the knobs the kernel restricts.
type denyOpenFs struct {
	afero.Fs
	deny map[string]bool
}

func (f *denyOpenFs) Open(name string) (afero.File, error) {
	if f.deny[name] {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return f.Fs.Open(name)
}

func procSysFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()
	for path, content := range map[string]string{
		// sorts before the denied entry
		"/proc/sys/fs/protected_hardlinks": "1\n",
		"/proc/sys/fs/suid_dumpable":       "0\n",
		// the denied entry itself, mode 0600 root-only on a real host
		"/proc/sys/kernel/usermodehelper/bset": "4294967295\n",
		// sorts after the denied entry
		"/proc/sys/kernel/randomize_va_space": "2\n",
		"/proc/sys/net/ipv4/ip_forward":       "0\n",
		"/proc/sys/vm/mmap_min_addr":          "65536\n",
	} {
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	return fs
}

func TestWalkProcSys_ReadsEveryParameter(t *testing.T) {
	params, err := walkProcSys(procSysFs(t))
	require.NoError(t, err)

	assert.Equal(t, "2", params["kernel.randomize_va_space"])
	assert.Equal(t, "0", params["net.ipv4.ip_forward"])
	assert.Equal(t, "1", params["fs.protected_hardlinks"])
	assert.Equal(t, "4294967295", params["kernel.usermodehelper.bset"])
	assert.Len(t, params, 6)
}

// kernel.usermodehelper/bset is mode 0600 and owned by root, so any scan that
// is not root gets EACCES on it. Before the fix that error ended the walk and
// kernel.parameters reported no data at all, rather than the hundreds of knobs
// sitting there world-readable -- randomize_va_space and ip_forward among them.
func TestWalkProcSys_KeepsGoingPastAnUnreadableParameter(t *testing.T) {
	fs := &denyOpenFs{
		Fs:   procSysFs(t),
		deny: map[string]bool{"/proc/sys/kernel/usermodehelper/bset": true},
	}

	params, err := walkProcSys(fs)
	require.NoError(t, err)

	// the readable knobs still arrive, including the ones that sort after the
	// denied entry
	assert.Equal(t, "2", params["kernel.randomize_va_space"])
	assert.Equal(t, "0", params["net.ipv4.ip_forward"])
	assert.Equal(t, "65536", params["vm.mmap_min_addr"])
	assert.Equal(t, "1", params["fs.protected_hardlinks"])
	assert.Equal(t, "0", params["fs.suid_dumpable"])

	// the one we could not read is absent rather than reported as empty, so a
	// check on it cannot pass on a value we never saw
	assert.NotContains(t, params, "kernel.usermodehelper.bset")
	assert.Len(t, params, 5)
}

// The three write-only knobs a stock kernel exports (vm/drop_caches,
// vm/compact_memory, net/ipv4/route/flush) are not parameter values, and root
// can open and read them regardless, so the mode is what keeps them out.
func TestWalkProcSys_SkipsWriteOnlyKnobs(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/proc/sys/vm/mmap_min_addr", []byte("65536\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/proc/sys/vm/drop_caches", []byte("0\n"), 0o200))
	require.NoError(t, afero.WriteFile(fs, "/proc/sys/vm/compact_memory", []byte("0\n"), 0o200))
	require.NoError(t, afero.WriteFile(fs, "/proc/sys/net/ipv4/route/flush", []byte("\n"), 0o200))

	params, err := walkProcSys(fs)
	require.NoError(t, err)

	assert.Equal(t, "65536", params["vm.mmap_min_addr"])
	assert.NotContains(t, params, "vm.drop_caches")
	assert.NotContains(t, params, "vm.compact_memory")
	assert.NotContains(t, params, "net.ipv4.route.flush")
	assert.Len(t, params, 1)
}

// A host without /proc/sys at all reports an empty map, not an error.
func TestWalkProcSys_NoProcSys(t *testing.T) {
	params, err := walkProcSys(afero.NewMemMapFs())
	require.NoError(t, err)
	assert.Empty(t, params)
}

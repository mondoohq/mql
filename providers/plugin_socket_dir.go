// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"fmt"
	"os"
	goruntime "runtime"
	"sync"

	"github.com/rs/zerolog/log"
)

// errNoSocketDir says why a provider cannot start on a host with no writable
// temporary directory. go-plugin only reports such a plugin as "not compiled
// for this architecture ... or failed to negotiate the handshake".
type errNoSocketDir struct {
	tmp string
}

func (e errNoSocketDir) Error() string {
	return fmt.Sprintf("no writable temporary directory for the provider's socket: %s is not writable; set TMPDIR to a writable directory", e.tmp)
}

// pickPluginSocketDir returns where providers should create their sockets:
// "" when the default temporary directory is writable, otherwise the first
// writable fallback. It returns errNoSocketDir when none is.
func pickPluginSocketDir(tmp string, fallbacks []string, writable func(string) bool) (string, error) {
	if writable(tmp) {
		return "", nil
	}
	for _, dir := range fallbacks {
		if dir != "" && dir != tmp && writable(dir) {
			return dir, nil
		}
	}
	return "", errNoSocketDir{tmp: tmp}
}

// socketDirFallbacks are tried in order when TMPDIR is not writable, as on
// OpenWrt run as non-root (/tmp is 0755 root) or a scratch image with no /tmp.
func socketDirFallbacks() []string {
	home, _ := os.UserHomeDir()
	cache, _ := os.UserCacheDir()
	return []string{os.Getenv("XDG_RUNTIME_DIR"), "/dev/shm", "/run/user/" + fmt.Sprint(os.Getuid()), cache, home}
}

func dirWritable(dir string) bool {
	if dir == "" {
		return false
	}
	d, err := os.MkdirTemp(dir, ".mql-probe-")
	if err != nil {
		return false
	}
	_ = os.Remove(d)
	return true
}

var (
	tempDirMu    sync.Mutex
	tempDirReady bool
)

// ensureWritableTempDir makes TMPDIR a writable directory when the default
// one is not. Both sides of a provider connection create Unix sockets there:
// the provider for its server and mql for the callback broker, so the
// fallback goes into this process's TMPDIR, which every provider inherits.
// Windows uses TCP.
//
// A directory that was found is kept for the life of the process; a search
// that found none is not, so the next provider start looks again.
func ensureWritableTempDir() error {
	if goruntime.GOOS == "windows" {
		return nil
	}
	tempDirMu.Lock()
	defer tempDirMu.Unlock()
	if tempDirReady {
		return nil
	}
	dir, err := pickPluginSocketDir(os.TempDir(), socketDirFallbacks(), dirWritable)
	if err != nil {
		return err
	}
	if dir != "" {
		log.Debug().Str("dir", dir).Str("tmpdir", os.TempDir()).Msg("TMPDIR is not writable, providers use another directory for their sockets")
		if err := os.Setenv("TMPDIR", dir); err != nil {
			return err
		}
	}
	tempDirReady = true
	return nil
}

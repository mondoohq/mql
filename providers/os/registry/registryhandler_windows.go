// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package registry

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// unloadTimeout bounds a single `reg unload`. Unloading runs while the
// connection closes, and a call that never returns keeps the provider from
// answering Shutdown.
const unloadTimeout = 10 * time.Second

func LoadRegistrySubkey(key, path string) error {
	return exec.Command("cmd", "/C", "reg", "load", fmt.Sprintf(`HKEY_LOCAL_MACHINE\%s`, key), path).Run()
}

// UnloadRegistrySubkey runs reg.exe directly rather than through cmd.exe, so
// that the timeout terminates reg.exe itself and not only the shell around it.
func UnloadRegistrySubkey(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), unloadTimeout)
	defer cancel()

	hive := fmt.Sprintf(`HKEY_LOCAL_MACHINE\%s`, key)
	err := exec.CommandContext(ctx, "reg", "unload", hive).Run()
	if ctx.Err() != nil {
		return fmt.Errorf("reg unload %s did not finish within %s", hive, unloadTimeout)
	}
	return err
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package resources

import (
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// lookupAccountSids resolves names through LookupAccountName, the API
// NTAccount.Translate wraps, so a local scan spawns no PowerShell for endpoint
// protection to score. Unresolvable names are dropped, as on the PowerShell path.
func lookupAccountSids(names []string) (map[string]string, bool) {
	res := make(map[string]string, len(names))
	for _, name := range names {
		sid, _, _, err := windows.LookupSID("", name)
		if err != nil {
			log.Debug().Str("account", name).Err(err).Msg("could not resolve account name to a SID")
			continue
		}
		res[name] = sid.String()
	}
	return res, true
}

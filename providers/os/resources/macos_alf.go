// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/types"
)

// alfPlistLocations holds the ALF preferences file, which is where the
// firewall settings were stored through macOS 14.
//
// /usr/libexec/ApplicationFirewall/com.apple.alf.plist is deliberately NOT
// listed. That file is the factory-default template the OS ships with, not
// live state: it is owned by root inside a SIP-protected directory and always
// reads globalstate 0 / stealthenabled 0. Recent macOS releases no longer
// write /Library/Preferences/com.apple.alf.plist at all, so treating the
// template as a fallback reported the firewall as disabled with stealth mode
// off on every such machine, whatever the firewall was actually doing.
// macos.firewall reads the live state from socketfilterfw instead.
var alfPlistLocations = []string{
	"/Library/Preferences/com.apple.alf.plist",
}

func initMacosAlf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)

	if args == nil {
		args = map[string]*llx.RawData{}
	}

	var plistLocation string
	fs := conn.FileSystem()
	for _, loc := range alfPlistLocations {
		log.Debug().Str("location", loc).Msg("Checking for ALF configuration")
		s, err := fs.Stat(loc)
		if err == nil && !s.IsDir() {
			log.Debug().Str("location", loc).Msg("Found ALF configuration")
			plistLocation = loc
			break
		}
	}

	if plistLocation == "" {
		return nil, nil, errors.New("ALF configuration not found")
	}

	f, err := fs.Open(plistLocation)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	alfConfig, err := plist.Decode(f)
	if err != nil {
		return nil, nil, err
	}

	explicitAuthsRaw := alfConfig["explicitauths"].([]any)
	explicitAuths := []any{}
	for i := range explicitAuthsRaw {
		entry := explicitAuthsRaw[i].(map[string]any)
		explicitAuths = append(explicitAuths, entry["id"])
	}

	args["allowDownloadSignedEnabled"] = llx.IntData(int64(alfConfig["allowdownloadsignedenabled"].(float64)))
	args["allowSignedEnabled"] = llx.IntData(int64(alfConfig["allowsignedenabled"].(float64)))
	args["firewallUnload"] = llx.IntData(int64(alfConfig["firewallunload"].(float64)))
	args["globalState"] = llx.IntData(int64(alfConfig["globalstate"].(float64)))
	args["loggingEnabled"] = llx.IntData(int64(alfConfig["loggingenabled"].(float64)))
	args["loggingOption"] = llx.IntData(int64(alfConfig["loggingoption"].(float64)))
	args["stealthEnabled"] = llx.IntData(int64(alfConfig["stealthenabled"].(float64)))
	args["version"] = llx.StringData(alfConfig["version"].(string))
	args["exceptions"] = llx.ArrayData(alfConfig["exceptions"].([]any), types.Dict)
	args["explicitAuths"] = llx.ArrayData(explicitAuths, types.String)
	args["applications"] = llx.ArrayData(alfConfig["applications"].([]any), types.Dict)

	return args, nil, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/config"
)

// addProxyConfig hands this process's proxy decision to a provider subprocess.
//
// The cloud SDKs inside providers read only HTTP_PROXY, HTTPS_PROXY and
// NO_PROXY, so a proxy that came from the operating system's settings (Windows
// Internet Settings, the WinHTTP default) has to travel as those variables or
// the provider's AWS, Azure and GCP calls go direct and fail behind the proxy
// the CLI itself just used. A system_proxy: false opt-out travels as
// MONDOO_SYSTEM_PROXY=false so the provider's own platform client makes the
// same choice. See config.ProviderEnvironment for what is and is not exported.
//
// go-plugin appends os.Environ() after these assignments and exec keeps the
// last value of a repeated variable, so anything already in the environment
// is inherited unchanged.
func addProxyConfig(cmd *exec.Cmd) {
	env := config.ProviderEnvironment()
	if len(env) == 0 {
		return
	}
	keys := make([]string, 0, len(env))
	for _, kv := range env {
		// keys only: a proxy URL may carry credentials
		keys = append(keys, strings.SplitN(kv, "=", 2)[0])
	}
	log.Debug().Strs("variables", keys).Msg("passing proxy settings to the provider")
	cmd.Env = append(cmd.Env, env...)
}

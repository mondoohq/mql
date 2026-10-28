// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mcpServerAsset builds the native `asset` value that anchors an MCP server
// resource to the asset discovered for it. The anchor is the resource's own
// (type, id); the owning host asset is contextual. Both this forward accessor
// and the mcp-servers discovery resolver derive the anchor the same way (from
// the resource identity), so they stay in lockstep. See ADR 030.
func mcpServerAsset(r plugin.Resource) *llx.AssetValue {
	return &llx.AssetValue{
		ResourceType: r.MqlName(),
		ResourceId:   r.MqlID(),
	}
}

// MCP transport types. These mirror the values AI tools write into their MCP
// config files; when a config omits the type we infer it from the connection
// shape (see deriveMcpTransport).
const (
	mcpTransportStdio = "stdio"
	mcpTransportHTTP  = "http"
)

// deriveMcpTransport returns the transport type for an MCP server. An explicit
// value from the config wins (lowercased, since transport names are a
// conventionally-lowercase set and configs may spell them any case); otherwise
// it is inferred from the connection shape: a local launch command implies
// stdio, a remote endpoint URL implies http. Returns an empty string when
// neither is present.
//
// Tools name the same transports differently, so the spellings that mean
// stdio or streamable HTTP are folded onto those two: Copilot CLI and OpenCode
// write "local" for stdio, OpenCode writes "remote", and Cline, Goose and
// Mistral Vibe spell streamable HTTP three different ways.
func deriveMcpTransport(explicitType, command, url string) string {
	if explicitType != "" {
		switch t := strings.ToLower(explicitType); t {
		case "local":
			return mcpTransportStdio
		case "remote", "streamablehttp", "streamable-http", "streamable_http":
			return mcpTransportHTTP
		default:
			return t
		}
	}
	if command != "" {
		return mcpTransportStdio
	}
	if url != "" {
		return mcpTransportHTTP
	}
	return ""
}

// mcpArgsData converts an MCP server's command-line arguments into the llx
// string-array RawData every mcpServer resource uses for its args field, with
// secrets passed on the command line redacted (see redactArgs).
func mcpArgsData(in []string) *llx.RawData {
	in = redactArgs(in)
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return llx.ArrayData(out, types.String)
}

// mcpNames returns the union of the given name lists, deduplicated and
// sorted, so a server's envNames and headerNames are stable across runs.
// Empty names are dropped. The result is never nil, an absent list is empty.
func mcpNames(lists ...[]string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, list := range lists {
		for _, n := range list {
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// mapKeys returns the keys of a map, in no particular order. Only the names
// of environment variables and headers are read, never their values.
func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Package runners an MCP server command can start. Each one fetches a
// package or image and runs it.
const (
	mcpLauncherNpx    = "npx"
	mcpLauncherBunx   = "bunx"
	mcpLauncherPnpm   = "pnpm dlx"
	mcpLauncherYarn   = "yarn dlx"
	mcpLauncherUvx    = "uvx"
	mcpLauncherPipx   = "pipx run"
	mcpLauncherDocker = "docker run"
	mcpLauncherPodman = "podman run"
)

// mcpLaunch is what a server's command says about the package it runs.
type mcpLaunch struct {
	// launcher is the package runner, empty for any other command.
	launcher string
	// packageName is the package or image, without version, tag or digest.
	packageName string
	// pinned reports whether the package is fixed to one exact release.
	pinned bool
}

// launcherFlags describes the flags of a package runner that come before the
// package: valueFlags take the next argument as their value, packageFlags
// name the package explicitly (npx -p, uvx --from, pipx run --spec). Any other
// argument starting with "-" is a flag without a value.
type launcherFlags struct {
	valueFlags   map[string]bool
	packageFlags map[string]bool
}

var (
	npmRunnerFlags = launcherFlags{
		valueFlags: map[string]bool{
			"-c": true, "--call": true, "--registry": true, "--cache": true,
			"--userconfig": true, "--node-options": true, "--workspace": true, "-w": true,
		},
		packageFlags: map[string]bool{"-p": true, "--package": true},
	}
	uvxFlags = launcherFlags{
		valueFlags: map[string]bool{
			"--with": true, "-w": true, "--with-requirements": true, "--with-editable": true,
			"--python": true, "-p": true, "--index": true, "--index-url": true, "-i": true,
			"--extra-index-url": true, "--default-index": true, "--find-links": true, "-f": true,
			"--directory": true, "--project": true, "--config-file": true, "--cache-dir": true,
			"--constraints": true, "-c": true, "--overrides": true, "--env-file": true,
			"--python-preference": true, "--index-strategy": true, "--keyring-provider": true,
			"--resolution": true, "--prerelease": true, "--exclude-newer": true,
			"--refresh-package": true, "--reinstall-package": true, "--upgrade-package": true,
			"-P": true, "--color": true, "--link-mode": true,
		},
		packageFlags: map[string]bool{"--from": true},
	}
	pipxRunFlags = launcherFlags{
		valueFlags: map[string]bool{
			"--python": true, "--pip-args": true, "--index-url": true, "-i": true, "--backend": true,
		},
		packageFlags: map[string]bool{"--spec": true},
	}
	containerRunFlags = launcherFlags{
		valueFlags: map[string]bool{
			"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true,
			"--name": true, "-p": true, "--publish": true, "--network": true, "--net": true,
			"-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true,
			"--mount": true, "-l": true, "--label": true, "--label-file": true, "--platform": true,
			"--pull": true, "--add-host": true, "--cap-add": true, "--cap-drop": true,
			"-m": true, "--memory": true, "--cpus": true, "-h": true, "--hostname": true,
			"--security-opt": true, "--device": true, "--tmpfs": true, "--ulimit": true,
			"--restart": true, "--runtime": true, "--gpus": true, "--dns": true,
			"--log-driver": true, "--log-opt": true, "--ipc": true, "--pid": true,
			"--userns": true, "--cidfile": true, "--stop-signal": true, "--stop-timeout": true,
			"--shm-size": true, "--group-add": true, "--expose": true, "--ip": true,
			"--mac-address": true, "--cgroupns": true, "--uts": true, "--volumes-from": true,
			"--secret": true, "--arch": true, "--os": true, "--authfile": true,
		},
	}
)

// launcherPackageSpec returns the package argument of a package runner: the
// value of a package flag when one is given, otherwise the first argument
// that is not a flag.
func launcherPackageSpec(args []string, flags launcherFlags) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return a
		}
		name, value, hasValue := strings.Cut(a, "=")
		if flags.packageFlags[name] {
			if hasValue {
				return value
			}
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if flags.valueFlags[name] && !hasValue {
			i++
		}
	}
	return ""
}

// commandBase is the program name of a command, without directory or a
// Windows executable extension, lowercased.
func commandBase(command string) string {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(command, "\\", "/")))
	for _, ext := range []string{".cmd", ".exe", ".bat", ".ps1"} {
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

// parseMcpLaunch reads the package runner and the package it fetches from a
// server's command and args. A command that is not one of the package runners
// returns an empty launch.
func parseMcpLaunch(command string, args []string) mcpLaunch {
	base := commandBase(command)
	sub := func(n int) []string {
		if len(args) < n {
			return nil
		}
		return args[n:]
	}
	first := ""
	if len(args) > 0 {
		first = args[0]
	}

	switch {
	case base == "npx":
		return npmLaunch(mcpLauncherNpx, launcherPackageSpec(args, npmRunnerFlags))
	case base == "bunx" || (base == "bun" && first == "x"):
		rest := args
		if base == "bun" {
			rest = sub(1)
		}
		return npmLaunch(mcpLauncherBunx, launcherPackageSpec(rest, npmRunnerFlags))
	case base == "pnpm" && first == "dlx":
		return npmLaunch(mcpLauncherPnpm, launcherPackageSpec(sub(1), npmRunnerFlags))
	case base == "yarn" && first == "dlx":
		return npmLaunch(mcpLauncherYarn, launcherPackageSpec(sub(1), npmRunnerFlags))
	case base == "uvx":
		return pypiLaunch(mcpLauncherUvx, launcherPackageSpec(args, uvxFlags), true)
	case base == "uv" && len(args) >= 2 && args[0] == "tool" && args[1] == "run":
		return pypiLaunch(mcpLauncherUvx, launcherPackageSpec(sub(2), uvxFlags), true)
	case base == "pipx" && first == "run":
		return pypiLaunch(mcpLauncherPipx, launcherPackageSpec(sub(1), pipxRunFlags), false)
	case base == "docker" || base == "podman":
		launcher := mcpLauncherDocker
		if base == "podman" {
			launcher = mcpLauncherPodman
		}
		rest := args
		if first == "container" {
			rest = sub(1)
		}
		if len(rest) == 0 || rest[0] != "run" {
			return mcpLaunch{}
		}
		return imageLaunch(launcher, launcherPackageSpec(rest[1:], containerRunFlags))
	}
	return mcpLaunch{}
}

// exactSemver matches an exact npm version, for example 1.2.3 or
// 1.2.3-beta.1. Ranges (^1.2, ~1.2.3, 1.x, >=1) and dist-tags (latest) do not
// match.
var exactSemver = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// npmLaunch splits an npm package spec (name, name@version,
// @scope/name@version) into its name and whether the version is exact.
func npmLaunch(launcher, spec string) mcpLaunch {
	out := mcpLaunch{launcher: launcher}
	if spec == "" {
		return out
	}
	name, version := spec, ""
	if at := strings.LastIndex(spec, "@"); at > 0 {
		name, version = spec[:at], spec[at+1:]
	}
	out.packageName = name
	out.pinned = exactSemver.MatchString(version)
	return out
}

// pypiVersion matches a release version written after == or @, for example
// 1.0 or 2.3.1rc1. A wildcard (1.*) does not match.
var pypiVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+!-]*$`)

// pypiLaunch splits a PyPI requirement (name, name==1.0, name[extra]==1.0,
// and for uvx name@1.0) into its name and whether it names one exact
// release. A range (>=1.0, ~=1.0), a wildcard (==1.*), or @latest is not
// pinned.
func pypiLaunch(launcher, spec string, allowAt bool) mcpLaunch {
	out := mcpLaunch{launcher: launcher}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return out
	}
	end := strings.IndexAny(spec, "[=<>~!@; ")
	if end < 0 {
		out.packageName = spec
		return out
	}
	out.packageName = spec[:end]
	rest := spec[end:]
	if strings.HasPrefix(rest, "[") {
		if end := strings.Index(rest, "]"); end >= 0 {
			rest = rest[end+1:]
		}
	}
	rest = strings.TrimSpace(rest)
	switch {
	case strings.HasPrefix(rest, "==="):
		out.pinned = pypiVersion.MatchString(strings.TrimSpace(rest[3:]))
	case strings.HasPrefix(rest, "=="):
		out.pinned = pypiVersion.MatchString(strings.TrimSpace(rest[2:]))
	case allowAt && strings.HasPrefix(rest, "@"):
		out.pinned = pypiVersion.MatchString(strings.TrimSpace(rest[1:]))
	}
	return out
}

// imageDigest matches a container image pinned by content digest.
var imageDigest = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)

// imageLaunch splits a container image reference into its repository and
// whether it is pinned by digest. A tag alone is not pinned: it can be
// pushed again with different content.
func imageLaunch(launcher, ref string) mcpLaunch {
	out := mcpLaunch{launcher: launcher}
	if ref == "" {
		return out
	}
	out.pinned = imageDigest.MatchString(ref)
	name := ref
	if at := strings.Index(name, "@"); at >= 0 {
		name = name[:at]
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	out.packageName = name
	return out
}

// mcpInsecureTransport reports whether a server URL uses plain http:// to a
// host other than localhost or a loopback address.
func mcpInsecureTransport(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

// setMcpServerShape adds the fields every mcpServer resource derives from its
// command, args, url and environment variable names: envNames, launcher,
// packageName, packagePinned and insecureTransport. envNames is the sorted
// union of the given name lists. packagePinned is null when the command is
// not a package runner or names no package.
func setMcpServerShape(fields map[string]*llx.RawData, command string, args []string, serverURL string, envNames ...[]string) {
	launch := parseMcpLaunch(command, args)
	fields["envNames"] = llx.ArrayData(llx.TArr2Raw(mcpNames(envNames...)), types.String)
	fields["launcher"] = llx.StringData(launch.launcher)
	fields["packageName"] = llx.StringData(launch.packageName)
	if launch.launcher == "" || launch.packageName == "" {
		fields["packagePinned"] = &llx.RawData{Type: types.Bool}
	} else {
		fields["packagePinned"] = llx.BoolData(launch.pinned)
	}
	fields["insecureTransport"] = llx.BoolData(mcpInsecureTransport(serverURL))
}

// mcpHeaderNamesData is the headerNames field of an mcpServer resource.
func mcpHeaderNamesData(names ...[]string) *llx.RawData {
	return llx.ArrayData(llx.TArr2Raw(mcpNames(names...)), types.String)
}

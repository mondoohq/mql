// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// runtimeKind selects how the runtime() accessor resolves an agent's host — the
// software the agent runs *inside* (docs/adr/058-ai-security-ard.md). The host is
// returned as a package resource, mirroring package() (the installer).
type runtimeKind int

const (
	// runtimeOS: a standalone agent (a CLI, or a standalone editor such as Cursor
	// or Zed) runs directly on the operating system — runtime() is the OS as a
	// package (purl pkg:platform/...).
	runtimeOS runtimeKind = iota
	// runtimeIDE: an editor plugin runs inside an IDE — runtime() is the editor
	// package (VS Code, a fork, or a JetBrains IDE).
	runtimeIDE
	// runtimeBrowser: a browser extension runs inside a browser — runtime() is
	// the browser package.
	runtimeBrowser
)

// toolPackageSpec describes how a tool resource resolves its backing package
// (the `package` accessor added to each AI coding-tool resource). See
// docs/adr/028-tool-install-indicator.md for the design.
type toolPackageSpec struct {
	// packageName is the canonical name used for an abstract package. Because
	// an abstract package has an unknown source (origin "unknown"), this is a
	// clean tool identifier (the resource name with dots turned into hyphens),
	// not a guess at an upstream package name.
	packageName string
	// binaryNames are the tool's executables on the target's PATH. They drive
	// the primary attribution path: resolve the binary, ask the OS package
	// manager which package owns it (pacman -Qo / dpkg -S / rpm -qf / apk
	// who-owns), and return that real, manager-tracked package. This works
	// regardless of how the package is named, so it is preferred over
	// managerCandidates. Leave empty for tools whose binary name collides with
	// an unrelated package (e.g. bare "goose"/"gemini") to avoid mis-attributing
	// the wrong install; those rely on managerCandidates instead.
	binaryNames []string
	// managerCandidates are names tried against the system package managers via
	// the name-based `package(name)` lookup, used as a fallback when binary
	// ownership finds nothing. Curated conservatively: only distinctive,
	// low-false-positive names are listed.
	managerCandidates []string
	// vendor is the producing vendor when confidently known; empty otherwise.
	vendor string
	// inferVersion optionally determines the tool version for the abstract
	// package. Best-effort: it returns "" (unknown) rather than an error when
	// the source is missing or unreadable.
	inferVersion func(runtime *plugin.Runtime, configPath string) (string, error)

	// runtime selects the host the tool runs in (see runtimeKind). The zero value
	// (runtimeOS) means a standalone agent hosted by the OS.
	runtime runtimeKind
	// runtimeHostName is the display name of the host (editor/browser) used for
	// the abstract fallback when no real host package can be resolved. Only
	// consulted for runtimeIDE / runtimeBrowser.
	runtimeHostName string
	// runtimeHostCandidates are package-manager names tried (by name) to resolve
	// the real host editor/browser package. Only consulted for runtimeIDE /
	// runtimeBrowser; falls back to an abstract host package named runtimeHostName.
	runtimeHostCandidates []string

	// vscodeExtensionIDs are the marketplace ids ("publisher.name") of the VS
	// Code extension that is the tool, for agents that ship as an editor
	// plugin. An installed extension is a stronger presence signal than the
	// config directory, which many of these plugins never create (they keep
	// their state in the editor's globalStorage), and it carries the version.
	vscodeExtensionIDs []string
	// configIsFile marks a tool whose configPath names a file rather than a
	// directory (Aider's .aider.conf.yml), so presence is the file existing.
	configIsFile bool
}

// toolPackageSpecs is keyed by MQL resource name.
var toolPackageSpecs = map[string]toolPackageSpec{
	"claude.code":    {packageName: "claude-code", binaryNames: []string{"claude"}, vendor: "Anthropic", inferVersion: inferClaudeVersion},
	"openai.codex":   {packageName: "openai-codex", binaryNames: []string{"codex"}, vendor: "OpenAI", inferVersion: inferCodexVersion},
	"cursor":         {packageName: "cursor", binaryNames: []string{"cursor"}, managerCandidates: []string{"cursor"}, vendor: "Anysphere"},
	"github.copilot": {packageName: "github-copilot", vendor: "GitHub", runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates},
	// Bare "goose"/"gemini" are intentionally NOT used as binaryNames: "goose"
	// collides with the widely-packaged pressly/goose DB-migration tool, and
	// "gemini" is ambiguous — attributing either by binary name risks pointing
	// at the wrong package. They fall back to distinctive candidate package
	// names (the real Gemini CLI ships as npm `@google/gemini-cli`, which no OS
	// manager owns, so it resolves to an abstract package).
	"goose":            {packageName: "goose", managerCandidates: []string{"block-goose-cli"}, vendor: "Block"},
	"gemini":           {packageName: "gemini", managerCandidates: []string{"gemini-cli"}, vendor: "Google"},
	"windsurf":         {packageName: "windsurf", binaryNames: []string{"windsurf"}, managerCandidates: []string{"windsurf"}},
	"zed":              {packageName: "zed", binaryNames: []string{"zed"}, managerCandidates: []string{"zed"}, vendor: "Zed Industries"},
	"roo":              {packageName: "roo", runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates, vscodeExtensionIDs: []string{"RooVeterinaryInc.roo-cline"}},
	"cline":            {packageName: "cline", runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates, vscodeExtensionIDs: []string{"saoudrizwan.claude-dev"}},
	"kiro":             {packageName: "kiro", binaryNames: []string{"kiro"}, managerCandidates: []string{"kiro"}},
	"continuedev":      {packageName: "continuedev", runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates, vscodeExtensionIDs: []string{"Continue.continue"}},
	"trae":             {packageName: "trae", managerCandidates: []string{"trae"}},
	"opencode":         {packageName: "opencode", binaryNames: []string{"opencode"}, managerCandidates: []string{"opencode"}},
	"pi":               {packageName: "pi"},
	"mistral.vibe":     {packageName: "mistral-vibe", vendor: "Mistral AI"},
	"antigravity":      {packageName: "antigravity", managerCandidates: []string{"antigravity"}, vendor: "Google"},
	"ibm.bob":          {packageName: "ibm-bob", vendor: "IBM"},
	"openclaw":         {packageName: "openclaw"},
	"snowflake.cortex": {packageName: "snowflake-cortex", vendor: "Snowflake"},
	"junie":            {packageName: "junie", managerCandidates: []string{"junie"}, vendor: "JetBrains", runtime: runtimeIDE, runtimeHostName: "JetBrains IDE"},
	"augment":          {packageName: "augment", runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates, vscodeExtensionIDs: []string{"augment.vscode-augment"}},
	"warp":             {packageName: "warp", vendor: "Warp"},
	"kilocode":         {packageName: "kilocode", managerCandidates: []string{"kilocode"}, runtime: runtimeIDE, runtimeHostName: "Visual Studio Code", runtimeHostCandidates: vscodeHostCandidates, vscodeExtensionIDs: []string{"kilocode.Kilo-Code"}},
	"openhands":        {packageName: "openhands", binaryNames: []string{"openhands"}, managerCandidates: []string{"openhands"}},
	"qwen.code":        {packageName: "qwen-code", binaryNames: []string{"qwen"}, vendor: "Alibaba"},
	// The desktop app installs per user (Windows, macOS), so no package manager
	// owns it; presence is its configuration directory.
	"claude.desktop": {packageName: "claude-desktop", vendor: "Anthropic"},
	// Aider installs with pip/pipx/uv, which OS package managers do not track;
	// "aider-chat" is its distribution name where one does (AUR, Homebrew).
	"aider": {packageName: "aider", binaryNames: []string{"aider"}, managerCandidates: []string{"aider-chat"}, configIsFile: true},
	// Ollama is a model server rather than a coding agent, but it is installed
	// and versioned the same way, so it resolves through the same path.
	"ollama": {packageName: "ollama", binaryNames: []string{"ollama"}, managerCandidates: []string{"ollama"}, vendor: "Ollama", inferVersion: inferOllamaVersion},
}

// resolveToolPackage returns the real system-package-manager entry that
// installed the tool when it can be attributed to one, otherwise an abstract
// package (origin "unknown", empty format, never inserted into `packages`).
func resolveToolPackage(runtime *plugin.Runtime, configPath string, spec toolPackageSpec) (*mqlPackage, error) {
	// (a) Strongest signal: ask the OS package manager which installed package
	// owns the tool's binary (pacman -Qo / dpkg -S / rpm -qf / apk who-owns),
	// then resolve that name to the real, manager-tracked package already in
	// the `packages` collection. This works regardless of the package's name.
	if conn, ok := runtime.Connection.(shared.Connection); ok {
		for _, bin := range spec.binaryNames {
			ownerName, err := packages.FindPackageOwningBinary(conn, bin)
			if err != nil {
				return nil, err
			}
			if ownerName == "" {
				continue
			}
			pkg, err := lookupInstalledPackage(runtime, ownerName)
			if err != nil {
				return nil, err
			}
			if pkg != nil {
				return pkg, nil
			}
		}
	}

	// (b) Weaker signal: try curated candidate package names by name. Resolves
	// to the same real, cached `packages` instance when one matches.
	for _, name := range spec.managerCandidates {
		pkg, err := lookupInstalledPackage(runtime, name)
		if err != nil {
			return nil, err
		}
		if pkg != nil {
			return pkg, nil
		}
	}

	// (c) Not attributable to any manager — detect presence and, where
	// possible, a version, then synthesize an abstract package. An installed
	// editor extension is both a presence signal and the version source.
	installed := configPresent(runtime, configPath, spec.configIsFile)
	version := ""
	if len(spec.vscodeExtensionIDs) > 0 {
		if homes, err := targetUserHomes(runtime); err == nil {
			dirs := make([]string, 0, len(homes))
			for _, u := range homes {
				dirs = append(dirs, u.home)
			}
			if v, ok := findVSCodeExtension(connectionAfs(runtime), dirs, spec.vscodeExtensionIDs); ok {
				installed = true
				version = v
			}
		}
	}
	if installed && version == "" && spec.inferVersion != nil {
		v, err := spec.inferVersion(runtime, configPath)
		if err != nil {
			return nil, err
		}
		version = v
	}

	// synthetic id; distinct from the real "format://name/version/arch" scheme
	// and hidden (no `id` field on package).
	return newSyntheticPackage(runtime, "tool://"+spec.packageName, spec.packageName, version, spec.vendor, "", installed)
}

// newSyntheticPackage creates an abstract package resource (origin "unknown", no
// package-manager format, never inserted into `packages`) with the given
// identity. Every remaining field is given a resolved state (null unless
// meaningful) so any field queries cleanly, mirroring the initPackage not-found
// stub. Shared by the tool package() accessor and the runtime() host accessor;
// pass purlStr for a host whose package URL is known (e.g. the OS), "" otherwise.
func newSyntheticPackage(runtime *plugin.Runtime, id, name, version, vendor, purlStr string, installed bool) (*mqlPackage, error) {
	raw, err := CreateResource(runtime, "package", map[string]*llx.RawData{
		"__id":      llx.StringData(id),
		"name":      llx.StringData(name),
		"installed": llx.BoolData(installed),
		"origin":    llx.StringData("unknown"), // abstract discriminator (seeds origin())
		"format":    llx.StringData(""),        // no package-manager format
	})
	if err != nil {
		return nil, err
	}
	pkg := raw.(*mqlPackage)

	setStrOrNull(&pkg.Version, version)
	setStrOrNull(&pkg.Vendor, vendor)
	setStrOrNull(&pkg.Purl, purlStr)

	pkg.Outdated = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	pkg.Epoch.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Available.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Description.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Cpes.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Arch.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Status.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Files.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.License.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.InstallDate.State = plugin.StateIsSet | plugin.StateIsNull
	pkg.Macos.State = plugin.StateIsSet | plugin.StateIsNull

	return pkg, nil
}

// vscodeHostCandidates are the package-manager names of VS Code and its common
// forks, tried when resolving the real host editor package for an IDE-plugin
// agent (mirrors vsCodeEditors in vscode.go). Falls back to an abstract editor
// package when none is manager-tracked (the common case for user-space installs).
var vscodeHostCandidates = []string{"code", "code-insiders", "vscodium", "cursor", "windsurf"}

// resolveRuntimePackage returns the host the tool runs inside — the OS for a
// standalone agent, the editor for an IDE plugin, the browser for a browser
// extension — as a package resource (docs/adr/058-ai-security-ard.md). runtime()
// is optional: it returns (nil, nil) when the host cannot be determined.
func resolveRuntimePackage(runtime *plugin.Runtime, spec toolPackageSpec) (*mqlPackage, error) {
	switch spec.runtime {
	case runtimeIDE, runtimeBrowser:
		return resolveHostRuntimePackage(runtime, spec)
	case runtimeOS:
		return resolveOSRuntimePackage(runtime)
	default:
		// any future/unset kind: treat as a standalone OS-hosted agent
		return resolveOSRuntimePackage(runtime)
	}
}

// resolveOSRuntimePackage synthesizes the operating system as a package, carrying
// the platform purl (pkg:platform/...) so the server can look the OS up in its
// vulnerability data exactly as it does for the agent's own installer package.
func resolveOSRuntimePackage(runtime *plugin.Runtime) (*mqlPackage, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil || conn.Asset().Platform == nil {
		return nil, nil // host undeterminable; runtime is optional
	}
	pf := conn.Asset().Platform
	purlStr, err := purl.NewPlatformPurl(pf)
	if err != nil {
		purlStr = ""
	}
	name := pf.Title
	if name == "" {
		name = pf.Name
	}
	return newSyntheticPackage(runtime, "runtime://os/"+pf.Name+"@"+pf.Version, name, pf.Version, "", purlStr, true)
}

// resolveHostRuntimePackage resolves an IDE/browser host. It first tries the real
// manager-tracked editor/browser package by name (which carries a purl the server
// can score); when none is found — the usual case for user-space editor/browser
// installs — it synthesizes an abstract host package named for the host so the
// runtime is still identified (name, no version/purl).
func resolveHostRuntimePackage(runtime *plugin.Runtime, spec toolPackageSpec) (*mqlPackage, error) {
	for _, name := range spec.runtimeHostCandidates {
		pkg, err := lookupInstalledPackage(runtime, name)
		if err != nil {
			return nil, err
		}
		if pkg != nil {
			return pkg, nil
		}
	}
	if spec.runtimeHostName == "" {
		return nil, nil // host undeterminable; runtime is optional
	}
	return newSyntheticPackage(runtime, "runtime://host/"+spec.packageName, spec.runtimeHostName, "", "", "", true)
}

// resolveRuntime resolves the host the tool runs inside (OS / IDE / browser) and
// wraps it as an extensionRuntime resource whose `package` carries the host's
// software identity for vulnerability lookup. runtime is optional: when the host
// cannot be determined it marks field explicitly null and returns (nil, nil).
// Setting the null state is required — GetOrCompute records only StateIsSet (not
// StateIsNull) for a nil result, and a singular resource accessor that returns
// nil without a null state makes the runtime panic or re-fetch (CLAUDE.md §3).
func resolveRuntime(field *plugin.TValue[*mqlExtensionRuntime], runtime *plugin.Runtime, spec toolPackageSpec) (*mqlExtensionRuntime, error) {
	pkg, err := resolveRuntimePackage(runtime, spec)
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil // host undeterminable; runtime is optional
	}
	// One extensionRuntime per distinct host package: keying by the package id
	// lets agents that share a host (e.g. all VS Code plugins) share the wrapper.
	raw, err := CreateResource(runtime, "extensionRuntime", map[string]*llx.RawData{
		"__id":    llx.StringData(pkg.MqlID()),
		"package": llx.ResourceData(pkg, "package"),
	})
	if err != nil {
		return nil, err
	}
	return raw.(*mqlExtensionRuntime), nil
}

// lookupInstalledPackage resolves a package by name to the real, cached
// instance from the `packages` collection (via initPackage — the same object
// that appears in `packages`). Returns nil when no such package is installed,
// so callers fall through to the next attribution signal.
func lookupInstalledPackage(runtime *plugin.Runtime, name string) (*mqlPackage, error) {
	raw, err := NewResource(runtime, "package", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	if pkg, ok := raw.(*mqlPackage); ok && pkg.Installed.Data {
		return pkg, nil
	}
	return nil, nil
}

// configDirPresent is the presence signal for the abstract-package fallback:
// the tool's configPath directory exists on the target. Best-effort — used only
// when binary ownership and name candidates both come up empty.
func configDirPresent(runtime *plugin.Runtime, configPath string) bool {
	return configPresent(runtime, configPath, false)
}

// configPresent reports whether configPath exists on the target as a directory,
// or as a regular file when isFile is set.
func configPresent(runtime *plugin.Runtime, configPath string, isFile bool) bool {
	if configPath == "" {
		return false
	}
	info, err := connectionAfs(runtime).Stat(configPath)
	if err != nil {
		return false
	}
	if isFile {
		return info.Mode().IsRegular()
	}
	return info.IsDir()
}

// findVSCodeExtension looks for an installed VS Code-family extension with one
// of the given marketplace ids ("publisher.name") in the extension directories
// of each home (vsCodeEditors), and returns the highest installed version.
// Matching reads each candidate's package.json, since the directory name is
// only "<id>-<version>" by convention and its case differs between editors.
// Ids compare case-insensitively, as the marketplace does. ok is true when an
// extension is found, even if its package.json carries no version.
func findVSCodeExtension(afs *afero.Afero, homes []string, ids []string) (version string, ok bool) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[strings.ToLower(id)] = struct{}{}
	}
	for _, home := range homes {
		for _, editor := range vsCodeEditors {
			extensionsDir := filepath.Join(home, editor.dir)
			entries, err := afs.ReadDir(extensionsDir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() || !hasExtensionIDPrefix(entry.Name(), want) {
					continue
				}
				pkg, err := readVSCodePackageJSON(afs, filepath.Join(extensionsDir, entry.Name(), "package.json"))
				if err != nil {
					continue
				}
				if _, match := want[strings.ToLower(pkg.Publisher+"."+pkg.Name)]; !match {
					continue
				}
				ok = true
				if pkg.Version != "" && (version == "" || semverLess(version, pkg.Version)) {
					version = pkg.Version
				}
			}
		}
	}
	return version, ok
}

// hasExtensionIDPrefix is a cheap pre-filter on an extension directory name
// ("<publisher>.<name>-<version>") before its package.json is read.
func hasExtensionIDPrefix(dirName string, want map[string]struct{}) bool {
	lower := strings.ToLower(dirName)
	for id := range want {
		if lower == id || strings.HasPrefix(lower, id+"-") {
			return true
		}
	}
	return false
}

// semverLess reports whether a sorts before b by MQL's semver parser, falling
// back to a string comparison when either does not parse.
func semverLess(a, b string) bool {
	if cmp, err := (semver.Parser{}).Compare(a, b); err == nil {
		return cmp < 0
	}
	return a < b
}

// setStrOrNull sets a string field to val, or to a resolved-null state when val
// is empty, so the field always reads cleanly in MQL.
func setStrOrNull(t *plugin.TValue[string], val string) {
	if val != "" {
		*t = plugin.TValue[string]{Data: val, State: plugin.StateIsSet}
	} else {
		*t = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
}

// inferCodexVersion runs `codex --version` through the command resource. Codex
// writes no authoritative version file (its version.json only records the latest
// release seen during an update check, which goes stale and is not the installed
// version), so we probe the binary. The output is e.g. "codex-cli 0.44.0"; we
// keep the first token MQL's semver parser recognizes. Best-effort: unknown when
// the binary is absent or the output carries no recognizable version.
func inferCodexVersion(runtime *plugin.Runtime, configPath string) (string, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("codex --version"),
	})
	if err != nil {
		return "", nil
	}
	cmd := o.(*mqlCommand)
	if cmd.GetExitcode().Data != 0 {
		return "", nil
	}
	for _, field := range strings.Fields(cmd.GetStdout().Data) {
		// Validate with MQL's semver parser instead of a bespoke regex. The
		// parser exposes only Compare, so we parse by self-compare: a valid
		// version compares against itself without error.
		if _, err := (semver.Parser{}).Compare(field, field); err == nil {
			return field, nil
		}
	}
	return "", nil
}

// inferClaudeVersion runs `claude --version` through the command resource
// (Claude Code writes no version file, so we probe the binary). The output is
// e.g. "2.1.191 (Claude Code)"; we take the leading token and keep it only if
// MQL's semver parser recognizes it. Best-effort: unknown when the binary is
// absent or the output carries no recognizable version.
func inferClaudeVersion(runtime *plugin.Runtime, configPath string) (string, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("claude --version"),
	})
	if err != nil {
		return "", nil
	}
	cmd := o.(*mqlCommand)
	if cmd.GetExitcode().Data != 0 {
		return "", nil
	}
	fields := strings.Fields(cmd.GetStdout().Data)
	if len(fields) == 0 {
		return "", nil
	}
	version := fields[0]
	// Validate with MQL's semver parser instead of a bespoke regex. The parser
	// exposes only Compare, so we parse by self-compare: a valid version
	// compares against itself without error; an invalid one returns an error.
	if _, err := (semver.Parser{}).Compare(version, version); err != nil {
		return "", nil
	}
	return version, nil
}

// compute_package accessors — one per tool resource. Each delegates to the
// shared resolver with the tool's spec. The method name is compute_package (not
// package) because `package` is a Go keyword; the generator's fieldCall prefixes
// reserved words with "compute_".

func (r *mqlClaudeCode) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["claude.code"])
}

func (r *mqlOpenaiCodex) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["openai.codex"])
}

func (r *mqlCursor) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["cursor"])
}

func (r *mqlGithubCopilot) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["github.copilot"])
}

func (r *mqlGoose) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["goose"])
}

func (r *mqlGemini) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["gemini"])
}

func (r *mqlWindsurf) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["windsurf"])
}

func (r *mqlZed) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["zed"])
}

func (r *mqlRoo) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["roo"])
}

func (r *mqlCline) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["cline"])
}

func (r *mqlKiro) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["kiro"])
}

func (r *mqlContinuedev) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["continuedev"])
}

func (r *mqlTrae) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["trae"])
}

func (r *mqlOpencode) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["opencode"])
}

func (r *mqlPi) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["pi"])
}

func (r *mqlMistralVibe) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["mistral.vibe"])
}

func (r *mqlAntigravity) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["antigravity"])
}

func (r *mqlIbmBob) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["ibm.bob"])
}

func (r *mqlOpenclaw) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["openclaw"])
}

func (r *mqlSnowflakeCortex) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["snowflake.cortex"])
}

func (r *mqlJunie) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["junie"])
}

func (r *mqlAugment) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["augment"])
}

func (r *mqlWarp) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["warp"])
}

func (r *mqlKilocode) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["kilocode"])
}

func (r *mqlOpenhands) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["openhands"])
}

func (r *mqlQwenCode) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["qwen.code"])
}

func (r *mqlClaudeDesktop) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["claude.desktop"])
}

func (r *mqlAider) compute_package() (*mqlPackage, error) {
	return resolveToolPackage(r.MqlRuntime, r.ConfigPath.Data, toolPackageSpecs["aider"])
}

// runtime() accessors — one per tool resource — return the host the agent runs
// inside (OS / IDE / browser) as an extensionRuntime, per each tool's spec.
// `runtime` is not a Go keyword, so the generator emits a plain runtime()
// method (unlike compute_package).

func (r *mqlClaudeCode) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["claude.code"])
}

func (r *mqlOpenaiCodex) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["openai.codex"])
}

func (r *mqlCursor) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["cursor"])
}

func (r *mqlGithubCopilot) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["github.copilot"])
}

func (r *mqlGoose) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["goose"])
}

func (r *mqlGemini) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["gemini"])
}

func (r *mqlWindsurf) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["windsurf"])
}

func (r *mqlZed) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["zed"])
}

func (r *mqlRoo) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["roo"])
}

func (r *mqlCline) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["cline"])
}

func (r *mqlKiro) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["kiro"])
}

func (r *mqlContinuedev) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["continuedev"])
}

func (r *mqlTrae) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["trae"])
}

func (r *mqlOpencode) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["opencode"])
}

func (r *mqlPi) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["pi"])
}

func (r *mqlMistralVibe) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["mistral.vibe"])
}

func (r *mqlAntigravity) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["antigravity"])
}

func (r *mqlIbmBob) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["ibm.bob"])
}

func (r *mqlOpenclaw) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["openclaw"])
}

func (r *mqlSnowflakeCortex) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["snowflake.cortex"])
}

func (r *mqlJunie) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["junie"])
}

func (r *mqlAugment) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["augment"])
}

func (r *mqlWarp) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["warp"])
}

func (r *mqlKilocode) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["kilocode"])
}

func (r *mqlOpenhands) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["openhands"])
}

func (r *mqlQwenCode) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["qwen.code"])
}

func (r *mqlClaudeDesktop) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["claude.desktop"])
}

func (r *mqlAider) runtime() (*mqlExtensionRuntime, error) {
	return resolveRuntime(&r.Runtime, r.MqlRuntime, toolPackageSpecs["aider"])
}

// inferOllamaVersion runs `ollama --version` through the command resource, for
// an installation no package manager owns (the official install script drops a
// binary into /usr/local/bin without registering it anywhere). Best-effort:
// unknown when the binary is absent or the output carries no version.
func inferOllamaVersion(runtime *plugin.Runtime, configPath string) (string, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("ollama --version"),
	})
	if err != nil {
		return "", nil
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil || exit.Data != 0 {
		return "", nil
	}
	return parseOllamaVersion(cmd.GetStdout().Data), nil
}

// parseOllamaVersion pulls the version out of `ollama --version`. The command
// reports two different lines depending on whether a server is reachable:
// "ollama version is 0.32.14" when one is, and a "client version is 0.32.14"
// warning when none is. The client line is preferred, because it is the version
// of the binary installed here rather than of whatever server OLLAMA_HOST points
// at, which may be another machine entirely.
func parseOllamaVersion(stdout string) string {
	var serverVersion string
	for _, line := range strings.Split(stdout, "\n") {
		_, rest, found := strings.Cut(line, "version is")
		if !found {
			continue
		}
		v := strings.TrimSpace(rest)
		if v == "" {
			continue
		}
		v = strings.Fields(v)[0]
		if strings.Contains(line, "client version") {
			return v
		}
		if serverVersion == "" {
			serverVersion = v
		}
	}
	return serverVersion
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- Roo Code ---

const defaultRooConfigDir = ".roo"

func initRoo(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "roo", defaultRooConfigDir)
}

func (r *mqlRoo) id() (string, error) {
	return "roo/" + r.ConfigPath.Data, nil
}

func (r *mqlRoo) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "roo.skill", r.ConfigPath.Data, defaultRooConfigDir,
		filepath.Join(defaultRooConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlRooSkill) id() (string, error)     { return "roo.skill/" + r.Source.Data, nil }
func (r *mqlRooSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlRooSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Cline ---

const defaultClineConfigDir = ".cline"

func initCline(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "cline", defaultClineConfigDir)
}

func (r *mqlCline) id() (string, error) {
	return "cline/" + r.ConfigPath.Data, nil
}

func (r *mqlCline) skills() ([]any, error) {
	// Cline reads skills from the shared ~/.agents/skills directory (not its own
	// ~/.cline config dir), matching the vercel-labs/skills convention.
	return agentSkills(r.MqlRuntime, "cline.skill", r.ConfigPath.Data, defaultClineConfigDir,
		filepath.Join(".agents", "skills"),
		filepath.Join(filepath.Dir(r.ConfigPath.Data), ".agents", "skills"))
}

func (r *mqlClineSkill) id() (string, error)     { return "cline.skill/" + r.Source.Data, nil }
func (r *mqlClineSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlClineSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Kiro CLI ---

const defaultKiroConfigDir = ".kiro"

func initKiro(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "kiro", defaultKiroConfigDir)
}

func (r *mqlKiro) id() (string, error) {
	return "kiro/" + r.ConfigPath.Data, nil
}

func (r *mqlKiro) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "kiro.skill", r.ConfigPath.Data, defaultKiroConfigDir,
		filepath.Join(defaultKiroConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlKiroSkill) id() (string, error)     { return "kiro.skill/" + r.Source.Data, nil }
func (r *mqlKiroSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlKiroSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Continue ---

const defaultContinueConfigDir = ".continue"

func initContinuedev(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "continuedev", defaultContinueConfigDir)
}

func (r *mqlContinuedev) id() (string, error) {
	return "continuedev/" + r.ConfigPath.Data, nil
}

func (r *mqlContinuedev) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "continuedev.skill", r.ConfigPath.Data, defaultContinueConfigDir,
		filepath.Join(defaultContinueConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlContinuedevSkill) id() (string, error)     { return "continuedev.skill/" + r.Source.Data, nil }
func (r *mqlContinuedevSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlContinuedevSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Trae ---

const defaultTraeConfigDir = ".trae"

func initTrae(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "trae", defaultTraeConfigDir)
}

func (r *mqlTrae) id() (string, error) {
	return "trae/" + r.ConfigPath.Data, nil
}

func (r *mqlTrae) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "trae.skill", r.ConfigPath.Data, defaultTraeConfigDir,
		filepath.Join(defaultTraeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlTraeSkill) id() (string, error)     { return "trae.skill/" + r.Source.Data, nil }
func (r *mqlTraeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlTraeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- OpenCode ---

const defaultOpenCodeConfigDir = ".config/opencode"

func initOpencode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "opencode", defaultOpenCodeConfigDir)
}

func (r *mqlOpencode) id() (string, error) {
	return "opencode/" + r.ConfigPath.Data, nil
}

func (r *mqlOpencode) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "opencode.skill", r.ConfigPath.Data, defaultOpenCodeConfigDir,
		filepath.Join(defaultOpenCodeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlOpencodeSkill) id() (string, error)     { return "opencode.skill/" + r.Source.Data, nil }
func (r *mqlOpencodeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlOpencodeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Pi ---

const defaultPiConfigDir = ".pi/agent"

func initPi(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "pi", defaultPiConfigDir)
}

func (r *mqlPi) id() (string, error) {
	return "pi/" + r.ConfigPath.Data, nil
}

func (r *mqlPi) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "pi.skill", r.ConfigPath.Data, defaultPiConfigDir,
		filepath.Join(defaultPiConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlPiSkill) id() (string, error)     { return "pi.skill/" + r.Source.Data, nil }
func (r *mqlPiSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlPiSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Mistral Vibe ---

const defaultMistralVibeConfigDir = ".vibe"

func initMistralVibe(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "mistral.vibe", defaultMistralVibeConfigDir)
}

func (r *mqlMistralVibe) id() (string, error) {
	return "mistral.vibe/" + r.ConfigPath.Data, nil
}

func (r *mqlMistralVibe) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "mistral.vibe.skill", r.ConfigPath.Data, defaultMistralVibeConfigDir,
		filepath.Join(defaultMistralVibeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlMistralVibeSkill) id() (string, error)     { return "mistral.vibe.skill/" + r.Source.Data, nil }
func (r *mqlMistralVibeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlMistralVibeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Antigravity (Google) ---

const defaultAntigravityConfigDir = ".gemini/antigravity"

func initAntigravity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "antigravity", defaultAntigravityConfigDir)
}

func (r *mqlAntigravity) id() (string, error) {
	return "antigravity/" + r.ConfigPath.Data, nil
}

// defaultAntigravityCLIConfigDir is where the Antigravity CLI (agy) keeps its
// user configuration: skills, plugins, mcp_config.json and hooks.json.
const defaultAntigravityCLIConfigDir = ".gemini/config"

// antigravityCLIConfigDir is the CLI's configuration directory beside an IDE
// configPath of <home>/.gemini/antigravity. Empty for a configPath of any
// other shape, which names no CLI directory.
func antigravityCLIConfigDir(configPath string) string {
	dir := filepath.Dir(configPath)
	if filepath.Base(configPath) != "antigravity" || filepath.Base(dir) != ".gemini" {
		return ""
	}
	return filepath.Join(dir, "config")
}

func (r *mqlAntigravity) skills() ([]any, error) {
	dirs, err := resolvePerUserDirs(r.MqlRuntime, r.ConfigPath.Data, defaultAntigravityConfigDir,
		filepath.Join(defaultAntigravityConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
	if err != nil {
		return nil, err
	}
	if cliDir := antigravityCLIConfigDir(r.ConfigPath.Data); cliDir != "" {
		cliDirs, err := resolvePerUserDirs(r.MqlRuntime, r.ConfigPath.Data, defaultAntigravityConfigDir,
			filepath.Join(defaultAntigravityCLIConfigDir, "skills"), filepath.Join(cliDir, "skills"))
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, cliDirs...)
	}
	return readSkillsFromDirs(r.MqlRuntime, dirs, "antigravity.skill")
}

// mcpServers reads the CLI's mcp_config.json and the IDE's, in that order.
func (r *mqlAntigravity) mcpServers() ([]any, error) {
	var paths []string
	if cliDir := antigravityCLIConfigDir(r.ConfigPath.Data); cliDir != "" {
		paths = append(paths, filepath.Join(cliDir, "mcp_config.json"))
	}
	paths = append(paths, filepath.Join(r.ConfigPath.Data, "mcp_config.json"))
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime), paths, "mcpServers")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "antigravity.mcpServer", specs)
}

func (r *mqlAntigravityMcpServer) id() (string, error) {
	return mcpServerResourceID("antigravity.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlAntigravityMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlAntigravityMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlAntigravitySkill) id() (string, error)     { return "antigravity.skill/" + r.Source.Data, nil }
func (r *mqlAntigravitySkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlAntigravitySkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- IBM Bob ---

const defaultBobConfigDir = ".bob"

func initIbmBob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "ibm.bob", defaultBobConfigDir)
}

func (r *mqlIbmBob) id() (string, error) {
	return "ibm.bob/" + r.ConfigPath.Data, nil
}

func (r *mqlIbmBob) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "ibm.bob.skill", r.ConfigPath.Data, defaultBobConfigDir,
		filepath.Join(defaultBobConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlIbmBobSkill) id() (string, error)     { return "ibm.bob.skill/" + r.Source.Data, nil }
func (r *mqlIbmBobSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlIbmBobSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- OpenClaw ---

const defaultOpenClawConfigDir = ".openclaw"

func initOpenclaw(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "openclaw", defaultOpenClawConfigDir)
}

func (r *mqlOpenclaw) id() (string, error) {
	return "openclaw/" + r.ConfigPath.Data, nil
}

func (r *mqlOpenclaw) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "openclaw.skill", r.ConfigPath.Data, defaultOpenClawConfigDir,
		filepath.Join(defaultOpenClawConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlOpenclawSkill) id() (string, error)     { return "openclaw.skill/" + r.Source.Data, nil }
func (r *mqlOpenclawSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlOpenclawSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Snowflake Cortex Code ---

const defaultCortexConfigDir = ".snowflake/cortex"

func initSnowflakeCortex(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "snowflake.cortex", defaultCortexConfigDir)
}

func (r *mqlSnowflakeCortex) id() (string, error) {
	return "snowflake.cortex/" + r.ConfigPath.Data, nil
}

func (r *mqlSnowflakeCortex) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "snowflake.cortex.skill", r.ConfigPath.Data, defaultCortexConfigDir,
		filepath.Join(defaultCortexConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlSnowflakeCortexSkill) id() (string, error) {
	return "snowflake.cortex.skill/" + r.Source.Data, nil
}
func (r *mqlSnowflakeCortexSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlSnowflakeCortexSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Junie (JetBrains) ---

const defaultJunieConfigDir = ".junie"

func initJunie(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "junie", defaultJunieConfigDir)
}

func (r *mqlJunie) id() (string, error) {
	return "junie/" + r.ConfigPath.Data, nil
}

func (r *mqlJunie) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "junie.skill", r.ConfigPath.Data, defaultJunieConfigDir,
		filepath.Join(defaultJunieConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlJunieSkill) id() (string, error)     { return "junie.skill/" + r.Source.Data, nil }
func (r *mqlJunieSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlJunieSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Augment ---

const defaultAugmentConfigDir = ".augment"

func initAugment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "augment", defaultAugmentConfigDir)
}

func (r *mqlAugment) id() (string, error) {
	return "augment/" + r.ConfigPath.Data, nil
}

func (r *mqlAugment) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "augment.skill", r.ConfigPath.Data, defaultAugmentConfigDir,
		filepath.Join(defaultAugmentConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlAugmentSkill) id() (string, error)     { return "augment.skill/" + r.Source.Data, nil }
func (r *mqlAugmentSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlAugmentSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Warp ---

const defaultWarpConfigDir = ".warp"

func initWarp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "warp", defaultWarpConfigDir)
}

func (r *mqlWarp) id() (string, error) {
	return "warp/" + r.ConfigPath.Data, nil
}

func (r *mqlWarp) skills() ([]any, error) {
	// Warp reads skills from the shared ~/.agents/skills directory.
	return agentSkills(r.MqlRuntime, "warp.skill", r.ConfigPath.Data, defaultWarpConfigDir,
		filepath.Join(".agents", "skills"),
		filepath.Join(filepath.Dir(r.ConfigPath.Data), ".agents", "skills"))
}

func (r *mqlWarpSkill) id() (string, error)     { return "warp.skill/" + r.Source.Data, nil }
func (r *mqlWarpSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlWarpSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Kilo Code ---

const defaultKiloCodeConfigDir = ".kilocode"

func initKilocode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "kilocode", defaultKiloCodeConfigDir)
}

func (r *mqlKilocode) id() (string, error) {
	return "kilocode/" + r.ConfigPath.Data, nil
}

func (r *mqlKilocode) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "kilocode.skill", r.ConfigPath.Data, defaultKiloCodeConfigDir,
		filepath.Join(defaultKiloCodeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlKilocodeSkill) id() (string, error)     { return "kilocode.skill/" + r.Source.Data, nil }
func (r *mqlKilocodeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlKilocodeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- OpenHands ---

const defaultOpenHandsConfigDir = ".openhands"

func initOpenhands(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "openhands", defaultOpenHandsConfigDir)
}

func (r *mqlOpenhands) id() (string, error) {
	return "openhands/" + r.ConfigPath.Data, nil
}

func (r *mqlOpenhands) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "openhands.skill", r.ConfigPath.Data, defaultOpenHandsConfigDir,
		filepath.Join(defaultOpenHandsConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlOpenhandsSkill) id() (string, error)     { return "openhands.skill/" + r.Source.Data, nil }
func (r *mqlOpenhandsSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlOpenhandsSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Qwen Code ---

const defaultQwenCodeConfigDir = ".qwen"

func initQwenCode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "qwen.code", defaultQwenCodeConfigDir)
}

func (r *mqlQwenCode) id() (string, error) {
	return "qwen.code/" + r.ConfigPath.Data, nil
}

func (r *mqlQwenCode) skills() ([]any, error) {
	dirs, err := resolvePerUserDirs(r.MqlRuntime, r.ConfigPath.Data, defaultQwenCodeConfigDir,
		filepath.Join(defaultQwenCodeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
	if err != nil {
		return nil, err
	}
	exts := r.GetExtensions()
	if exts.Error != nil {
		return nil, exts.Error
	}
	for _, e := range exts.Data {
		if ext := e.(*mqlQwenCodeExtension); ext.Enabled.Data {
			dirs = append(dirs, ext.ext.skillsDir)
		}
	}
	return readSkillsFromDirs(r.MqlRuntime, dirs, "qwen.code.skill")
}

func (r *mqlQwenCodeSkill) id() (string, error)     { return "qwen.code.skill/" + r.Source.Data, nil }
func (r *mqlQwenCodeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlQwenCodeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Devin Desktop ---

// devinDesktopConfigDir is where Devin Desktop keeps its MCP servers and global
// skills, relative to the user's home: ~/.config/devin on macOS and Linux (XDG,
// not ~/Library), %APPDATA%\devin on Windows. The Devin CLI shares it.
func devinDesktopConfigDir(osFamily string) string {
	if osFamily == "windows" {
		return filepath.Join("AppData", "Roaming", "devin")
	}
	return filepath.Join(".config", "devin")
}

func initDevinDesktop(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "devin.desktop", devinDesktopConfigDir)
}

func (r *mqlDevinDesktop) id() (string, error) {
	return "devin.desktop/" + r.ConfigPath.Data, nil
}

func (r *mqlDevinDesktop) skills() ([]any, error) {
	defaultDir := devinDesktopConfigDir(runtimeOSFamily(r.MqlRuntime))
	return agentSkills(r.MqlRuntime, "devin.desktop.skill", r.ConfigPath.Data, defaultDir,
		filepath.Join(defaultDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlDevinDesktopSkill) id() (string, error) {
	return "devin.desktop.skill/" + r.Source.Data, nil
}
func (r *mqlDevinDesktopSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlDevinDesktopSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- ZCode ---

const defaultZcodeConfigDir = ".zcode"

func initZcode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "zcode", defaultZcodeConfigDir)
}

func (r *mqlZcode) id() (string, error) {
	return "zcode/" + r.ConfigPath.Data, nil
}

func (r *mqlZcode) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "zcode.skill", r.ConfigPath.Data, defaultZcodeConfigDir,
		filepath.Join(defaultZcodeConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlZcodeSkill) id() (string, error)     { return "zcode.skill/" + r.Source.Data, nil }
func (r *mqlZcodeSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlZcodeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Qualia ---

// qualiaConfigDir is Qualia's settings directory relative to the user's home,
// named for its bundle id on every platform.
func qualiaConfigDir(osFamily string) string {
	switch osFamily {
	case "darwin":
		return filepath.Join("Library", "Application Support", "io.quadrillion.qualia")
	case "windows":
		return filepath.Join("AppData", "Roaming", "io.quadrillion.qualia")
	default: // linux and other unix-likes
		return filepath.Join(".config", "io.quadrillion.qualia")
	}
}

func initQualia(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "qualia", qualiaConfigDir)
}

func (r *mqlQualia) id() (string, error) {
	return "qualia/" + r.ConfigPath.Data, nil
}

// --- Builder.io ---

const defaultBuilderioConfigDir = ".builder"

func initBuilderio(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "builderio", defaultBuilderioConfigDir)
}

func (r *mqlBuilderio) id() (string, error) {
	return "builderio/" + r.ConfigPath.Data, nil
}

func (r *mqlBuilderio) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "builderio.skill", r.ConfigPath.Data, defaultBuilderioConfigDir,
		filepath.Join(defaultBuilderioConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlBuilderioSkill) id() (string, error)     { return "builderio.skill/" + r.Source.Data, nil }
func (r *mqlBuilderioSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlBuilderioSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// --- Claude Platform CLI ---

// anthropicCLIConfigDir is the anthropic-sdk-go configuration directory the
// CLI keeps its profiles and credentials in, relative to the user's home:
// ~/.config/anthropic on macOS and Linux, %APPDATA%\Anthropic on Windows.
func anthropicCLIConfigDir(osFamily string) string {
	if osFamily == "windows" {
		return filepath.Join("AppData", "Roaming", "Anthropic")
	}
	return filepath.Join(".config", "anthropic")
}

func initAnthropicCli(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "anthropic.cli", anthropicCLIConfigDir)
}

func (r *mqlAnthropicCli) id() (string, error) {
	return "anthropic.cli/" + r.ConfigPath.Data, nil
}

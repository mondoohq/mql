// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
	"go.mondoo.com/mql/types"
	"sigs.k8s.io/yaml"
)

// initConfigPath is a shared init helper for resources that resolve a
// configPath from the target's home directory (e.g. claude.code, openai.codex).
func initConfigPath(runtime *plugin.Runtime, args map[string]*llx.RawData, resourceName, defaultDir string) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["configPath"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, fmt.Errorf("wrong type for 'configPath' in %s initialization, it must be a string", resourceName)
		}
		if path == "" {
			delete(args, "configPath")
		}
	}

	if _, ok := args["configPath"]; !ok {
		// Resolve the home directory from the target's user list, not the local host.
		home, err := targetHomeDir(runtime)
		if err != nil {
			return nil, nil, err
		}
		args["configPath"] = llx.StringData(filepath.Join(home, defaultDir))
	}

	return args, nil, nil
}

// connectionAfs returns an afero.Afero wrapping the connection's filesystem.
func connectionAfs(runtime *plugin.Runtime) *afero.Afero {
	conn := runtime.Connection.(shared.Connection)
	return &afero.Afero{Fs: conn.FileSystem()}
}

// listSubdirsAfero returns the names and full paths of subdirectories in dir,
// following symlinks so that symlinked directories are included.
func listSubdirsAfero(afs *afero.Afero, dir string) ([]subdirEntry, error) {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var result []subdirEntry
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		// Stat follows symlinks; ReadDir returns Lstat info where
		// symlinked directories report IsDir()==false.
		info, err := afs.Stat(fullPath)
		if err != nil || !info.IsDir() {
			continue
		}
		result = append(result, subdirEntry{name: entry.Name(), path: fullPath})
	}
	return result, nil
}

type subdirEntry struct {
	name string
	path string
}

// readJSONFileAfero reads and unmarshals a JSON file relative to a base directory
// using the provided afero filesystem (which may be remote via SSH, container, etc.).
func readJSONFileAfero(afs *afero.Afero, baseDir string, relPath string, v interface{}) error {
	data, err := afs.ReadFile(filepath.Join(baseDir, relPath))
	if err != nil {
		return err
	}
	return unmarshalJSONConfig(data, v)
}

// unmarshalJSONConfig parses an AI tool's JSON config file. An empty or
// whitespace-only file is an empty config, not a malformed one: tools create
// the file before anything is configured (Antigravity writes a zero-byte
// mcp_config.json), and json.Unmarshal rejects empty input with "unexpected end
// of JSON input", which would turn "no MCP servers" into an error.
func unmarshalJSONConfig(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// dirHasFilesAfero returns true if the directory contains at least one non-directory entry.
func dirHasFilesAfero(afs *afero.Afero, dir string) bool {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// contentSHA256 returns the hex-encoded SHA-256 digest of s.
func contentSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Skill parsing types and functions shared by claude.code and openai.codex.

type skillInfo struct {
	name         string
	description  string
	allowedTools []string
	argumentHint string
	source       string
	content      string
}

type skillFrontmatter struct {
	Name         string `json:"name" yaml:"name"`
	Description  string `json:"description" yaml:"description"`
	AllowedTools string `json:"allowed-tools" yaml:"allowed-tools"`
	ArgumentHint string `json:"argument-hint" yaml:"argument-hint"`
}

func parseSkillMd(name, sourcePath, content string) skillInfo {
	info := skillInfo{
		name:    name,
		source:  sourcePath,
		content: content,
	}

	// Extract YAML frontmatter between --- delimiters
	if !strings.HasPrefix(content, "---\n") {
		return info
	}

	endIdx := strings.Index(content[4:], "\n---")
	if endIdx == -1 {
		return info
	}

	frontmatter := content[4 : 4+endIdx]
	var fm skillFrontmatter
	if err := yaml.Unmarshal([]byte(frontmatter), &fm); err != nil {
		return info
	}

	if fm.Name != "" {
		info.name = fm.Name
	}
	info.description = fm.Description
	info.argumentHint = fm.ArgumentHint

	// allowed-tools is a comma-separated string in both Claude Code and Codex SKILL.md files
	if fm.AllowedTools != "" {
		for _, tool := range strings.Split(fm.AllowedTools, ",") {
			tool = strings.TrimSpace(tool)
			if tool != "" {
				info.allowedTools = append(info.allowedTools, tool)
			}
		}
	}

	return info
}

// targetHomeDir resolves a single user's home as the anchor for a default
// configPath: the logged-in user if any, else the first real user. Data that
// must cover every account (e.g. agent skills) should use targetUserHomes.
func targetHomeDir(runtime *plugin.Runtime) (string, error) {
	users, err := targetUserHomes(runtime)
	if err != nil {
		return "", err
	}

	conn := runtime.Connection.(shared.Connection)
	loggedIn, _ := loggedInUsers(runtime, conn)

	var fallback string
	for _, u := range users {
		// Prefer a user that is currently logged in.
		if loggedIn[u.name] {
			return u.home, nil
		}
		if fallback == "" {
			fallback = u.home
		}
	}

	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no valid user home directory found on target")
}

// collectSkillFiles reads SKILL.md files from the subdirectories of each
// skillsDir, deduped by source path. Unreadable dirs (missing or
// permission-denied when scanning another user's home) are skipped.
func collectSkillFiles(afs *afero.Afero, skillsDirs []string) []skillInfo {
	var result []skillInfo
	seen := map[string]struct{}{}
	for _, skillsDir := range skillsDirs {
		subdirs, err := listSubdirsAfero(afs, skillsDir)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Debug().Err(err).Str("path", skillsDir).Msg("skipping unreadable AI agent skills directory")
			}
			continue
		}

		for _, dir := range subdirs {
			skillPath := filepath.Join(dir.path, "SKILL.md")
			if _, ok := seen[skillPath]; ok {
				continue
			}
			// Mark seen before reading so an unreadable file isn't retried when
			// the same skills dir appears more than once.
			seen[skillPath] = struct{}{}
			data, err := afs.ReadFile(skillPath)
			if err != nil {
				continue
			}
			result = append(result, parseSkillMd(dir.name, skillPath, string(data)))
		}
	}
	return result
}

// readSkillsFromDirs reads SKILL.md files across skillsDirs and returns them as
// MQL resources of resourceType, keyed by source path so same-named skills from
// different users are all reported.
func readSkillsFromDirs(runtime *plugin.Runtime, skillsDirs []string, resourceType string) ([]interface{}, error) {
	skills := collectSkillFiles(connectionAfs(runtime), skillsDirs)

	result := make([]interface{}, 0, len(skills))
	for _, skill := range skills {
		allowedToolsAny := make([]interface{}, len(skill.allowedTools))
		for i, t := range skill.allowedTools {
			allowedToolsAny[i] = t
		}

		res, err := NewResource(runtime, resourceType, map[string]*llx.RawData{
			"__id":         llx.StringData(resourceType + "/" + skill.source),
			"name":         llx.StringData(skill.name),
			"description":  llx.StringData(skill.description),
			"allowedTools": llx.ArrayData(allowedToolsAny, types.String),
			"argumentHint": llx.StringData(skill.argumentHint),
			"source":       llx.StringData(skill.source),
			"content":      llx.StringData(skill.content),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// resolvePerUserDirs resolves a per-user directory list for a resource.
// homeRelDir is the directory relative to each home (e.g. ".cursor/skills").
// When configPath is a per-user default — it matches home/defaultConfigDir for
// some enumerated user — it returns homeRelDir under every user's home, deduped.
// Otherwise (a custom configPath override, or no users could be enumerated) it
// returns just overrideDir, honoring the override exactly.
func resolvePerUserDirs(runtime *plugin.Runtime, configPath, defaultConfigDir, homeRelDir, overrideDir string) []string {
	users, err := targetUserHomes(runtime)
	if err != nil {
		log.Debug().Err(err).Msg("cannot enumerate users; using configPath only")
		return []string{overrideDir}
	}

	// Detect the default case first so the per-user list is built only when used.
	// No match (including an empty user list) means a custom override.
	isDefault := false
	for _, u := range users {
		if filepath.Join(u.home, defaultConfigDir) == configPath {
			isDefault = true
			break
		}
	}
	if !isDefault {
		return []string{overrideDir}
	}

	seen := map[string]struct{}{}
	var dirs []string
	for _, u := range users {
		d := filepath.Join(u.home, homeRelDir)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		dirs = append(dirs, d)
	}
	return dirs
}

// agentSkills reads an agent's skills across every user, honoring a configPath
// override. For agents whose skills sit at a fixed path under each home.
func agentSkills(runtime *plugin.Runtime, resourceType, configPath, defaultConfigDir, homeRelSkillsDir, overrideSkillsDir string) ([]interface{}, error) {
	dirs := resolvePerUserDirs(runtime, configPath, defaultConfigDir, homeRelSkillsDir, overrideSkillsDir)
	return readSkillsFromDirs(runtime, dirs, resourceType)
}

// skillsAllUsers reads skills from homeRelSkillsDir under every user's home, for
// agents whose skills location is independent of configPath (e.g. Copilot).
func skillsAllUsers(runtime *plugin.Runtime, homeRelSkillsDir, resourceType string) ([]interface{}, error) {
	users, err := targetUserHomes(runtime)
	if err != nil {
		log.Debug().Err(err).Msg("cannot enumerate users for AI agent skills")
		return nil, nil
	}
	dirs := make([]string, 0, len(users))
	for _, u := range users {
		dirs = append(dirs, filepath.Join(u.home, homeRelSkillsDir))
	}
	return readSkillsFromDirs(runtime, dirs, resourceType)
}

// gitRepoResult holds the fields derived from a project's git working tree.
type gitRepoResult struct {
	root    string
	url     string
	host    string
	name    string
	branch  string
	remotes map[string]string
}

// gitReposFromPaths resolves each path to its git working tree and returns
// deduplicated repo resources of resourceName. Paths that are not inside a git
// working tree are skipped, and repositories are deduplicated by their
// working-tree root so multiple paths inside one checkout collapse to one repo.
// It is shared by the AI agent resources (claude.code, openai.codex, cursor,
// windsurf, zed) whose repos() derive git repositories from project paths.
func gitReposFromPaths(runtime *plugin.Runtime, resourceName string, paths []string) ([]interface{}, error) {
	afs := connectionAfs(runtime)
	seen := map[string]struct{}{}
	var result []interface{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		info, ok := gitRepoInfo(afs, p)
		if !ok {
			continue
		}
		if _, dup := seen[info.root]; dup {
			continue
		}
		seen[info.root] = struct{}{}

		res, err := NewResource(runtime, resourceName, map[string]*llx.RawData{
			"__id":    llx.StringData(resourceName + "/" + info.root),
			"path":    llx.StringData(info.root),
			"url":     llx.StringData(info.url),
			"host":    llx.StringData(info.host),
			"name":    llx.StringData(info.name),
			"branch":  llx.StringData(info.branch),
			"remotes": llx.MapData(llx.TMap2Raw(info.remotes), types.String),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// gitRepoInfo locates the git working-tree root for startPath and parses its
// config and HEAD. It returns ok=false when startPath is not inside a git
// working tree (no reachable .git). Both a normal checkout (`.git` directory)
// and a linked worktree (`.git` file pointing at a `gitdir:`) are supported;
// for a worktree the shared config comes from the common git dir while HEAD is
// read per-worktree.
func gitRepoInfo(afs *afero.Afero, startPath string) (gitRepoResult, bool) {
	root, gitPath, ok := findGitPath(afs, startPath)
	if !ok {
		return gitRepoResult{}, false
	}

	configPath, headPath := resolveGitConfigAndHead(afs, root, gitPath)

	res := gitRepoResult{root: root}
	res.remotes = parseGitRemotes(afs, configPath)
	res.url = res.remotes["origin"]
	if res.url == "" {
		// No origin: fall back to any single remote so a repo with only an
		// upstream (or a differently-named remote) still surfaces a URL.
		for _, u := range res.remotes {
			res.url = u
			break
		}
	}
	res.host, res.name = parseGitRemoteURL(res.url)
	res.branch = parseGitHeadBranch(afs, headPath)
	return res, true
}

// findGitPath walks up from startPath until it finds a .git entry (directory or
// file), stopping at the filesystem root. It returns the working-tree root (the
// directory holding .git) and the path to that .git entry.
func findGitPath(afs *afero.Afero, startPath string) (root string, gitPath string, ok bool) {
	dir := filepath.Clean(startPath)
	for {
		p := filepath.Join(dir, ".git")
		if _, err := afs.Stat(p); err == nil {
			return dir, p, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false
		}
		dir = parent
	}
}

// resolveGitConfigAndHead returns the config and HEAD paths for a .git entry.
// For a plain `.git` directory both live inside it. For a linked worktree
// (`.git` is a file with a `gitdir:` line), HEAD lives in the per-worktree git
// dir and config lives in the shared common git dir.
func resolveGitConfigAndHead(afs *afero.Afero, root, gitPath string) (configPath, headPath string) {
	commonDir, worktreeDir := resolveGitDirs(afs, root, gitPath)
	return filepath.Join(commonDir, "config"), filepath.Join(worktreeDir, "HEAD")
}

// resolveGitDirs returns the shared common git dir (holding config, refs and
// packed-refs) and the per-worktree git dir (holding HEAD) for a .git entry.
// For a plain `.git` directory both are that directory. For a linked worktree
// (`.git` is a file with a `gitdir:` line) the per-worktree git dir holds HEAD
// while the shared data lives in the common git dir.
func resolveGitDirs(afs *afero.Afero, root, gitPath string) (commonDir, worktreeDir string) {
	info, err := afs.Stat(gitPath)
	if err == nil && info.IsDir() {
		return gitPath, gitPath
	}

	worktreeGitDir, ok := parseGitdirFile(afs, gitPath, root)
	if !ok {
		// Unreadable or malformed pointer: best-effort, treat as if inline.
		return gitPath, gitPath
	}

	return resolveGitCommonDir(afs, worktreeGitDir), worktreeGitDir
}

// parseGitdirFile reads a `.git` pointer file and returns the absolute git dir
// it references. A relative gitdir is resolved against the worktree root.
func parseGitdirFile(afs *afero.Afero, gitFilePath, root string) (string, bool) {
	data, err := afs.ReadFile(gitFilePath)
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	dir := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if dir == "" {
		return "", false
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	return filepath.Clean(dir), true
}

// resolveGitCommonDir returns the shared common git dir for a per-worktree git
// dir. It honors the `commondir` file when present, otherwise falls back to the
// conventional `<common>/worktrees/<name>` layout (two levels up).
func resolveGitCommonDir(afs *afero.Afero, worktreeGitDir string) string {
	data, err := afs.ReadFile(filepath.Join(worktreeGitDir, "commondir"))
	if err == nil {
		common := strings.TrimSpace(string(data))
		if common != "" {
			if !filepath.IsAbs(common) {
				common = filepath.Join(worktreeGitDir, common)
			}
			return filepath.Clean(common)
		}
	}
	return filepath.Dir(filepath.Dir(worktreeGitDir))
}

// parseGitRemotes reads a git config file and returns a map of remote name to
// fetch URL. It is a minimal INI reader scoped to `[remote "<name>"]` sections;
// a missing or unreadable file yields an empty map.
func parseGitRemotes(afs *afero.Afero, configPath string) map[string]string {
	data, err := afs.ReadFile(configPath)
	if err != nil {
		return map[string]string{}
	}

	remotes := map[string]string{}
	var currentRemote string
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentRemote = ""
			// section header, e.g. [remote "origin"]
			header := strings.TrimSpace(line[1 : len(line)-1])
			if name, ok := parseRemoteSection(header); ok {
				currentRemote = name
			}
			continue
		}
		if currentRemote == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "url" {
			remotes[currentRemote] = strings.TrimSpace(value)
		}
	}
	return remotes
}

// parseRemoteSection returns the remote name from a section header of the form
// `remote "origin"`, and false for any other section.
func parseRemoteSection(header string) (string, bool) {
	const prefix = "remote "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	name := strings.TrimSpace(header[len(prefix):])
	name = strings.Trim(name, "\"")
	if name == "" {
		return "", false
	}
	return name, true
}

// parseGitRemoteURL extracts the host and owner/name slug from a git remote
// URL, handling both scp-style (git@github.com:owner/repo.git) and
// URL-style (https://github.com/owner/repo.git, ssh://git@host/owner/repo)
// forms. It returns empty strings when the URL cannot be parsed.
func parseGitRemoteURL(remote string) (host string, name string) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", ""
	}

	var rest string
	switch {
	case strings.Contains(remote, "://"):
		// scheme://[user@]host[:port]/path
		rest = remote[strings.Index(remote, "://")+3:]
		if at := strings.LastIndex(rest, "@"); at != -1 {
			rest = rest[at+1:]
		}
		slash := strings.Index(rest, "/")
		if slash == -1 {
			return "", ""
		}
		host = rest[:slash]
		name = rest[slash+1:]
	case strings.Contains(remote, "@") && strings.Contains(remote, ":"):
		// scp-style: [user@]host:path
		rest = remote[strings.Index(remote, "@")+1:]
		colon := strings.Index(rest, ":")
		if colon == -1 {
			return "", ""
		}
		host = rest[:colon]
		name = rest[colon+1:]
	default:
		return "", ""
	}

	// strip a :port suffix from the host
	if colon := strings.Index(host, ":"); colon != -1 {
		host = host[:colon]
	}
	name = strings.TrimSuffix(strings.Trim(name, "/"), ".git")
	return host, name
}

// parseGitHeadBranch reads .git/HEAD and returns the branch name it points at,
// or "" when HEAD is detached or unreadable.
func parseGitHeadBranch(afs *afero.Afero, headPath string) string {
	data, err := afs.ReadFile(headPath)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	const refPrefix = "ref: refs/heads/"
	if !strings.HasPrefix(line, refPrefix) {
		// detached HEAD (a raw commit SHA) has no branch name
		return ""
	}
	return strings.TrimPrefix(line, refPrefix)
}

// skillPURL derives a package URL (purl) for a skill from the path of its
// SKILL.md definition. When the skill directory sits inside a git checkout
// whose origin remote points at github.com, the purl pins the checkout's
// current HEAD commit:
//
//	pkg:github/<org>/<repo>@<first 12 chars of HEAD sha>?skill=<skill dir name>
//
// It returns "" when the skill is not inside a git checkout, the checkout has
// no github.com origin remote, or the HEAD commit cannot be resolved. A
// coordinate is never guessed: an empty purl means provenance is unknown.
func skillPURL(afs *afero.Afero, sourcePath string) string {
	if sourcePath == "" {
		return ""
	}
	skillDir := filepath.Dir(sourcePath)
	root, gitPath, ok := findGitPath(afs, skillDir)
	if !ok {
		return ""
	}

	commonDir, worktreeDir := resolveGitDirs(afs, root, gitPath)
	origin := parseGitRemotes(afs, filepath.Join(commonDir, "config"))["origin"]
	host, slug := parseGitRemoteURL(origin)
	if host != "github.com" {
		return ""
	}
	org, repo, ok := strings.Cut(slug, "/")
	if !ok || org == "" || repo == "" || strings.Contains(repo, "/") {
		return ""
	}

	sha := resolveGitHeadSha(afs, commonDir, worktreeDir)
	if sha == "" {
		return ""
	}
	// Rendered through the purl encoder rather than concatenated: the skill
	// directory name is an arbitrary name off disk, and a "&", "?" or space in
	// it would otherwise split the qualifier or terminate the purl.
	return purl.NewPackageURL(nil, purl.TypeGithub, repo, sha[:12],
		purl.WithNamespace(org),
		purl.WithQualifiers(map[string]string{"skill": filepath.Base(skillDir)}),
	).String()
}

// resolveGitHeadSha resolves the commit sha HEAD points at using only file
// reads: a detached HEAD carries the sha directly, otherwise the named ref is
// looked up as a loose ref file and then in packed-refs. It returns "" when
// the sha cannot be resolved.
func resolveGitHeadSha(afs *afero.Afero, commonDir, worktreeDir string) string {
	data, err := afs.ReadFile(filepath.Join(worktreeDir, "HEAD"))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, "ref:") {
		// detached HEAD: the commit sha is stored directly
		if isGitCommitSha(line) {
			return line
		}
		return ""
	}
	ref := strings.TrimSpace(strings.TrimPrefix(line, "ref:"))
	if ref == "" {
		return ""
	}

	// Loose ref file: the per-worktree git dir first (worktree-local refs),
	// then the shared common dir.
	dirs := []string{worktreeDir}
	if commonDir != worktreeDir {
		dirs = append(dirs, commonDir)
	}
	for _, dir := range dirs {
		if data, err := afs.ReadFile(filepath.Join(dir, ref)); err == nil {
			if sha := strings.TrimSpace(string(data)); isGitCommitSha(sha) {
				return sha
			}
		}
	}
	return packedRefSha(afs, filepath.Join(commonDir, "packed-refs"), ref)
}

// packedRefSha looks up ref in a git packed-refs file (`<sha> <ref>` lines;
// `#` comment and `^` peel lines are skipped). It returns "" when the ref is
// absent or the file is unreadable.
func packedRefSha(afs *afero.Afero, packedRefsPath, ref string) string {
	data, err := afs.ReadFile(packedRefsPath)
	if err != nil {
		return ""
	}
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		sha, name, ok := strings.Cut(line, " ")
		if ok && strings.TrimSpace(name) == ref && isGitCommitSha(sha) {
			return sha
		}
	}
	return ""
}

// isGitCommitSha reports whether s is a full hex commit id (40 characters for
// SHA-1 repositories, 64 for SHA-256 repositories).
func isGitCommitSha(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// vscodeUserDataDir returns the platform-specific User data directory of a
// VS Code-family editor (appName, e.g. "Cursor" or "Windsurf") under a given
// user home. This is where opened-workspace history lives, distinct from the
// agent config dir the editor's resource resolves as configPath.
func vscodeUserDataDir(home, osFamily, appName string) string {
	switch osFamily {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", appName, "User")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", appName, "User")
	default: // linux and other unix-likes
		return filepath.Join(home, ".config", appName, "User")
	}
}

// vscodeWorkspaceFolders returns the deduplicated on-disk folder paths a
// VS Code-family editor (appName) has opened, gathered across every user on the
// target. It reads each opened workspace's folder URI from
// User/workspaceStorage/<hash>/workspace.json and the recent backup folders
// from User/globalStorage/storage.json, stripping the file:// scheme.
// Multi-root workspaces (a `workspace` key pointing at a .code-workspace file)
// are not expanded. Unreadable stores are skipped.
func vscodeWorkspaceFolders(runtime *plugin.Runtime, appName string) []string {
	conn := runtime.Connection.(shared.Connection)
	osFamily := targetOSFamily(conn)
	afs := connectionAfs(runtime)

	users, err := targetUserHomes(runtime)
	if err != nil {
		log.Debug().Err(err).Msg("cannot enumerate users for editor workspaces")
		return nil
	}

	seen := map[string]struct{}{}
	var folders []string
	add := func(uri string) {
		p := fileURIToPath(uri)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		folders = append(folders, p)
	}

	for _, u := range users {
		userDir := vscodeUserDataDir(u.home, osFamily, appName)

		// Per-workspace opened-folder records.
		subdirs, err := listSubdirsAfero(afs, filepath.Join(userDir, "workspaceStorage"))
		if err == nil {
			for _, d := range subdirs {
				var ws struct {
					Folder string `json:"folder"`
				}
				if err := readJSONFileAfero(afs, d.path, "workspace.json", &ws); err == nil {
					add(ws.Folder)
				}
			}
		}

		// Recently-open backup folders.
		var storage struct {
			BackupWorkspaces struct {
				Folders []struct {
					FolderURI string `json:"folderUri"`
				} `json:"folders"`
			} `json:"backupWorkspaces"`
		}
		if err := readJSONFileAfero(afs, filepath.Join(userDir, "globalStorage"), "storage.json", &storage); err == nil {
			for _, f := range storage.BackupWorkspaces.Folders {
				add(f.FolderURI)
			}
		}
	}
	return folders
}

// fileURIToPath converts a file:// URI to a local filesystem path, decoding
// percent-escapes. Non-file URIs and empty strings return "". On Windows the
// leading slash before a drive letter (for example /C:/…) is stripped.
func fileURIToPath(uri string) string {
	if !strings.HasPrefix(uri, "file://") {
		return ""
	}
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	p := u.Path
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return p
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sshclient parses OpenSSH client configuration (ssh_config) and
// known_hosts files.
package sshclient

import (
	"errors"
	"path"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/sshd"
)

// Block is a Host or Match block of an ssh_config, or the settings before
// the first block (Kind "").
type Block struct {
	// Kind is "Host", "Match", or "" for settings outside any block.
	Kind string
	// Criteria is the block's argument as written, for example
	// "bastion *.internal" or "host prod exec \"test -f x\"".
	Criteria string
	// Patterns are the host patterns of a Host block.
	Patterns []string
	// Params maps a lowercase keyword to its first value: ssh uses the
	// first value it reads for a setting.
	Params map[string]string
	Path   string
	Line   int
	Range  llx.Range
}

// Config is a parsed client configuration.
type Config struct {
	// Blocks in the order ssh reads them, includes expanded in place.
	Blocks []*Block
	// Files read, the configuration first.
	Files []string
}

type (
	// ContentFunc reads a file.
	ContentFunc func(path string) (string, error)
	// GlobFunc expands an Include pattern to the files it names.
	GlobFunc func(pattern string) ([]string, error)
)

const maxIncludeDepth = 16

// Parse reads the configuration at root and the files it includes. Relative
// Include paths resolve against the directory of the configuration, which is
// ~/.ssh for a user's file and /etc/ssh for the system one, as ssh does; a
// leading ~/ resolves against home, when known.
func Parse(root string, home string, content ContentFunc, glob GlobFunc) (*Config, error) {
	cfg := &Config{}
	win := IsWindowsPath(root)
	p := &parser{cfg: cfg, base: dirOf(root, win), home: home, win: win, content: content, glob: glob, seen: map[string]bool{}}
	p.cur = &Block{Params: map[string]string{}, Path: root, Line: 1, Range: llx.NewRange()}
	cfg.Blocks = append(cfg.Blocks, p.cur)
	if err := p.file(root, 0); err != nil {
		return nil, err
	}
	return cfg, nil
}

type parser struct {
	cfg  *Config
	cur  *Block
	base string
	home string
	// The configuration is on a Windows target: paths use backslashes and drive letters.
	win     bool
	content ContentFunc
	glob    GlobFunc
	seen    map[string]bool
}

func (p *parser) file(file string, depth int) error {
	if depth > maxIncludeDepth {
		return errors.New("ssh_config: Include nested too deeply in " + file)
	}
	if !p.seen[file] {
		p.cfg.Files = append(p.cfg.Files, file)
	}
	p.seen[file] = true

	text, err := p.content(file)
	if err != nil {
		return err
	}
	for i, raw := range strings.Split(text, "\n") {
		l, err := sshd.ParseLine([]rune(strings.TrimRight(raw, "\r")))
		if err != nil {
			// One unreadable line must not hide the rest of the file.
			continue
		}
		key, args := l.Key(), l.Args()
		if key == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "host", "match":
			kind := "Host"
			if strings.EqualFold(key, "match") {
				kind = "Match"
			}
			b := &Block{Kind: kind, Criteria: args, Params: map[string]string{}, Path: file, Line: i + 1, Range: llx.NewRange().AddLineRange(uint32(i+1), uint32(i+1))}
			if kind == "Host" {
				b.Patterns = strings.Fields(args)
			}
			p.cur = b
			p.cfg.Blocks = append(p.cfg.Blocks, b)
		case "include":
			// An included file's lines continue the current block, as ssh reads them.
			for _, pattern := range strings.Fields(args) {
				matches, err := p.glob(p.resolve(pattern))
				if err != nil {
					return err
				}
				for _, m := range matches {
					if p.seen[m] {
						continue
					}
					if err := p.file(m, depth+1); err != nil {
						return err
					}
				}
			}
		default:
			k := strings.ToLower(key)
			if _, ok := p.cur.Params[k]; !ok {
				p.cur.Params[k] = args
			}
			if p.cur.Path == file {
				p.cur.Range = p.cur.Range.AddLineRange(uint32(i+1), uint32(i+1))
			}
		}
	}
	return nil
}

func (p *parser) resolve(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "~/") && p.home != "":
		return joinPath(p.win, p.home, pattern[2:])
	case p.win && IsWindowsPath(pattern), !p.win && path.IsAbs(pattern):
		return pattern
	default:
		return joinPath(p.win, p.base, pattern)
	}
}

// IsWindowsPath reports whether p is a Windows path: a drive letter (C:\, C:/)
// or a UNC path. The target's paths decide this, not the scanner's OS: a
// Windows host scanned from Linux still has Windows paths.
func IsWindowsPath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return strings.HasPrefix(p, `\\`)
}

func dirOf(p string, win bool) string {
	if !win {
		return path.Dir(p)
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return p
}

func joinPath(win bool, base, rel string) string {
	if !win {
		return path.Join(base, rel)
	}
	return strings.TrimRight(base, `\/`) + `\` + strings.ReplaceAll(strings.TrimLeft(rel, `\/`), "/", `\`)
}

// HomeOf returns the home directory of a user's configuration in <home>/.ssh,
// so an Include of ~/... resolves; empty for any other configuration, such as
// the system-wide one.
func HomeOf(configPath string) string {
	win := IsWindowsPath(configPath)
	dir := dirOf(configPath, win)
	base := dir
	if i := strings.LastIndexAny(dir, `\/`); i >= 0 {
		base = dir[i+1:]
	}
	if base != ".ssh" {
		return ""
	}
	return dirOf(dir, win)
}

// LiteralHosts returns the host names Host blocks name without wildcards or
// negation, in file order and without duplicates.
func (c *Config) LiteralHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range c.Blocks {
		for _, h := range b.Patterns {
			if h == "" || strings.ContainsAny(h, "*?!") || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// Global returns the settings outside any block.
func (c *Config) Global() map[string]string {
	if len(c.Blocks) == 0 || c.Blocks[0].Kind != "" {
		return map[string]string{}
	}
	return c.Blocks[0].Params
}

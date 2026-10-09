// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package frr parses FRRouting configuration files (frr.conf, vtysh.conf).
//
// The grammar is line-oriented and block-structured:
//
//   - A block starts with a keyword such as `router bgp <asn> [vrf <name>]`,
//     `vrf <name>`, `interface <name> [vrf <name>]`, `route-map <name>
//     <permit|deny> <seq>`, `bfd` or `pbr-map <name> seq <n>`.
//   - Blocks nest. `address-family <afi> <safi>` lives inside a router block,
//     `vni <id>` lives inside an `address-family l2vpn evpn` block, and
//     `peer`/`profile` live inside `bfd`.
//   - Blocks close with an explicit terminator (`exit`, `exit-vrf`,
//     `exit-address-family`, `exit-vni`, `end`). Many configs written by hand
//     or by templates omit the terminator, so a new block keyword also closes
//     every block that cannot contain it.
//   - `!` and `#` start a comment that runs to end of line. A lone `!` is the
//     conventional separator between blocks.
//   - `no <directive>` negates a directive. The parser strips the `no` and
//     marks the directive negated, so `no bgp ebgp-requires-policy` is stored
//     as name `bgp` with args `[ebgp-requires-policy]` and Negated true.
//
// The parser is lenient. It records problems in Config.Errors instead of
// aborting, so an audit still sees every block it could read.
package frr

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// maxConfigBytes caps the bytes read from a single config file. FRR configs
// on a busy fabric node stay far below this.
const maxConfigBytes = 10 << 20

// Directive is one parsed line inside a block, or at the top level.
type Directive struct {
	// Name is the first token of the line, after a leading `no` is removed.
	Name string
	// Args are the remaining tokens.
	Args []string
	// Negated is true when the line started with `no`.
	Negated bool
	// Line is the 1-based source line.
	Line int
	// File is the source file path.
	File string
	// Raw is the full source line with comments and indentation removed.
	Raw string
}

// Block is a parsed configuration block.
type Block struct {
	// Type is the normalized block keyword, for example "router bgp",
	// "address-family", "vrf", "interface", "route-map", "vni".
	Type string
	// Name is the primary identifier of the block. It is the ASN for a
	// router block, the VRF name for a vrf block, the interface name for an
	// interface block, and the map name for a route-map block.
	Name string
	// Args holds every token after the block keyword, including Name.
	Args []string
	// Directives are the lines directly inside the block. Lines inside a
	// nested block belong to that block instead.
	Directives []Directive
	// Blocks are the nested blocks in source order.
	Blocks []Block
	// File is the source file path.
	File string
	// StartLine is the 1-based line of the block header.
	StartLine int
	// EndLine is the 1-based line of the last line inside the block.
	EndLine int
	// Raw is the raw text of the block including its header line.
	Raw string
}

// ParseError describes a non-fatal problem found while parsing.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e ParseError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// Config is the result of parsing one FRR configuration file.
type Config struct {
	// Blocks holds every top-level block in source order.
	Blocks []Block
	// Directives holds every top-level line that is not inside a block, for
	// example `hostname`, `frr version`, `ip prefix-list` and `ip route`.
	Directives []Directive
	// Files lists the files parsed into this config.
	Files []string
	// Errors collects non-fatal parse problems.
	Errors []ParseError
}

// blockKind groups block types by where they may appear. The parser uses it
// to close blocks that cannot contain the block it just read.
type blockKind int

const (
	kindTop blockKind = iota
	kindAddressFamily
	kindVNI
	kindBFDPeer
	// kindNested is a block that lives inside another block and closes only
	// on its own terminator or when a new top-level block starts. The
	// segment routing tree uses it.
	kindNested
)

// blockTerminators maps an explicit terminator to the block type it closes.
// An empty value means "close the innermost block".
var blockTerminators = map[string]string{
	"exit":                "",
	"exit-vrf":            "vrf",
	"exit-address-family": "address-family",
	"exit-vni":            "vni",
	"exit-vrf-policy":     "vrf-policy",
}

// Parse parses one configuration file. The filename is used for error
// reporting and is stored on every block and directive. The *Config is
// returned even when an error is reported, so lenient callers keep what was
// readable.
func Parse(filename string, r io.Reader) (*Config, error) {
	cfg := &Config{Files: []string{filename}}
	err := parseInto(filename, r, cfg)
	return cfg, err
}

type frame struct {
	block *Block
	kind  blockKind
}

func parseInto(filename string, r io.Reader, cfg *Config) error {
	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var stack []frame
	// rawLines keeps every source line so a block can rebuild its raw text.
	var rawLines []string
	lineNo := 0

	// starts records the source line index where each open block began.
	closeTop := func(endLine int) {
		if len(stack) == 0 {
			return
		}
		top := stack[len(stack)-1]
		top.block.EndLine = endLine
		if top.block.StartLine >= 1 && endLine <= len(rawLines) {
			top.block.Raw = strings.Join(rawLines[top.block.StartLine-1:endLine], "\n")
		}
		stack = stack[:len(stack)-1]
		if len(stack) == 0 {
			cfg.Blocks = append(cfg.Blocks, *top.block)
			return
		}
		parent := stack[len(stack)-1].block
		parent.Blocks = append(parent.Blocks, *top.block)
	}

	closeAll := func(endLine int) {
		for len(stack) > 0 {
			closeTop(endLine)
		}
	}

	// closeUntil pops blocks until the innermost open block can hold a block
	// of the given kind.
	closeUntil := func(kind blockKind, endLine int) {
		switch kind {
		case kindTop:
			closeAll(endLine)
		case kindAddressFamily:
			for len(stack) > 0 && stack[len(stack)-1].kind != kindTop {
				closeTop(endLine)
			}
		case kindVNI, kindBFDPeer:
			for len(stack) > 0 && stack[len(stack)-1].kind != kindAddressFamily &&
				stack[len(stack)-1].kind != kindTop {
				closeTop(endLine)
			}
		case kindNested:
			// A nested block stays inside whatever is open.
		}
	}

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		rawLines = append(rawLines, raw)

		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)

		// `end` closes every open block.
		if fields[0] == "end" {
			closeAll(lineNo)
			continue
		}

		if target, ok := blockTerminators[fields[0]]; ok {
			if len(stack) == 0 {
				cfg.Errors = append(cfg.Errors, ParseError{
					File: filename, Line: lineNo,
					Msg: "block terminator '" + fields[0] + "' outside of a block",
				})
				continue
			}
			if target != "" && stack[len(stack)-1].block.Type != target {
				// A mismatched terminator still closes blocks until it lines
				// up, which keeps a partly hand-edited config usable.
				cfg.Errors = append(cfg.Errors, ParseError{
					File: filename, Line: lineNo,
					Msg: "terminator '" + fields[0] + "' does not match open block '" +
						stack[len(stack)-1].block.Type + "'",
				})
				for len(stack) > 0 && stack[len(stack)-1].block.Type != target {
					closeTop(lineNo - 1)
				}
			}
			if len(stack) > 0 {
				closeTop(lineNo)
			}
			continue
		}

		if bt, name, args, kind, ok := blockHeader(fields, stack); ok {
			closeUntil(kind, lineNo-1)
			blk := &Block{
				Type:      bt,
				Name:      name,
				Args:      args,
				File:      filename,
				StartLine: lineNo,
				EndLine:   lineNo,
			}
			stack = append(stack, frame{block: blk, kind: kind})
			continue
		}

		d := makeDirective(filename, lineNo, line, fields)
		if len(stack) == 0 {
			cfg.Directives = append(cfg.Directives, d)
			continue
		}
		top := stack[len(stack)-1].block
		top.Directives = append(top.Directives, d)
		top.EndLine = lineNo
	}

	closeAll(lineNo)

	if err := scanner.Err(); err != nil {
		cfg.Errors = append(cfg.Errors, ParseError{File: filename, Msg: err.Error()})
		return err
	}
	if len(cfg.Errors) > 0 {
		return errorList(cfg.Errors)
	}
	return nil
}

// blockHeader decides whether fields start a block. It returns the block
// type, its primary name, the header arguments and where the block may nest.
// nestedKeywords are the block keywords of the segment routing tree. They
// only start a block inside another block.
var nestedKeywords = map[string]bool{
	"srv6":           true,
	"locators":       true,
	"locator":        true,
	"traffic-eng":    true,
	"policy":         true,
	"candidate-path": true,
	"segment-list":   true,
}

func blockHeader(fields []string, stack []frame) (string, string, []string, blockKind, bool) {
	// The segment routing tree nests several levels deep, and its keywords
	// mean nothing at the top level.
	if len(stack) > 0 && nestedKeywords[fields[0]] {
		name := ""
		if len(fields) > 1 {
			name = fields[1]
		}
		return fields[0], name, fields[1:], kindNested, true
	}

	switch fields[0] {
	case "address-family":
		if len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		return "address-family", strings.Join(fields[1:], " "), fields[1:], kindAddressFamily, true

	case "vni":
		// `vni <id>` is a block only inside an address-family. Inside a vrf
		// block it is a plain directive that assigns the L3VNI.
		if len(stack) == 0 || stack[len(stack)-1].kind != kindAddressFamily || len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		return "vni", fields[1], fields[1:], kindVNI, true

	case "peer", "profile":
		// bfd sub-blocks.
		if len(stack) == 0 || stack[len(stack)-1].block.Type != "bfd" || len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		return fields[0], fields[1], fields[1:], kindBFDPeer, true

	case "router":
		if len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		// `router bgp 65000 vrf cluster` names the ASN, the vrf stays in Args.
		name := ""
		if len(fields) > 2 {
			name = fields[2]
		}
		return "router " + fields[1], name, fields[2:], kindTop, true

	case "vrf", "interface", "route-map", "pbr-map", "nexthop-group", "rpki":
		if len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		return fields[0], fields[1], fields[1:], kindTop, true

	case "bfd", "segment-routing":
		// These take no name of their own, and they only start a block at
		// the top level. Inside an interface block `bfd` is a directive that
		// enables a session on the link.
		if len(fields) != 1 || len(stack) > 0 {
			return "", "", nil, kindTop, false
		}
		return fields[0], "", nil, kindTop, true

	case "key", "line":
		// `key chain <name>` and `line vty`.
		if len(fields) < 2 {
			return "", "", nil, kindTop, false
		}
		name := ""
		if len(fields) > 2 {
			name = fields[2]
		}
		return fields[0] + " " + fields[1], name, fields[2:], kindTop, true
	}
	return "", "", nil, kindTop, false
}

func makeDirective(file string, line int, raw string, fields []string) Directive {
	d := Directive{Line: line, File: file, Raw: raw}
	if fields[0] == "no" && len(fields) > 1 {
		d.Negated = true
		fields = fields[1:]
	}
	d.Name = fields[0]
	if len(fields) > 1 {
		d.Args = fields[1:]
	}
	return d
}

// stripComment removes a `!` or `#` comment.
//
// A comment marker only starts a comment at the beginning of a line, which
// is what FRR itself accepts. A marker inside a line is part of the command,
// so `description Transit peer! Primary path` keeps its text.
func stripComment(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	return line
}

func errorList(errs []ParseError) error {
	msgs := make([]string, 0, len(errs))
	for i := range errs {
		msgs = append(msgs, errs[i].Error())
	}
	return fmt.Errorf("frr config parse errors: %s", strings.Join(msgs, "; "))
}

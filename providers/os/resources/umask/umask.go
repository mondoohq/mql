// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package umask parses umask values and the statements that set them: the
// umask builtin in shell startup files, and UMASK keys in login.defs and
// /etc/default/login.
package umask

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Mask is a file creation mask: the permission bits removed from new files.
type Mask struct {
	// Bits are the permission bits the mask removes, 0 to 0777. For a relative
	// mask they are the bits it removes whatever the umask was before.
	Bits uint32
	// Relative is set for a symbolic mask that leaves a class unchanged, such
	// as g=rx (u and o keep their bits) or o-w. Bits then holds the least
	// the mask removes.
	Relative bool
}

// String returns the mask in four-digit octal, such as 0027.
func (m Mask) String() string {
	return fmt.Sprintf("%04o", m.Bits)
}

var octalMode = regexp.MustCompile(`^[0-7]{1,4}$`)

// ParseOctal parses an octal umask such as 027 or 0027, as pam_umask and the
// shell's umask builtin read one.
func ParseOctal(s string) (Mask, error) {
	if !octalMode.MatchString(s) {
		return Mask{}, fmt.Errorf("umask %q is not an octal mode", s)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return Mask{}, fmt.Errorf("umask %q is not an octal mode: %w", s, err)
	}
	if v > 0o777 {
		return Mask{}, fmt.Errorf("umask %q is out of range", s)
	}
	return Mask{Bits: uint32(v)}, nil
}

// Parse parses the argument of the shell's umask builtin: an octal mode, or a
// symbolic one such as u=rwx,g=rx,o= that names the permissions new files
// keep, as `umask -S` prints it.
func Parse(s string) (Mask, error) {
	if octalMode.MatchString(s) {
		return ParseOctal(s)
	}
	return parseSymbolic(s)
}

// classes of a symbolic mode, in the order of their octal digits
const (
	classUser = iota
	classGroup
	classOther
)

// parseSymbolic reads a symbolic mode the way bash and dash apply one to the
// current umask. Every class starts unknown; `=` sets it, `-` removes
// permissions (adds them to the mask) and `+` grants them. A class left
// unknown counts with the bits it is known to remove.
func parseSymbolic(s string) (Mask, error) {
	if s == "" {
		return Mask{}, errors.New("empty umask")
	}
	var known [3]bool
	var deny [3]uint32

	for clause := range strings.SplitSeq(s, ",") {
		i := 0
		var who []int
		for ; i < len(clause); i++ {
			switch clause[i] {
			case 'u':
				who = append(who, classUser)
			case 'g':
				who = append(who, classGroup)
			case 'o':
				who = append(who, classOther)
			case 'a':
				who = append(who, classUser, classGroup, classOther)
			default:
				goto ops
			}
		}
	ops:
		if len(who) == 0 {
			who = []int{classUser, classGroup, classOther}
		}
		if i == len(clause) {
			return Mask{}, fmt.Errorf("umask %q has a clause without an operator", s)
		}
		for i < len(clause) {
			op := clause[i]
			if op != '=' && op != '+' && op != '-' {
				return Mask{}, fmt.Errorf("umask %q has an unknown operator %q", s, op)
			}
			i++
			var perms uint32
			for ; i < len(clause) && clause[i] != '=' && clause[i] != '+' && clause[i] != '-'; i++ {
				switch clause[i] {
				case 'r':
					perms |= 4
				case 'w':
					perms |= 2
				case 'x':
					perms |= 1
				default:
					return Mask{}, fmt.Errorf("umask %q has an unknown permission %q", s, clause[i])
				}
			}
			for _, c := range who {
				switch op {
				case '=':
					known[c] = true
					deny[c] = 7 &^ perms
				case '-':
					deny[c] |= perms
				case '+':
					deny[c] &^= perms
				}
			}
		}
	}

	res := Mask{Bits: deny[classUser]<<6 | deny[classGroup]<<3 | deny[classOther]}
	res.Relative = !known[classUser] || !known[classGroup] || !known[classOther]
	return res, nil
}

// Statement is one call of the umask builtin that sets the mask.
type Statement struct {
	// Line is the line number of the statement, counted from 1.
	Line int
	// Value is the mode argument as written, without quotes.
	Value string
	// Conditional is set when the statement may not run every time the file
	// is read: it is inside an if, case, loop or function, in a subshell, or
	// after && or || on its own command line.
	Conditional bool
}

// ParseShell finds the umask statements of a POSIX shell startup file, such
// as /etc/profile. A bare umask, which prints the mask, and one with an
// expanded argument such as $UMASK are listed only when they set it: the
// first is skipped, the second is listed with its argument as written.
func ParseShell(r io.Reader) []Statement {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), math.MaxInt)

	var res []Statement
	var st shellState
	lineNo := 0
	var pending string
	pendingStart := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if pending != "" || strings.HasSuffix(line, "\\") {
			if pending == "" {
				pendingStart = lineNo
			}
			if before, ok := strings.CutSuffix(line, "\\"); ok {
				pending += before + " "
				continue
			}
			line = pending + line
			pending = ""
		} else {
			pendingStart = lineNo
		}
		for _, s := range st.statements(tokenize(line)) {
			s.Line = pendingStart
			res = append(res, s)
		}
	}
	if pending != "" {
		for _, s := range st.statements(tokenize(pending)) {
			s.Line = pendingStart
			res = append(res, s)
		}
	}
	return res
}

// token is a shell word or control operator.
type token struct {
	text string
	// op is set for a control operator: ; & && || | ( ) ;;
	op bool
}

// tokenize splits a line into words and control operators. Quotes, `...`,
// $(...) and ${...} stay inside their word, and a comment ends the line.
func tokenize(line string) []token {
	var res []token
	var word strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			res = append(res, token{text: word.String()})
			word.Reset()
			inWord = false
		}
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && !inWord:
			return res
		case c == '\'':
			inWord = true
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				word.WriteString(line[i+1:])
				i = len(line)
			} else {
				word.WriteString(line[i+1 : i+1+j])
				i += j + 1
			}
		case c == '"' || c == '`':
			inWord = true
			j := i + 1
			for ; j < len(line) && line[j] != c; j++ {
				if line[j] == '\\' && j+1 < len(line) {
					j++
				}
			}
			if c == '"' {
				word.WriteString(line[i+1 : min(j, len(line))])
			} else {
				word.WriteString(line[i:min(j+1, len(line))])
			}
			i = j
		case c == '$' && i+1 < len(line) && (line[i+1] == '(' || line[i+1] == '{'):
			inWord = true
			open, closing := line[i+1], byte(')')
			if open == '{' {
				closing = '}'
			}
			depth := 0
			j := i + 1
			for ; j < len(line); j++ {
				if line[j] == open {
					depth++
				} else if line[j] == closing {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			word.WriteString(line[i:min(j+1, len(line))])
			i = j
		case c == '\\' && i+1 < len(line):
			inWord = true
			word.WriteByte(line[i+1])
			i++
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flush()
			op := string(c)
			if i+1 < len(line) && (c == ';' || c == '&' || c == '|') && line[i+1] == c {
				op += string(c)
				i++
			}
			res = append(res, token{text: op, op: true})
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	flush()
	return res
}

// block is a compound command open across lines.
type block int

const (
	// blockCond is an if, case or loop: the commands in it may not run
	blockCond block = iota
	// blockFunc is a function body, which runs only when called
	blockFunc
	// blockSubshell is ( ... ): a umask set in it does not outlive it
	blockSubshell
	// blockGroup is { ... }, which runs its commands like the file does
	blockGroup
)

// shellState follows the compound commands open across lines.
type shellState struct {
	blocks []block
	// funcPending is set after a function name, until its body opens
	funcPending bool
}

func (st *shellState) conditional() bool {
	for _, b := range st.blocks {
		if b != blockGroup {
			return true
		}
	}
	return false
}

func (st *shellState) push(b block) {
	st.blocks = append(st.blocks, b)
}

// pop closes the innermost block of kind b, and any block opened after it
// that was never closed.
func (st *shellState) pop(b block) {
	for i, v := range slices.Backward(st.blocks) {
		if v == b {
			st.blocks = st.blocks[:i]
			return
		}
	}
}

func (st *shellState) top() (block, bool) {
	if len(st.blocks) == 0 {
		return 0, false
	}
	return st.blocks[len(st.blocks)-1], true
}

// statements walks the tokens of one line and returns its umask statements.
func (st *shellState) statements(toks []token) []Statement {
	var res []Statement
	start := true
	// afterAndOr is set once && or || appeared on this command line
	afterAndOr := false

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.op {
			switch t.text {
			case "&&", "||":
				afterAndOr = true
			case ";", ";;", "&", "|":
				if t.text == ";" || t.text == "&" {
					afterAndOr = false
				}
			case "(":
				// a function definition name() or a subshell
				if i > 0 && !toks[i-1].op && i+1 < len(toks) && toks[i+1].text == ")" {
					st.funcPending = true
					i++
				} else if start {
					st.push(blockSubshell)
				}
			case ")":
				// closes a subshell, or else ends the pattern of a case item
				if b, ok := st.top(); ok && b == blockSubshell {
					st.pop(blockSubshell)
				}
			}
			start = true
			continue
		}
		// the body of `function name {` opens after the name
		if !start && (t.text != "{" || !st.funcPending) {
			continue
		}
		start = false

		switch t.text {
		case "if", "while", "until", "for", "select", "case":
			st.push(blockCond)
			start = t.text != "case" && t.text != "for" && t.text != "select"
		case "fi", "done", "esac":
			st.pop(blockCond)
		case "then", "else", "elif", "do", "!":
			start = true
		case "function":
			st.funcPending = true
		case "{":
			if st.funcPending {
				st.push(blockFunc)
			} else {
				st.push(blockGroup)
			}
			st.funcPending = false
			start = true
		case "}":
			if b, ok := st.top(); ok && (b == blockFunc || b == blockGroup) {
				st.blocks = st.blocks[:len(st.blocks)-1]
			}
		case "command", "builtin":
			start = true
		case "umask":
			var args []string
			for j := i + 1; j < len(toks) && !toks[j].op; j++ {
				args = append(args, toks[j].text)
				i = j
			}
			value := ""
			for k, a := range args {
				if a == "--" {
					if k+1 < len(args) {
						value = args[k+1]
					}
					break
				}
				if strings.HasPrefix(a, "-") && len(a) > 1 && !strings.ContainsAny(a[1:], "=+-") {
					continue
				}
				value = a
				break
			}
			if value != "" {
				res = append(res, Statement{
					Value:       value,
					Conditional: afterAndOr || st.conditional(),
				})
			}
		default:
			// name() on its own, with the body on a later line
			if strings.HasSuffix(t.text, "()") {
				st.funcPending = true
			}
		}
	}
	return res
}

// Assignment is one KEY=value or KEY value line of a configuration file such
// as /etc/default/login.
type Assignment struct {
	// Line is the line number, counted from 1.
	Line  int
	Value string
}

// ParseKey finds the lines of r that set key, as pam_umask reads
// /etc/default/login: the key at the start of the line, followed by = or
// white space, then the value. Comments start with #.
func ParseKey(r io.Reader, key string) []Assignment {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), math.MaxInt)
	var res []Assignment
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, key)
		if !ok || rest == "" || (rest[0] != '=' && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		rest = strings.TrimPrefix(rest, "=")
		rest = strings.TrimSpace(rest)
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}
		rest = strings.Trim(rest, `"'`)
		if rest == "" {
			continue
		}
		res = append(res, Assignment{Line: lineNo, Value: rest})
	}
	return res
}

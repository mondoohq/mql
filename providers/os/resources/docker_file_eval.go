// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
)

// dockerfileVars holds the build variables (ARG and ENV) in scope at one
// instruction. A variable is unknown when its value comes from outside the
// Dockerfile (an ARG without a default, or a value built from one), so the
// value a build would see cannot be told from the file alone.
type dockerfileVars struct {
	vals    map[string]string
	unknown map[string]struct{}
	// fromEnv marks variables set by ENV, which an ARG of the same name does
	// not override
	fromEnv map[string]struct{}
}

var _ shell.EnvGetter = (*dockerfileVars)(nil)

func newDockerfileVars() *dockerfileVars {
	return &dockerfileVars{
		vals:    map[string]string{},
		unknown: map[string]struct{}{},
		fromEnv: map[string]struct{}{},
	}
}

func (v *dockerfileVars) Get(key string) (string, bool) {
	val, ok := v.vals[key]
	return val, ok
}

func (v *dockerfileVars) Keys() []string {
	return slices.Sorted(maps.Keys(v.vals))
}

func (v *dockerfileVars) set(key, val string, known bool) {
	v.vals[key] = val
	if known {
		delete(v.unknown, key)
	} else {
		v.unknown[key] = struct{}{}
	}
}

func (v *dockerfileVars) isKnown(key string) bool {
	_, ok := v.unknown[key]
	return !ok
}

// cloneEnv copies the ENV variables, which carry over into a stage built FROM
// this one. ARGs go out of scope at the end of their stage.
func (v *dockerfileVars) cloneEnv() *dockerfileVars {
	res := newDockerfileVars()
	for k := range v.fromEnv {
		res.vals[k] = v.vals[k]
		res.fromEnv[k] = struct{}{}
		if !v.isKnown(k) {
			res.unknown[k] = struct{}{}
		}
	}
	return res
}

// dockerfileExpansion is a word after variable substitution and quote removal.
type dockerfileExpansion struct {
	// value keeps a reference to a variable without a value as written
	// (`$NAME`), so it shows where the build would substitute
	value string
	// built is what the build produces with the default arguments: a variable
	// without a value expands to the empty string
	built string
	// known is false when the result depends on a variable whose value is
	// not in the Dockerfile
	known bool
}

// dockerfileEval evaluates a Dockerfile's variables the way the BuildKit
// frontend does when it builds it with the default build arguments.
type dockerfileEval struct {
	keep  *shell.Lex
	build *shell.Lex
	// meta are the global ARGs declared before the first FROM
	meta *dockerfileVars
	// stages are the evaluated stages by lowercased stage name
	stages map[string]*dockerfileStageEval
}

// dockerfileStageEval is the state a stage leaves for a stage built FROM it.
type dockerfileStageEval struct {
	vars *dockerfileVars
	// runsAsRoot is the stage's effective user resolution
	runsAsRoot bool
}

func newDockerfileEval(escapeToken rune, metaArgs []instructions.ArgCommand) *dockerfileEval {
	keep := shell.NewLex(escapeToken)
	keep.SkipUnsetEnv = true
	e := &dockerfileEval{
		keep:   keep,
		build:  shell.NewLex(escapeToken),
		meta:   newDockerfileVars(),
		stages: map[string]*dockerfileStageEval{},
	}
	for _, cmd := range metaArgs {
		for _, kv := range cmd.Args {
			// Like BuildKit, a global ARG without a default adds no value (and
			// keeps an earlier one). A stage that redeclares it then finds no
			// value, and whatever reads it is unknown.
			if kv.Value == nil {
				continue
			}
			x, err := e.expand(*kv.Value, e.meta)
			if err != nil {
				e.meta.set(kv.Key, *kv.Value, false)
				continue
			}
			e.meta.set(kv.Key, x.value, x.known)
		}
	}
	return e
}

// expand substitutes variables in word and removes its shell quoting.
func (e *dockerfileEval) expand(word string, vars *dockerfileVars) (dockerfileExpansion, error) {
	kept, err := e.keep.ProcessWordWithMatches(word, vars)
	if err != nil {
		return dockerfileExpansion{}, err
	}
	built, _, err := e.build.ProcessWord(word, vars)
	if err != nil {
		return dockerfileExpansion{}, err
	}
	known := len(kept.Unmatched) == 0
	for k := range kept.Matched {
		if !vars.isKnown(k) {
			known = false
		}
	}
	return dockerfileExpansion{value: kept.Result, built: built, known: known}, nil
}

// expandOrRaw expands word, returning it unchanged when it can't be parsed
// (the build would fail on it).
func (e *dockerfileEval) expandOrRaw(word string, vars *dockerfileVars) string {
	x, err := e.expand(word, vars)
	if err != nil {
		return word
	}
	return x.value
}

// stageEval tracks one stage while its instructions are read in order.
type stageEval struct {
	*dockerfileEval
	vars *dockerfileVars
	// parentRunsAsRoot is the effective user resolution of the stage this one
	// is built FROM; true for an external image, whose USER is not visible
	parentRunsAsRoot bool
}

// startStage resolves the stage's base image with the global ARGs and, when
// it names an earlier stage, starts from that stage's ENV and user.
func (e *dockerfileEval) startStage(stage instructions.Stage) (*stageEval, string, string) {
	baseName := e.expandOrRaw(stage.BaseName, e.meta)
	platform := stage.Platform
	if platform != "" {
		platform = e.expandOrRaw(platform, e.meta)
	}

	s := &stageEval{dockerfileEval: e, vars: newDockerfileVars(), parentRunsAsRoot: true}
	if parent, ok := e.stages[strings.ToLower(baseName)]; ok {
		s.vars = parent.vars.cloneEnv()
		s.parentRunsAsRoot = parent.runsAsRoot
	}
	return s, baseName, platform
}

// finishStage records the stage for later stages built FROM it.
func (e *dockerfileEval) finishStage(stage instructions.Stage, s *stageEval, runsAsRoot bool) {
	if stage.Name == "" {
		return
	}
	e.stages[strings.ToLower(stage.Name)] = &dockerfileStageEval{vars: s.vars, runsAsRoot: runsAsRoot}
}

// env applies an ENV pair and returns its value as the build sets it.
func (s *stageEval) env(kv instructions.KeyValuePair) string {
	x, err := s.expand(kv.Value, s.vars)
	if err != nil {
		s.vars.set(kv.Key, kv.Value, false)
		s.vars.fromEnv[kv.Key] = struct{}{}
		return kv.Value
	}
	s.vars.set(kv.Key, x.value, x.known)
	s.vars.fromEnv[kv.Key] = struct{}{}
	return x.value
}

// arg applies an ARG declaration and returns its default as the build reads
// it, nil when it has none.
func (s *stageEval) arg(kv instructions.KeyValuePairOptional) *string {
	_, isEnv := s.vars.fromEnv[kv.Key]
	if kv.Value == nil {
		// a stage ARG without a value takes the global ARG's default
		if v, ok := s.meta.Get(kv.Key); ok && !isEnv {
			s.vars.set(kv.Key, v, s.meta.isKnown(kv.Key))
		}
		return nil
	}

	x, err := s.expand(*kv.Value, s.vars)
	if err != nil {
		if !isEnv {
			s.vars.set(kv.Key, *kv.Value, false)
		}
		return kv.Value
	}
	if !isEnv {
		s.vars.set(kv.Key, x.value, x.known)
	}
	return &x.value
}

// user expands a USER value. root is true when the user is root or can't be
// resolved from the Dockerfile, in which case the build may well run as root.
func (s *stageEval) user(raw string) (user string, group string, root bool) {
	rawUser, rawGroup := splitUserGroup(raw)
	group = s.expandOrRaw(rawGroup, s.vars)
	x, err := s.expand(rawUser, s.vars)
	if err != nil {
		return rawUser, group, true
	}
	return x.value, group, !x.known || isRootUser(x.built)
}

// splitUserGroup splits a USER value at the first colon that is not inside a
// ${...} substitution, so `${UID:-0}:app` keeps its default.
func splitUserGroup(raw string) (string, string) {
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '{':
			if i > 0 && raw[i-1] == '$' || depth > 0 {
				depth++
			}
		case '}':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return raw[:i], raw[i+1:]
			}
		}
	}
	return raw, ""
}

// label returns a LABEL key without its shell quoting.
func (s *stageEval) labelKey(key string) string {
	return s.expandOrRaw(key, s.vars)
}

type dockerfilePort struct {
	port     int64
	protocol string
}

// expose expands the port specs of an EXPOSE instruction into one entry per
// port, like the image config the build writes.
func (s *stageEval) expose(specs []string) ([]dockerfilePort, error) {
	var res []dockerfilePort
	for _, spec := range specs {
		x, err := s.expand(spec, s.vars)
		if err != nil {
			return nil, errors.New("invalid EXPOSE port " + strconv.Quote(spec) + ": " + err.Error())
		}
		if !x.known {
			return nil, errors.New("EXPOSE port " + strconv.Quote(spec) + " is set from a variable without a value in the Dockerfile")
		}
		words, err := s.build.ProcessWords(spec, s.vars)
		if err != nil {
			return nil, errors.New("invalid EXPOSE port " + strconv.Quote(spec) + ": " + err.Error())
		}
		for _, w := range words {
			ports, err := parseExposePort(w)
			if err != nil {
				return nil, err
			}
			res = append(res, ports...)
		}
	}
	return res, nil
}

// parseExposePort parses `[[ip:]hostPort:]port[-endPort][/protocol]` into one
// entry per container port, following the BuildKit frontend.
func parseExposePort(spec string) ([]dockerfilePort, error) {
	invalid := func(reason string) error {
		return errors.New("invalid EXPOSE port " + strconv.Quote(spec) + ": " + reason)
	}

	// the container port is always the last colon-separated part, after any
	// ip and host port, IPv6 addresses included
	rest := spec
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		rest = rest[i+1:]
	}
	portRange, proto, _ := strings.Cut(rest, "/")
	proto = strings.ToLower(proto)
	switch proto {
	case "":
		proto = "tcp"
	case "tcp", "udp", "sctp":
	default:
		return nil, invalid("unknown protocol " + strconv.Quote(proto))
	}
	if portRange == "" {
		return nil, invalid("no port")
	}

	startStr, endStr, isRange := strings.Cut(portRange, "-")
	start, err := strconv.ParseUint(startStr, 10, 16)
	if err != nil {
		return nil, invalid("port is not a number from 0 to 65535")
	}
	end := start
	if isRange && endStr != startStr {
		end, err = strconv.ParseUint(endStr, 10, 16)
		if err != nil {
			return nil, invalid("port is not a number from 0 to 65535")
		}
		if end < start {
			return nil, invalid("range end is lower than its start")
		}
	}

	res := make([]dockerfilePort, 0, end-start+1)
	for p := start; p <= end; p++ {
		res = append(res, dockerfilePort{port: int64(p), protocol: proto})
	}
	return res, nil
}

// heredocShells are the interpreters whose heredoc input is a script the
// build runs, rather than data.
var heredocShells = map[string]struct{}{
	"sh": {}, "bash": {}, "ash": {}, "dash": {}, "zsh": {}, "ksh": {}, "busybox": {},
}

// runScript returns the script a RUN executes and the argv of each command
// in it. Heredocs follow the BuildKit frontend: a RUN that is only a heredoc
// runs the heredoc body; otherwise the instruction line and the heredoc
// bodies form one shell script, where a heredoc is the input of a command and
// counts as commands only when that command is a shell.
func runScript(cmd *instructions.RunCommand) (script string, argvs [][]string) {
	if len(cmd.Files) == 0 || len(cmd.CmdLine) != 1 || !cmd.PrependShell {
		return strings.Join(cmd.CmdLine, "\n"), cmdLineArgvs(cmd.CmdLine, !cmd.PrependShell)
	}

	line := cmd.CmdLine[0]
	if parser.MustParseHeredoc(line) != nil {
		data := heredocData(cmd.Files[0])
		return data, parseShellCommands(data)
	}

	var b strings.Builder
	b.WriteString(line)
	files := map[string]instructions.ShellInlineFile{}
	for _, f := range cmd.Files {
		b.WriteByte('\n')
		b.WriteString(f.Data)
		b.WriteString(f.Name)
		files[f.Name] = f
	}

	for _, argv := range parseShellCommands(line) {
		var stripped []string
		var input []string
		for _, a := range argv {
			if h := parser.MustParseHeredoc(a); h != nil {
				if f, ok := files[h.Name]; ok {
					input = append(input, heredocData(f))
				}
				continue
			}
			stripped = append(stripped, a)
		}
		if len(stripped) == 0 {
			continue
		}
		argvs = append(argvs, stripped)
		if _, ok := heredocShells[path.Base(stripped[0])]; ok {
			for _, data := range input {
				argvs = append(argvs, parseShellCommands(data)...)
			}
		}
	}
	return b.String(), argvs
}

func heredocData(f instructions.ShellInlineFile) string {
	if f.Chomp {
		return parser.ChompHeredocContent(f.Data)
	}
	return f.Data
}

// cmdLineArgvs returns the commands of a RUN, CMD or ENTRYPOINT line: the argv
// itself in exec form, the parsed shell commands in shell form.
func cmdLineArgvs(cmdLine []string, execForm bool) [][]string {
	if execForm {
		if len(cmdLine) == 0 {
			return nil
		}
		return [][]string{cmdLine}
	}
	return parseShellCommands(strings.Join(cmdLine, " "))
}

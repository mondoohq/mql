// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/spf13/afero"
)

// Claude Code, Gemini CLI and Codex share one hooks layout: an object keyed by
// event name, each event holding a list of matcher groups, each group an
// optional matcher and a list of handlers:
//
//	{"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "..."}]}]}
//
// Settings files carry that object under a "hooks" key; plugin and extension
// hooks files wrap it the same way.

// agentHookGroup is one matcher group of an event.
type agentHookGroup struct {
	Matcher string             `json:"matcher"`
	Hooks   []agentHookHandler `json:"hooks"`
}

// agentHookHandler is one hook handler. Each tool reads the fields it
// documents: Claude Code command, args, url and timeout in seconds; Gemini CLI
// name, description and timeout in milliseconds; Codex command and timeout in
// seconds.
type agentHookHandler struct {
	Type        string   `json:"type"`
	Command     string   `json:"command"`
	Args        []string `json:"args"`
	URL         string   `json:"url"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Timeout     *float64 `json:"timeout"`
}

// agentHook is one handler together with the event and matcher it is
// registered under and its position in the file, which keeps ids unique.
type agentHook struct {
	event   string
	matcher string
	group   int
	index   int
	handler agentHookHandler
}

// timeout returns the handler's timeout, nil when the file does not set one.
func (h agentHook) timeout() *int64 {
	if h.handler.Timeout == nil {
		return nil
	}
	v := int64(math.Round(*h.handler.Timeout))
	return &v
}

// id is the resource id of the hook: resource name, the key of the file (or
// inline block) that declares it, the event, and its group and handler
// positions.
func (h agentHook) id(resource, key string) string {
	return resource + "/" + key + "/" + h.event + "/" + strconv.Itoa(h.group) + "/" + strconv.Itoa(h.index)
}

// parseAgentHookEvents parses an event map. Events are returned sorted by
// name, groups and handlers in file order. A null or absent map has no hooks;
// a map that is not an object, an event that is not a list of groups, or a
// handler that is not an object is malformed and returns an error.
func parseAgentHookEvents(raw json.RawMessage) ([]agentHook, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var events map[string][]agentHookGroup
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, fmt.Errorf("malformed hooks configuration: %w", err)
	}
	names := make([]string, 0, len(events))
	for name := range events {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []agentHook
	for _, name := range names {
		for gi, group := range events[name] {
			for hi, handler := range group.Hooks {
				out = append(out, agentHook{event: name, matcher: group.Matcher, group: gi, index: hi, handler: handler})
			}
		}
	}
	return out, nil
}

// parseAgentHooksDocument parses a settings or hooks file whose event map sits
// under a top-level "hooks" key. decode parses the file format (strict JSON,
// or JSON with comments for Gemini CLI).
func parseAgentHooksDocument(data []byte, decode func([]byte, any) error) ([]agentHook, error) {
	var doc struct {
		Hooks json.RawMessage `json:"hooks"`
	}
	if err := decode(data, &doc); err != nil {
		return nil, err
	}
	return parseAgentHookEvents(doc.Hooks)
}

// readAgentHooksFile reads the hooks of the file at path. A missing file has
// no hooks; a file that cannot be read or parsed returns an error naming it.
func readAgentHooksFile(afs *afero.Afero, path string, decode func([]byte, any) error) ([]agentHook, error) {
	data, err := readBoundedRegularFile(afs, path, maxConfigFileSize)
	if err != nil {
		if isAbsentPath(err) {
			return nil, nil
		}
		return nil, err
	}
	hooks, err := parseAgentHooksDocument(data, decode)
	if err != nil {
		return nil, fmt.Errorf("cannot read hooks from %s: %w", path, err)
	}
	return hooks, nil
}

// agentHookSet is the hooks one file (or one inline block of a manifest)
// declares. key identifies the block in resource ids: the file path, with the
// position appended for an inline block.
type agentHookSet struct {
	source  string
	key     string
	managed bool
	hooks   []agentHook
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

// CommandError is a command the device refused, with the reasons EOS gave.
//
// goeapi reports a failed command as `JSON Error(1000): CLI command 2 of 2
// '<cmd>' failed: could not run command` and drops the JSON-RPC error's data,
// which is where EOS says why: "BGP inactive", "There seem to be no power
// supplies connected.", "% Unavailable command (not supported on this
// hardware platform)". Several of those mean "there is nothing here" rather
// than "the read failed", and only the message tells them apart.
type CommandError struct {
	Command  string
	Messages []string
	Err      error
}

func (e *CommandError) Error() string {
	if len(e.Messages) == 0 {
		return e.Err.Error()
	}
	return fmt.Sprintf("%v: %s", e.Err, strings.Join(e.Messages, "; "))
}

func (e *CommandError) Unwrap() error { return e.Err }

// HasMessage reports whether EOS gave a reason that contains text.
func (e *CommandError) HasMessage(text string) bool {
	for _, m := range e.Messages {
		if strings.Contains(m, text) {
			return true
		}
	}
	return false
}

// refusedWith reports whether err is a command the device refused with a
// reason that contains text.
func refusedWith(err error, text string) bool {
	var cerr *CommandError
	return errors.As(err, &cerr) && cerr.HasMessage(text)
}

// runCommand runs one command and returns its result. It goes through the
// node's connection rather than goeapi's RunCommands or command handles,
// which discard the response, and with it EOS's reasons, whenever the device
// reports an error. A failure is returned as a *CommandError.
func (eos *Eos) runCommand(cmd, encoding string) (map[string]any, error) {
	resp, err := eos.node.GetConnection().Execute([]any{"enable", cmd}, encoding)
	if err != nil {
		cerr := &CommandError{Command: cmd, Err: err}
		if resp != nil && resp.Error != nil {
			cerr.Messages = commandMessages(resp.Error.Data)
		}
		return nil, cerr
	}
	// The first result is the `enable` that precedes every command.
	if resp == nil || len(resp.Result) < 2 {
		return nil, &CommandError{Command: cmd, Err: fmt.Errorf("no result for %q", cmd)}
	}
	return resp.Result[1], nil
}

// runJSON runs a command with JSON output and decodes its result into out.
// The result arrives already parsed into a map, so it is decoded by the json
// struct tags the same way goeapi's command handles decode theirs.
func (eos *Eos) runJSON(cmd string, out any) error {
	res, err := eos.runCommand(cmd, "json")
	if err != nil {
		return err
	}
	return decodeResult(cmd, res, out)
}

// decodeResult decodes one command's parsed JSON result into out.
func decodeResult(cmd string, res map[string]any, out any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: out})
	if err != nil {
		return err
	}
	if err := dec.Decode(res); err != nil {
		return fmt.Errorf("could not decode %q: %w", cmd, err)
	}
	return nil
}

// commandMessages returns the reasons EOS gave in a JSON-RPC error's data: one
// entry per command sent, and the failing command's entry carries `errors`.
// A text-encoded command may carry its reason as `%`-prefixed output instead.
func commandMessages(data any) []string {
	entries, ok := data.([]any)
	if !ok {
		return nil
	}
	res := []string{}
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if errs, ok := m["errors"].([]any); ok {
			for _, x := range errs {
				if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
					res = append(res, strings.TrimSpace(s))
				}
			}
			continue
		}
		if out, ok := m["output"].(string); ok {
			for _, line := range strings.Split(out, "\n") {
				if line = strings.TrimSpace(line); strings.HasPrefix(line, "%") {
					res = append(res, line)
				}
			}
		}
	}
	return res
}

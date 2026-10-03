// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redisdb/connection"
)

func (r *mqlRedisdb) id() (string, error) {
	return "redisdb", nil
}

func redisdbConnection(runtime *plugin.Runtime) *connection.RedisdbConnection {
	return runtime.Connection.(*connection.RedisdbConnection)
}

// isNoPerm reports whether an error is a Redis access-control denial. These are
// treated as "not visible" for privilege-gated fetches; other errors propagate.
func isNoPerm(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "NOPERM") || strings.Contains(msg, "WRONGPASS")
}

// classifyRefusal wraps a Redis access-control denial in the error kind it
// stands for, naming the ACL command the credential lacks. NOPERM is a
// credential that may not run the command; WRONGPASS is one that did not
// authenticate. Any other error is returned unchanged.
func classifyRefusal(err error, permission string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "NOPERM"):
		return llx.Forbidden(err, llx.WithPermissions(permission))
	case strings.Contains(msg, "WRONGPASS"):
		return llx.Unauthenticated(err)
	}
	return err
}

// refusedList is what a list accessor returns when the server refused its
// command. v13 returned an empty list, which let a check over the list pass on
// a server the scanner could not read; with StructuredErrors the refusal is an
// error naming the ACL command the credential lacks (ADR 046).
func refusedList(err error, permission string) ([]any, error) {
	if !plugin.StructuredErrors() {
		return []any{}, nil
	}
	return nil, classifyRefusal(err, permission)
}

// refusedField is the error a field read from a refused command carries. v13
// left such fields null, so with StructuredErrors off it is nil and the field
// stays null; with it on the field errors instead of reading as "not set".
func refusedField(err error, permission string) error {
	if !plugin.StructuredErrors() {
		return nil
	}
	return classifyRefusal(err, permission)
}

func atoiOr(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

// isUnknownCommand reports whether the server does not have the command at all:
// it was renamed or removed with rename-command, or the server mode (Sentinel)
// does not implement it.
func isUnknownCommand(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "ERR unknown command")
}

// configUnavailable is the error the CONFIG GET-derived fields report when the
// server has no CONFIG command. v13 failed the whole instance on it, so it is
// an error in both modes rather than a null. It is not classified: the
// command is neither refused nor inapplicable, the posture just cannot be read
// over a connection.
func configUnavailable(mode string, err error) error {
	if mode == "sentinel" {
		return fmt.Errorf("a Sentinel server does not implement CONFIG GET, so the server configuration cannot be read: %w", err)
	}
	return fmt.Errorf("CONFIG GET is not available on this server (CONFIG renamed or removed with rename-command), so the server configuration cannot be read: %w", err)
}

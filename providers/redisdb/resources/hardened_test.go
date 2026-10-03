// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"testing"
)

// The reply Valkey 9.0 with rename-command CONFIG "" and a Redis 7.2 Sentinel
// both give CONFIG GET *.
var errConfigRenamed = errors.New("ERR unknown command 'config', with args beginning with: 'get' '*' ")

func TestIsUnknownCommand(t *testing.T) {
	if !isUnknownCommand(errConfigRenamed) {
		t.Error("a renamed CONFIG is an unknown command")
	}
	for _, err := range []error{
		errors.New("NOPERM User noconf has no permissions to run the 'config|get' command"),
		errors.New("ERR wrong number of arguments for 'config|get' command"),
		errors.New("dial tcp 192.0.2.1:6379: connect: connection refused"),
		nil,
	} {
		if isUnknownCommand(err) {
			t.Errorf("isUnknownCommand(%v) = true", err)
		}
	}
}

func TestConfigUnavailableFailsOnlyConfigFields(t *testing.T) {
	r := &mqlRedisdbInstance{}
	r.configErr = configUnavailable("standalone", errConfigRenamed)
	r.setConfigFields(map[string]string{}, false)

	if r.ProtectedMode.Error == nil || r.RequirepassSet.Error == nil || r.BindsAllInterfaces.Error == nil || r.Port.Error == nil {
		t.Fatal("a CONFIG-derived field reads null without saying CONFIG is unavailable")
	}
	if !strings.Contains(r.ProtectedMode.Error.Error(), "rename-command") {
		t.Errorf("error = %q, want it to name rename-command", r.ProtectedMode.Error)
	}
	if !errors.Is(r.ProtectedMode.Error, errConfigRenamed) {
		t.Error("the server's reply was not kept")
	}
	if _, err := r.config(); err == nil {
		t.Error("config() = nil error on a server without CONFIG")
	}

	s := configUnavailable("sentinel", errConfigRenamed)
	if !strings.Contains(s.Error(), "Sentinel") {
		t.Errorf("sentinel error = %q, want it to name Sentinel", s)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	redis "github.com/stackitcloud/stackit-sdk-go/services/redis/v2api"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestDictInt pins the number shapes a parameters blob can carry. The blob
// goes through a JSON round-trip (toDict), so every number arrives as a
// float64; a threshold or port read as 0 because the float was rejected
// would fail a check that should have passed.
func TestDictInt(t *testing.T) {
	cases := []struct {
		name   string
		in     any
		want   int64
		wantOk bool
	}{
		{"json float64", float64(80), 80, true},
		{"native int", 5140, 5140, true},
		{"int64", int64(12), 12, true},
		{"numeric string", "514", 514, true},
		{"numeric string with whitespace", " 90 ", 90, true},
		{"fractional float is not a whole number", 80.5, 0, false},
		{"float beyond int64 range is rejected, not wrapped", 1e19, 0, false},
		{"negative float beyond int64 range is rejected", -1e19, 0, false},
		{"non-numeric string", "eighty", 0, false},
		{"bool is not a number", true, 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := dictInt(tc.in)
			if ok != tc.wantOk || got != tc.want {
				t.Fatalf("dictInt(%v) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.wantOk)
			}
		})
	}
}

// paramsOf runs a JSON parameters payload through the same SDK decode and
// toDict marshal the provider uses, so the accessors are tested against the
// exact dict shape they see at runtime.
func paramsOf(t *testing.T, payload string) *plugin.TValue[any] {
	t.Helper()
	var inst redis.Instance
	if err := json.Unmarshal([]byte(`{"instanceId":"i1","name":"r","cfGuid":"g","cfOrganizationGuid":"o","cfSpaceGuid":"s","dashboardUrl":"","imageUrl":"","offeringName":"redis","offeringVersion":"7","planId":"p","planName":"p","lastOperation":{"type":"create","state":"succeeded","description":""},"parameters":`+payload+`}`), &inst); err != nil {
		t.Fatalf("decoding instance: %v", err)
	}
	return &plugin.TValue[any]{Data: toDict(inst.GetParameters()), State: plugin.StateIsSet}
}

// TestParamAccessors pins the parameter reads behind the hoisted fields:
// present values come through typed, absent ones report "not present" so the
// field reads null rather than a zero or false the API never sent.
func TestParamAccessors(t *testing.T) {
	full := paramsOf(t, `{
		"sgw_acl": "10.0.0.0/8,192.168.1.0/24",
		"syslog": ["syslog.example.test:514"],
		"graphite": "graphite.example.test:2003",
		"enable_monitoring": true,
		"monitoring_instance_id": "obs-1",
		"max_disk_threshold": 80,
		"maxclients": 10000,
		"snapshot": "900 1 300 10",
		"maxmemory-policy": "noeviction",
		"plugins": ["rabbitmq_mqtt", "rabbitmq_tracing"],
		"fluentd-tcp": 5140
	}`)

	t.Run("comma-separated acl becomes a list", func(t *testing.T) {
		got, err := tlsParamList(full, "sgw_acl")
		if err != nil || len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.1.0/24" {
			t.Fatalf("sgw_acl = %v, %v", got, err)
		}
	})

	t.Run("integers survive the json float round-trip", func(t *testing.T) {
		v, ok, err := paramInt(full, "max_disk_threshold")
		if err != nil || !ok || v != 80 {
			t.Fatalf("max_disk_threshold = (%d, %v, %v), want 80", v, ok, err)
		}
		v, ok, _ = paramInt(full, "fluentd-tcp")
		if !ok || v != 5140 {
			t.Fatalf("fluentd-tcp = (%d, %v), want 5140", v, ok)
		}
	})

	t.Run("bool present", func(t *testing.T) {
		v, ok, err := paramBool(full, "enable_monitoring")
		if err != nil || !ok || !v {
			t.Fatalf("enable_monitoring = (%v, %v, %v), want true", v, ok, err)
		}
	})

	t.Run("strings and lists", func(t *testing.T) {
		if s, _ := tlsParamString(full, "snapshot"); s != "900 1 300 10" {
			t.Fatalf("snapshot = %q", s)
		}
		if s, _ := tlsParamString(full, "maxmemory-policy"); s != "noeviction" {
			t.Fatalf("maxmemory-policy = %q", s)
		}
		if s, _ := tlsParamString(full, "monitoring_instance_id"); s != "obs-1" {
			t.Fatalf("monitoring_instance_id = %q", s)
		}
		plugins, _ := tlsParamList(full, "plugins")
		if len(plugins) != 2 || plugins[1] != "rabbitmq_tracing" {
			t.Fatalf("plugins = %v", plugins)
		}
	})

	empty := paramsOf(t, `{}`)

	t.Run("absent keys report not present, not zero", func(t *testing.T) {
		if _, ok, _ := paramInt(empty, "max_disk_threshold"); ok {
			t.Fatal("absent max_disk_threshold must not read as present")
		}
		if _, ok, _ := paramBool(empty, "enable_monitoring"); ok {
			t.Fatal("absent enable_monitoring must not read as present")
		}
		if l, _ := tlsParamList(empty, "sgw_acl"); len(l) != 0 {
			t.Fatalf("absent sgw_acl = %v, want empty", l)
		}
		if s, _ := tlsParamString(empty, "graphite"); s != "" {
			t.Fatalf("absent graphite = %q, want empty", s)
		}
	})

	t.Run("string false is a real false, not absent", func(t *testing.T) {
		v, ok, _ := paramBool(paramsOf(t, `{"enable_monitoring": "false"}`), "enable_monitoring")
		if !ok || v {
			t.Fatalf("enable_monitoring = (%v, %v), want (false, present)", v, ok)
		}
	})
}

// TestCfBrokerInstanceArgs pins the split between the two status-like fields:
// `status` stays the last operation's outcome, `state` is the instance's own
// lifecycle state, and an instance whose response omits its state reads null
// there rather than "".
func TestCfBrokerInstanceArgs(t *testing.T) {
	decode := func(payload string) *redis.Instance {
		var inst redis.Instance
		if err := json.Unmarshal([]byte(payload), &inst); err != nil {
			t.Fatalf("decoding instance: %v", err)
		}
		return &inst
	}
	base := `"instanceId":"i1","name":"cache","cfGuid":"cf-1","cfOrganizationGuid":"o","cfSpaceGuid":"s","dashboardUrl":"","imageUrl":"","offeringName":"redis","offeringVersion":"7","planId":"p","planName":"stackit-redis-1.2.10-single","parameters":{}`

	t.Run("stopped instance with a succeeded last operation", func(t *testing.T) {
		inst := decode(`{` + base + `,"status":"stopped","lastOperation":{"type":"update","state":"succeeded","description":"ok"}}`)
		lop := inst.GetLastOperation()
		st, ok := inst.GetStatusOk()
		args := cfBrokerInstanceArgs("eu01", inst, st, ok, &lop)
		if got := args["status"].Value; got != "succeeded" {
			t.Fatalf("status = %v, want succeeded (the last operation's outcome)", got)
		}
		if got := args["state"].Value; got != "stopped" {
			t.Fatalf("state = %v, want stopped", got)
		}
		if got := args["lastOperationType"].Value; got != "update" {
			t.Fatalf("lastOperationType = %v", got)
		}
		if got := args["region"].Value; got != "eu01" {
			t.Fatalf("region = %v", got)
		}
		if got := args["cfGuid"].Value; got != "cf-1" {
			t.Fatalf("cfGuid = %v", got)
		}
	})

	t.Run("absent status reads null, not empty", func(t *testing.T) {
		inst := decode(`{` + base + `,"lastOperation":{"type":"create","state":"in progress","description":""}}`)
		lop := inst.GetLastOperation()
		st, ok := inst.GetStatusOk()
		args := cfBrokerInstanceArgs("eu01", inst, st, ok, &lop)
		if args["state"].Value != nil {
			t.Fatalf("state = %v, want null when the response omits it", args["state"].Value)
		}
	})
}

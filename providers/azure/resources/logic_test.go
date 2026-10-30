// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	logic "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/stretchr/testify/assert"
)

// strPtr returns a pointer to s. Test helper to avoid `&"x"` boilerplate.
//
//go:fix inline
func strPtr(s string) *string { return new(s) }

func TestPolicyHasIpAllowList(t *testing.T) {
	t.Run("nil policy", func(t *testing.T) {
		assert.False(t, policyHasIpAllowList(nil))
	})
	t.Run("empty list", func(t *testing.T) {
		p := &logic.FlowAccessControlConfigurationPolicy{}
		assert.False(t, policyHasIpAllowList(p))
	})
	t.Run("entry with empty range", func(t *testing.T) {
		empty := ""
		p := &logic.FlowAccessControlConfigurationPolicy{
			AllowedCallerIPAddresses: []*logic.IPAddressRange{
				{AddressRange: &empty},
			},
		}
		assert.False(t, policyHasIpAllowList(p))
	})
	t.Run("entry with non-empty range", func(t *testing.T) {
		r := "10.0.0.0/8"
		p := &logic.FlowAccessControlConfigurationPolicy{
			AllowedCallerIPAddresses: []*logic.IPAddressRange{
				{AddressRange: &r},
			},
		}
		assert.True(t, policyHasIpAllowList(p))
	})
	t.Run("nil entry skipped", func(t *testing.T) {
		r := "10.0.0.0/8"
		p := &logic.FlowAccessControlConfigurationPolicy{
			AllowedCallerIPAddresses: []*logic.IPAddressRange{
				nil,
				{AddressRange: &r},
			},
		}
		assert.True(t, policyHasIpAllowList(p))
	})
}

func TestWorkflowParametersToMQL(t *testing.T) {
	t.Run("nil definition returns empty slices", func(t *testing.T) {
		params, secure := workflowParametersToMQL(nil, nil)
		assert.Empty(t, params)
		assert.Empty(t, secure)
	})

	t.Run("plain string parameter without default", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"region": map[string]any{"type": "String"},
			},
		}
		params, secure := workflowParametersToMQL(def, nil)
		assert.Len(t, params, 1)
		entry := params[0].(map[string]any)
		assert.Equal(t, "region", entry["name"])
		assert.Equal(t, "String", entry["type"])
		assert.Equal(t, false, entry["hasDefaultValue"])
		assert.Equal(t, false, entry["isSecure"])
		assert.Empty(t, secure)
	})

	t.Run("secure-string parameter with default value", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"apiKey": map[string]any{"type": "SecureString", "defaultValue": "redacted"},
			},
		}
		params, secure := workflowParametersToMQL(def, nil)
		assert.Len(t, params, 1)
		entry := params[0].(map[string]any)
		assert.Equal(t, "apiKey", entry["name"])
		assert.Equal(t, "SecureString", entry["type"])
		assert.Equal(t, true, entry["hasDefaultValue"])
		assert.Equal(t, true, entry["isSecure"])
		assert.Equal(t, []any{"apiKey"}, secure)
	})

	t.Run("secure-object also flagged as secure", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"creds": map[string]any{"type": "SecureObject"},
			},
		}
		params, secure := workflowParametersToMQL(def, nil)
		assert.Equal(t, true, params[0].(map[string]any)["isSecure"])
		assert.Equal(t, []any{"creds"}, secure)
	})

	t.Run("declaration without type yields blank type", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"empty": map[string]any{},
			},
		}
		params, _ := workflowParametersToMQL(def, nil)
		entry := params[0].(map[string]any)
		assert.Equal(t, "empty", entry["name"])
		assert.Equal(t, "", entry["type"])
		assert.Equal(t, false, entry["isSecure"])
	})

	t.Run("output is sorted by name", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"zeta":  map[string]any{"type": "String"},
				"alpha": map[string]any{"type": "String"},
				"mu":    map[string]any{"type": "String"},
			},
		}
		params, _ := workflowParametersToMQL(def, nil)
		got := []string{
			params[0].(map[string]any)["name"].(string),
			params[1].(map[string]any)["name"].(string),
			params[2].(map[string]any)["name"].(string),
		}
		assert.Equal(t, []string{"alpha", "mu", "zeta"}, got)
	})

	t.Run("runtime values supply default flag when declaration lacks it", func(t *testing.T) {
		def := map[string]any{
			"parameters": map[string]any{
				"$connections": map[string]any{"type": "Object"},
			},
		}
		runtime := map[string]*logic.WorkflowParameter{
			"$connections": {Value: map[string]any{"some": "value"}},
		}
		params, _ := workflowParametersToMQL(def, runtime)
		entry := params[0].(map[string]any)
		assert.Equal(t, "$connections", entry["name"])
		assert.Equal(t, "Object", entry["type"])
		assert.Equal(t, true, entry["hasDefaultValue"])
	})

	t.Run("runtime-only entry (no declaration) still appears", func(t *testing.T) {
		typ := logic.ParameterTypeSecureString
		runtime := map[string]*logic.WorkflowParameter{
			"legacyKey": {Type: &typ, Value: "x"},
		}
		params, secure := workflowParametersToMQL(nil, runtime)
		assert.Len(t, params, 1)
		entry := params[0].(map[string]any)
		assert.Equal(t, "legacyKey", entry["name"])
		assert.Equal(t, "SecureString", entry["type"])
		assert.Equal(t, true, entry["hasDefaultValue"])
		assert.Equal(t, true, entry["isSecure"])
		assert.Equal(t, []any{"legacyKey"}, secure)
	})
}

func TestParseDefinitionMap(t *testing.T) {
	t.Run("non-map input returns empty", func(t *testing.T) {
		assert.Empty(t, parseDefinitionMap(nil, true))
		assert.Empty(t, parseDefinitionMap("string", false))
		assert.Empty(t, parseDefinitionMap([]any{1, 2}, false))
	})

	t.Run("triggers include kind", func(t *testing.T) {
		in := map[string]any{
			"manual": map[string]any{"type": "Request", "kind": "Http"},
		}
		out := parseDefinitionMap(in, true)
		assert.Len(t, out, 1)
		entry := out[0].(map[string]any)
		assert.Equal(t, "manual", entry["name"])
		assert.Equal(t, "Request", entry["type"])
		assert.Equal(t, "Http", entry["kind"])
	})

	t.Run("actions exclude kind", func(t *testing.T) {
		in := map[string]any{
			"send": map[string]any{"type": "ApiConnection", "kind": "ignored"},
		}
		out := parseDefinitionMap(in, false)
		entry := out[0].(map[string]any)
		_, hasKind := entry["kind"]
		assert.False(t, hasKind)
	})

	t.Run("missing kind not added", func(t *testing.T) {
		in := map[string]any{
			"recur": map[string]any{"type": "Recurrence"},
		}
		out := parseDefinitionMap(in, true)
		entry := out[0].(map[string]any)
		_, hasKind := entry["kind"]
		assert.False(t, hasKind)
	})

	t.Run("missing type yields empty string", func(t *testing.T) {
		in := map[string]any{"weird": map[string]any{}}
		out := parseDefinitionMap(in, false)
		assert.Equal(t, "", out[0].(map[string]any)["type"])
	})

	t.Run("output is sorted by name", func(t *testing.T) {
		in := map[string]any{
			"z": map[string]any{"type": "Http"},
			"a": map[string]any{"type": "Http"},
			"m": map[string]any{"type": "Http"},
		}
		out := parseDefinitionMap(in, false)
		got := []string{
			out[0].(map[string]any)["name"].(string),
			out[1].(map[string]any)["name"].(string),
			out[2].(map[string]any)["name"].(string),
		}
		assert.Equal(t, []string{"a", "m", "z"}, got)
	})
}

func TestWorkflowDefinitionToMQL(t *testing.T) {
	t.Run("non-object definition returns empty", func(t *testing.T) {
		t1, a1, c1 := workflowDefinitionToMQL("not an object")
		assert.Empty(t, t1)
		assert.Empty(t, a1)
		assert.Empty(t, c1)
	})

	t.Run("complete definition with connections", func(t *testing.T) {
		def := map[string]any{
			"triggers": map[string]any{
				"manual": map[string]any{"type": "Request"},
			},
			"actions": map[string]any{
				"send_email": map[string]any{"type": "ApiConnection"},
				"compose":    map[string]any{"type": "Compose"},
			},
			"parameters": map[string]any{
				"$connections": map[string]any{
					"value": map[string]any{
						"office365": map[string]any{},
						"sql":       map[string]any{},
					},
				},
			},
		}
		triggers, actions, conns := workflowDefinitionToMQL(def)
		assert.Len(t, triggers, 1)
		assert.Len(t, actions, 2)
		assert.Equal(t, []any{"office365", "sql"}, conns)
	})

	t.Run("missing $connections section yields empty connections", func(t *testing.T) {
		def := map[string]any{
			"triggers": map[string]any{"manual": map[string]any{"type": "Request"}},
		}
		_, _, conns := workflowDefinitionToMQL(def)
		assert.Empty(t, conns)
	})
}

func TestAccessPolicyToDict(t *testing.T) {
	t.Run("nil policy returns empty stable shape", func(t *testing.T) {
		out, err := accessPolicyToDict(nil)
		assert.NoError(t, err)
		assert.Equal(t, []any{}, out["allowedCallerIpAddresses"])
		assert.Equal(t, map[string]any{}, out["openAuthenticationPolicies"])
	})

	t.Run("policy with IP entries flattens AddressRange", func(t *testing.T) {
		p := &logic.FlowAccessControlConfigurationPolicy{
			AllowedCallerIPAddresses: []*logic.IPAddressRange{
				{AddressRange: new("10.0.0.0/8")},
				{AddressRange: new("192.168.0.0/16")},
			},
		}
		out, err := accessPolicyToDict(p)
		assert.NoError(t, err)
		assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, out["allowedCallerIpAddresses"])
	})
}

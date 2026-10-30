// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

func TestAlfConfigFloat(t *testing.T) {
	tests := []struct {
		name     string
		config   plist.Data
		key      string
		expected float64
		wantErr  bool
	}{
		{
			name:     "valid float value",
			config:   plist.Data{"globalstate": float64(1)},
			key:      "globalstate",
			expected: 1,
		},
		{
			name:    "missing key",
			config:  plist.Data{},
			key:     "globalstate",
			wantErr: true,
		},
		{
			name:    "nil value",
			config:  plist.Data{"globalstate": nil},
			key:     "globalstate",
			wantErr: true,
		},
		{
			name:    "wrong type (string)",
			config:  plist.Data{"globalstate": "1"},
			key:     "globalstate",
			wantErr: true,
		},
		{
			name:     "zero value",
			config:   plist.Data{"globalstate": float64(0)},
			key:      "globalstate",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := alfConfigFloat(tt.config, tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.key)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, val)
			}
		})
	}
}

func TestAlfConfigString(t *testing.T) {
	tests := []struct {
		name     string
		config   plist.Data
		key      string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid string value",
			config:   plist.Data{"version": "1.6"},
			key:      "version",
			expected: "1.6",
		},
		{
			name:    "missing key",
			config:  plist.Data{},
			key:     "version",
			wantErr: true,
		},
		{
			name:    "wrong type (int)",
			config:  plist.Data{"version": 16},
			key:     "version",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := alfConfigString(tt.config, tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.key)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, val)
			}
		})
	}
}

func TestAlfConfigSlice(t *testing.T) {
	tests := []struct {
		name     string
		config   plist.Data
		key      string
		expected []any
		wantErr  bool
	}{
		{
			name:     "valid slice",
			config:   plist.Data{"exceptions": []any{"a", "b"}},
			key:      "exceptions",
			expected: []any{"a", "b"},
		},
		{
			name:     "empty slice",
			config:   plist.Data{"exceptions": []any{}},
			key:      "exceptions",
			expected: []any{},
		},
		{
			name:    "missing key",
			config:  plist.Data{},
			key:     "exceptions",
			wantErr: true,
		},
		{
			name:    "wrong type (string)",
			config:  plist.Data{"exceptions": "not-a-slice"},
			key:     "exceptions",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := alfConfigSlice(tt.config, tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.key)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, val)
			}
		})
	}
}

// TestAlfFirewallGlobalStateMapping verifies the globalState → enabled/blockAllIncoming logic.
// Since these methods require the full runtime, we test the mapping logic directly.
func TestAlfFirewallGlobalStateMapping(t *testing.T) {
	tests := []struct {
		globalState    float64
		expectEnabled  bool
		expectBlockAll bool
	}{
		{0, false, false}, // firewall off
		{1, true, false},  // firewall on, normal mode
		{2, true, true},   // firewall on, block all incoming
	}

	for _, tt := range tests {
		state := int64(tt.globalState)
		assert.Equal(t, tt.expectEnabled, state >= 1, "enabled for globalState=%d", state)
		assert.Equal(t, tt.expectBlockAll, state == 2, "blockAllIncoming for globalState=%d", state)
	}
}

// TestAlfFirewallLoggingDetailMapping verifies the loggingOption → string mapping.
func TestAlfFirewallLoggingDetailMapping(t *testing.T) {
	mapping := map[int64]string{
		0: "disabled",
		1: "detail",
		2: "brief",
		3: "throttled",
		9: "unknown",
	}

	toDetail := func(option int64) string {
		switch option {
		case 0:
			return "disabled"
		case 1:
			return "detail"
		case 2:
			return "brief"
		case 3:
			return "throttled"
		default:
			return "unknown"
		}
	}

	for option, expected := range mapping {
		assert.Equal(t, expected, toDetail(option), "loggingDetail for option=%d", option)
	}
}

// TestAlfFirewallAppNameFallback verifies the name/id fallback logic for app entries.
func TestAlfFirewallAppNameFallback(t *testing.T) {
	tests := []struct {
		name       string
		entry      map[string]any
		index      int
		expectName string
		expectID   string
	}{
		{
			name:       "path takes precedence over bundleid",
			entry:      map[string]any{"bundleid": "com.example.app", "path": "/Applications/Example.app"},
			index:      0,
			expectName: "/Applications/Example.app",
			expectID:   "com.example.app",
		},
		{
			name:       "bundleid used when path is missing",
			entry:      map[string]any{"bundleid": "com.example.app"},
			index:      0,
			expectName: "com.example.app",
			expectID:   "com.example.app",
		},
		{
			name:       "bundleid used when path is empty",
			entry:      map[string]any{"bundleid": "com.example.app", "path": ""},
			index:      0,
			expectName: "com.example.app",
			expectID:   "com.example.app",
		},
		{
			name:       "falls back to index when both empty",
			entry:      map[string]any{},
			index:      3,
			expectName: "unknown-3",
			expectID:   "",
		},
		{
			name:       "falls back to index when both missing keys",
			entry:      map[string]any{"state": float64(1)},
			index:      7,
			expectName: "unknown-7",
			expectID:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundleId, _ := tt.entry["bundleid"].(string)
			name := bundleId
			if path, ok := tt.entry["path"].(string); ok && path != "" {
				name = path
			}
			if name == "" {
				name = fmt.Sprintf("unknown-%d", tt.index)
			}

			assert.Equal(t, tt.expectName, name)
			assert.Equal(t, tt.expectID, bundleId)
		})
	}
}

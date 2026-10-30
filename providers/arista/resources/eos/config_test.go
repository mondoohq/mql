// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigParser(t *testing.T) {
	f, err := os.Open("./testdata/config")
	require.NoError(t, err)
	defer f.Close()

	dict := ParseConfig(f)
	assert.NotNil(t, dict)

	data, err := json.Marshal(dict)
	require.NoError(t, err)
	fmt.Printf("%v\n", string(data))

	entry := dict["management telnet"].(map[string]any)
	assert.NotNil(t, entry)

	_, ok := entry["shutdown"]
	assert.True(t, ok)
}

func TestGetSection(t *testing.T) {
	f, err := os.Open("./testdata/config")
	require.NoError(t, err)
	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)

	section := GetSection(bytes.NewReader(data), "cvx service openstack")
	expected := "shutdown\ngrace-period 60\nnetwork type-driver vlan default\nname-resolution interval 21600\n"
	assert.Equal(t, expected, section)

	section = GetSection(bytes.NewReader(data), "management telnet")
	expected = "shutdown\nidle-timeout 0\nsession-limit 20\nsession-limit per-host 20\n"
	assert.Equal(t, expected, section)
}

// A running-config can contain lines indented more than one level deeper than
// the previous line (an indented login/motd banner is the common case). Such a
// jump must not underflow the parser's stack. Both functions previously
// panicked with "slice bounds out of range" on this input.
const deepIndentConfig = `management ssh
   no shutdown
banner login
         welcome to the switch
                  please authenticate
EOF
management telnet
   shutdown
   idle-timeout 0
`

func TestGetSection_DeepIndentDoesNotPanic(t *testing.T) {
	var section string
	assert.NotPanics(t, func() {
		section = GetSection(strings.NewReader(deepIndentConfig), "management telnet")
	})
	// The parser must still recover and read a section that follows the
	// irregularly-indented banner block.
	assert.Equal(t, "shutdown\nidle-timeout 0\n", section)
}

func TestParseConfig_DeepIndentDoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		dict := ParseConfig(strings.NewReader(deepIndentConfig))
		assert.NotNil(t, dict)
	})
}

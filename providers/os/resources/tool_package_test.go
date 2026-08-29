// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOllamaVersion(t *testing.T) {
	// What `ollama --version` prints when no server is reachable, captured from
	// ollama 0.32.14. Both lines go to stdout and the exit status is 0, so the
	// warning is not a failure signal.
	assert.Equal(t, "0.32.14", parseOllamaVersion(
		"Warning: could not connect to a running Ollama instance\nWarning: client version is 0.32.14\n"))

	// What it prints when one is.
	assert.Equal(t, "0.32.14", parseOllamaVersion("ollama version is 0.32.14\n"))

	// With OLLAMA_HOST pointing at another machine both lines appear. The
	// client line is the binary installed here, which is what the package
	// version has to describe; the server line belongs to a different host.
	assert.Equal(t, "0.31.0", parseOllamaVersion(
		"ollama version is 0.32.14\nWarning: client version is 0.31.0\n"))

	for _, in := range []string{"", "\n", "command not found", "ollama version is"} {
		assert.Empty(t, parseOllamaVersion(in), "input %q", in)
	}
}

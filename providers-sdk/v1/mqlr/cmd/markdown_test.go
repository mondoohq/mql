// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
)

func TestSanitizeComments(t *testing.T) {
	comments := []lrcore.CommentToken{
		{Text: ""},
		{Text: "// "},
		{Text: "// normal comment"},
		{Text: "// normal comment | delimiter"},
		{Text: `// normal comment \| pre-escaped delimiter`},
	}
	expected := []string{
		"",
		"",
		"normal comment",
		`normal comment \| delimiter`,
		`normal comment \| pre-escaped delimiter`,
	}

	actual := sanitizeComments(comments)
	assert.ElementsMatch(t, expected, actual)
}

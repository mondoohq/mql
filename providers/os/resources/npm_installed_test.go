// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

func TestTopLevelNodeModules(t *testing.T) {
	pkg := func(name, evidence string) *languages.Package {
		return &languages.Package{
			Name:         name,
			EvidenceList: []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: evidence}},
		}
	}
	const nm = "/usr/local/lib/node_modules"
	all := languages.Packages{
		pkg("semver", nm+"/semver/package.json"),
		pkg("@anthropic-ai/claude-code", nm+"/@anthropic-ai/claude-code/package.json"),
		pkg("yallist", nm+"/semver/node_modules/yallist/package.json"),
		pkg("nested-scoped", nm+"/semver/node_modules/@scope/x/package.json"),
		pkg("elsewhere", "/opt/app/node_modules/elsewhere/package.json"),
		pkg("hidden", nm+"/.cache/package.json"),
		{Name: "no-evidence"},
	}
	names := []string{}
	for _, p := range topLevelNodeModules(nm, all) {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"semver", "@anthropic-ai/claude-code"}, names)
}

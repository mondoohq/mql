// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"helm.sh/helm/v3/pkg/lint"
	"helm.sh/helm/v3/pkg/lint/support"
)

type mqlHelmChartLintResultInternal struct {
	idKey        string
	lintMessages []support.Message
}

// lint runs Helm's built-in lint rules against the chart. Linting needs
// an on-disk chart directory, so it returns null for charts loaded from a
// .tgz archive or reached as vendored subcharts (which carry no path of
// their own).
func (c *mqlHelmChart) lint() (*mqlHelmChartLintResult, error) {
	if c.chartPath == "" {
		c.Lint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if fi, err := os.Stat(c.chartPath); err != nil || !fi.IsDir() {
		c.Lint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	ro := c.renderOptions()
	// Lint with the same overrides used for rendering so values-dependent
	// rules see what would actually be installed. Override-merge failures
	// fall back to linting with no extra values rather than erroring out.
	userVals, err := mergeRenderValues(ro)
	if err != nil {
		userVals = map[string]any{}
	}

	linter := lint.All(c.chartPath, userVals, ro.Namespace, false)
	passed := linter.HighestSeverity < support.ErrorSev

	res, err := CreateResource(c.MqlRuntime, "helm.chart.lintResult", map[string]*llx.RawData{
		"__id":   llx.StringData(c.idKey + "/lint"),
		"passed": llx.BoolData(passed),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlHelmChartLintResult)
	mqlRes.idKey = c.idKey
	mqlRes.lintMessages = linter.Messages
	return mqlRes, nil
}

func (r *mqlHelmChartLintResult) messages() ([]any, error) {
	out := []any{}
	for i, m := range r.lintMessages {
		text := ""
		if m.Err != nil {
			text = m.Err.Error()
		}
		res, err := CreateResource(r.MqlRuntime, "helm.chart.lintMessage", map[string]*llx.RawData{
			"__id":     llx.StringData(r.idKey + "/lint/msg/" + strconv.Itoa(i)),
			"severity": llx.StringData(lintSeverityName(m.Severity)),
			"path":     llx.StringData(m.Path),
			"message":  llx.StringData(text),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func lintSeverityName(sev int) string {
	switch sev {
	case support.InfoSev:
		return "info"
	case support.WarningSev:
		return "warning"
	case support.ErrorSev:
		return "error"
	default:
		return "unknown"
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reporter

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/utils/iox"
)

// CoverageGapsKey is the reserved key under which JSON output lists, per
// query label, the parts of each result that could not be read.
const CoverageGapsKey = "_coverageGaps"

// CodeBundleToJSON converts a code bundle and its results to JSON output
func CodeBundleToJSON(code *llx.CodeBundle, results map[string]*llx.RawResult, out iox.OutputHelper) error {
	var checksums []string
	eps := code.CodeV2.Entrypoints()
	checksums = make([]string, len(eps))
	for i, ref := range eps {
		checksums[i] = code.CodeV2.Checksums[ref]
	}

	// since we iterate over checksums, we run into the situation that this could be a slice
	// eg. mql run k8s --query "platform { name } k8s.pod.name" --json

	_ = out.WriteString("{")

	var gaps [][]byte
	for j, checksum := range checksums {
		result := results[checksum]
		if result == nil {
			llx.JSONerror(errors.New("cannot find result for this query"))
		} else {
			jsonData := result.Data.JSONfield(checksum, code)
			_, _ = out.Write(jsonData)
			if gap := result.Data.CoverageGapsJSONfield(checksum, code); gap != nil {
				gaps = append(gaps, gap)
			}
		}

		if len(checksums) != j+1 {
			_ = out.WriteString(",")
		}
	}

	// Parts of a result that could not be read go beside the values, under one
	// reserved key, so no value changes shape (ADR 046 §8). Complete results
	// write nothing here.
	if len(gaps) != 0 {
		_ = out.WriteString(",\"" + CoverageGapsKey + "\":{")
		for i, gap := range gaps {
			if i != 0 {
				_ = out.WriteString(",")
			}
			_, _ = out.Write(gap)
		}
		_ = out.WriteString("}")
	}

	_ = out.WriteString("}")

	return nil
}

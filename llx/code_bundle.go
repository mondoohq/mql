// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

func (x *CodeBundle) FilterResults(results map[string]*RawResult) map[string]*RawResult {
	filteredResults := map[string]*RawResult{}

	for i := range x.CodeV2.Checksums {
		checksum := x.CodeV2.Checksums[i]

		res := results[checksum]
		if res != nil {
			filteredResults[checksum] = res
		}
	}

	return filteredResults
}

func Results2Assessment(bundle *CodeBundle, results map[string]*RawResult) *Assessment {
	return Results2AssessmentLookupV2(bundle, func(s string) (*RawResult, bool) {
		r := results[s]
		return r, r != nil
	})
}

func ReturnValuesV2(bundle *CodeBundle, f func(s string) (*RawResult, bool)) []*RawResult {
	return bundle.CodeV2.returnValues(bundle, f)
}

// Results2AssessmentLookup creates an assessment for a bundle using a lookup hook to get all results
func Results2AssessmentLookupV2(bundle *CodeBundle, f func(s string) (*RawResult, bool)) *Assessment {
	code := bundle.CodeV2

	if code == nil {
		return nil
	}

	res := Assessment{
		Success:  true,
		Checksum: code.Id,
	}
	res.Success = true

	entrypoints := code.Entrypoints()
	for i := range entrypoints {
		ep := entrypoints[i]
		cur := code.Entrypoint2Assessment(bundle, ep, f)
		if cur == nil {
			continue
		}

		res.Results = append(res.Results, cur)
		if !cur.Success {
			res.Success = false
		}

		res.IsAssertion = res.IsAssertion || cur.IsAssertion
	}

	if !res.IsAssertion {
		return nil
	}

	return &res
}

// CodepointChecksums returns the entrypoint- and datapoint-checksums
func (x *CodeBundle) CodepointChecksums() []string {
	return append(
		x.EntrypointChecksums(),
		x.DatapointChecksums()...)
}

// EntrypointChecksums returns the checksums for all entrypoints
func (x *CodeBundle) EntrypointChecksums() []string {
	checksums := make([]string, len(x.CodeV2.Blocks[0].Entrypoints))
	for i, ref := range x.CodeV2.Blocks[0].Entrypoints {
		checksums[i] = x.CodeV2.Checksums[ref]
	}
	return checksums
}

// DatapointChecksums returns the checksums for all datapoints
func (x *CodeBundle) DatapointChecksums() []string {
	checksums := make([]string, len(x.CodeV2.Blocks[0].Datapoints))
	for i, ref := range x.CodeV2.Blocks[0].Datapoints {
		checksums[i] = x.CodeV2.Checksums[ref]
	}
	return checksums
}

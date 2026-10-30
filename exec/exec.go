// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package exec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec/internal"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
)

// New creates a new MQL executor instance. It allows you to easily run multiple queries against the
// same runtime
func New(runtime llx.Runtime, features mql.Features) *Executor {
	return &Executor{
		runtime:  runtime,
		features: features,
	}
}

type Executor struct {
	runtime  llx.Runtime
	features mql.Features
}

// Exec runs a query with properties against the runtime
func (e *Executor) Exec(query string, props mqlc.PropsHandler) (*llx.RawData, error) {
	return Exec(query, e.runtime, e.features, props)
}

func Exec(query string, runtime llx.Runtime, features mql.Features, props mqlc.PropsHandler) (*llx.RawData, error) {
	return ExecStrict(query, runtime, features, props, false)
}

// ExecStrict is Exec with an explicit ADR 043 strict-mode setting. Exec keeps its
// signature and stays non-strict, which is the right default for a caller that
// has no content declaring otherwise.
func ExecStrict(query string, runtime llx.Runtime, features mql.Features, props mqlc.PropsHandler, strict bool) (*llx.RawData, error) {
	if props == nil {
		props = mqlc.EmptyPropsHandler
	}

	conf := mqlc.NewConfigFrom(runtime, features)
	conf.Strict = strict
	bundle, err := mqlc.Compile(query, props, conf)
	if err != nil {
		return nil, errors.New("failed to compile: " + err.Error())
	}

	var results []*llx.RawResult

	if len(bundle.CodeV2.Entrypoints()) == 0 {
		return llx.NilData, nil
	}

	if !bundle.CodeV2.Blocks[0].SingleValue {
		log.Warn().Str("query", query).Msg("mql> Code must only return one value, but it has many configured. Only returning last result.")
	}

	raw, err := ExecuteCode(runtime, bundle, props.Available(), features)
	if err != nil {
		return nil, err
	}

	results = llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})

	if len(results) > 1 {
		return nil, errors.New("too many results received")
	}

	rawres := results[0]
	res, err := rawres.Data.Dereference(rawres.CodeID, bundle)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func ExecuteCode(runtime llx.Runtime, codeBundle *llx.CodeBundle, props map[string]*llx.Primitive, features mql.Features) (map[string]*llx.RawResult, error) {
	// Content narrowed to a set of asset roots says which assets it is about
	// (ADR 031). Running it against an asset outside that set produces answers
	// about a platform the content was never written for - nulls that read as
	// facts - so it is refused with an error the caller can recognize.
	//
	// Only under RootedNamespace, which is the opt-in to this model. Refusing by
	// default would turn "not applicable to this asset" into a hard failure for
	// every caller that does not yet tell the two apart, and no caller does yet:
	// the scanner-side handling that skips such an asset instead of failing the
	// check lives in cnspec and lands with the work that consumes
	// compatible_roots. Until then a caller opts in either by that feature or by
	// asking mqlc.SupportsRoot itself, and v14 execution is unchanged - a
	// mismatched member degrades exactly as it does today.
	if features.IsActive(mql.RootedNamespace) {
		if src, ok := runtime.(llx.AssetRootSource); ok {
			if root := src.AssetRoot(); !mqlc.SupportsRoot(codeBundle, root) {
				return nil, fmt.Errorf("%w: this asset is rooted at %s, the content targets %s",
					mqlc.ErrRootMismatch, root, strings.Join(codeBundle.CompatibleRoots, ", "))
			}
		}
	}

	// Install any downgrade translations this reader needs (ADR 040 part 6).
	//
	// Patch returns the code to execute rather than editing in place, so the
	// bundle stays shareable: one CodeBundle is executed against many assets and
	// queries run in goroutines, and a patched copy is private to this call.
	// A reader that needs no translation gets its own code straight back.
	if len(codeBundle.GetTranslations()) > 0 && runtime.Schema() != nil {
		patched, installed := llx.Patch(codeBundle.CodeV2,
			codeBundle.GetTranslations(), runtime.Schema().AllProviderVersions())
		if len(installed) > 0 {
			log.Debug().Int("count", len(installed)).
				Msg("installed downgrade translations for this provider version")
			// Shallow copy: the patched code is the only thing that differs, and
			// everything reported still keys on the shipped checksums.
			nu := *codeBundle
			nu.CodeV2 = patched
			codeBundle = &nu
		}
	}

	// The reverse direction: a bundle compiled before a field changed shape
	// carries no translation for it, so the reader is the only side that can
	// notice (ADR 040 part 6). Detection only - repairing a drift needs the
	// inverse of the provider's own translation, and until that exists saying
	// so is strictly better than the alternative, which is a wrong answer with
	// no symptom.
	if schema := runtime.Schema(); schema != nil {
		if drift := llx.FindTypeDrift(codeBundle.CodeV2, schema); len(drift) > 0 {
			log.Warn().Msg(llx.ReportTypeDrift(drift))
		}
	}

	builder := internal.NewBuilder()

	builder.AddQuery(codeBundle, nil, props)
	for _, checksum := range internal.CodepointChecksums(codeBundle) {
		builder.CollectDatapoint(checksum)
	}

	resultMap := map[string]*llx.RawResult{}
	collector := &internal.FuncCollector{
		SinkDataFunc: func(results []*llx.RawResult) {
			for _, d := range results {
				resultMap[d.CodeID] = d
			}
		},
	}
	builder.AddDatapointCollector(collector)

	ge, err := builder.Build(runtime.Schema(), runtime, "")
	if err != nil {
		return nil, err
	}

	if err := ge.Execute(); err != nil {
		return nil, err
	}

	return resultMap, nil
}

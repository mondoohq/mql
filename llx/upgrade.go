// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// The other direction: an old bundle meeting a newer reader (ADR 040 part 6).
//
// A bundle compiled before a change carries no translation for it - the
// producer had nothing to say about a future it had not seen. So the reader
// adapts, which it can do because it is the newer side and its own provider
// ships the catalog.
//
// Detection is a type comparison the reader can already make: the writer's type
// is baked into every field chunk by the compiler, and the reader's type is in
// its schema. When they disagree, the bundle was compiled against a different
// shape of that field, and every chunk downstream of it is compiled expecting
// the writer's shape.
//
// This is the failure that has no symptom otherwise. A missing name errors; a
// changed type does not - the field resolves, returns the reader's shape, and
// the query either fails somewhere unrelated ("cannot find function '=='") or
// silently produces a plausible wrong answer.

// TypeDrift is one field whose type differs between the bundle and the reader.
type TypeDrift struct {
	// Ref of the chunk that reads the field.
	Ref uint64
	// Resource and Field name it.
	Resource string
	Field    string
	// Writer is the type the bundle was compiled against, Reader the type this
	// build has.
	Writer types.Type
	Reader types.Type
}

// FindTypeDrift reports every field chunk whose declared type disagrees with the
// reader's schema.
//
// It is the detection half on its own. Repairing a drift needs the inverse of
// the provider's translation for that change, which is why this returns
// findings rather than patching: knowing `[]string` is not `string` says nothing
// about which element to take, and only the provider that made the change can
// say whether there is an answer at all.
func FindTypeDrift(code *CodeV2, schema resources.ResourcesSchema) []TypeDrift {
	if code == nil || schema == nil {
		return nil
	}

	var res []TypeDrift
	for blockIdx, block := range code.Blocks {
		if block == nil {
			continue
		}
		for chunkIdx, chunk := range block.Chunks {
			if chunk == nil || chunk.Call != Chunk_FUNCTION || chunk.Function == nil {
				continue
			}
			if chunk.Function.Binding == 0 || chunk.Id == TranslateChunkID {
				continue
			}

			bound := chunkAt(code, chunk.Function.Binding)
			if bound == nil {
				continue
			}
			resource := types.ResourceOf(bound.Type())
			if resource == "" {
				continue
			}

			info, field := schema.LookupField(resource, chunk.Id)
			if info == nil || field == nil || field.Type == "" {
				// A name the reader does not have is a different problem, and
				// the unavailable path already handles it.
				continue
			}

			writer := types.Type(chunk.Function.Type)
			reader := types.Type(field.Type)
			if writer == reader || writer == "" {
				continue
			}

			res = append(res, TypeDrift{
				Ref:      (uint64(blockIdx+1) << 32) | uint64(chunkIdx+1),
				Resource: resource,
				Field:    chunk.Id,
				Writer:   writer,
				Reader:   reader,
			})
		}
	}
	return res
}

// ReportTypeDrift renders the one message a reader should log when a bundle was
// compiled against different shapes than this build has.
//
// It is a warning, not a failure. The drift may be harmless - the reader may
// never touch the drifted field in a way that matters - and refusing to run
// otherwise-good content over it would be worse than the drift. But it must be
// said: this is the only announcement of a condition whose other symptoms are a
// confusing error somewhere unrelated, or a plausible wrong answer.
func ReportTypeDrift(drift []TypeDrift) string {
	if len(drift) == 0 {
		return ""
	}
	var msg strings.Builder
	msg.WriteString("this content was compiled against different field types than this build has;" +
		" affected fields may produce wrong results:")
	for i, d := range drift {
		if i == 3 {
			msg.WriteString(" ... and " + itoa(len(drift)-3) + " more")
			break
		}
		msg.WriteString(" " + d.Resource + "." + d.Field +
			" (compiled as " + d.Writer.Label() + ", this build has " + d.Reader.Label() + ")")
	}
	return msg.String()
}

func itoa(i int) string {
	if i <= 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

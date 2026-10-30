// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenaiBatchInternal struct {
	cacheModel        string
	cacheInputFileID  string
	cacheOutputFileID string
	cacheErrorFileID  string
}

// batchRequestCounts converts the per-outcome request tally. A batch that has
// not been counted yet leaves the object out of the response, and reporting
// zeros for it would claim a batch with no failed requests.
func batchRequestCounts(b openai.Batch) any {
	if !b.JSON.RequestCounts.Valid() {
		return nil
	}
	return map[string]any{
		"total":     b.RequestCounts.Total,
		"completed": b.RequestCounts.Completed,
		"failed":    b.RequestCounts.Failed,
	}
}

// batchMetadata converts the user-defined metadata. The API sends null when a
// batch carries none, which has to stay null rather than becoming an empty map
// that reads as "the metadata was read and it was empty".
func batchMetadata(b openai.Batch) any {
	if !b.JSON.Metadata.Valid() || b.Metadata == nil {
		return nil
	}
	out := make(map[string]any, len(b.Metadata))
	for k, v := range b.Metadata {
		out[k] = v
	}
	return out
}

// mapBatch builds the resource args for an openai.batch. Both the collection
// path and the single-object init share it so the two paths cannot diverge.
// The model and file IDs are cached on the resource separately by the caller
// (see newBatch).
func mapBatch(b openai.Batch) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData(b.ID),
		"id":               llx.StringData(b.ID),
		"endpoint":         llx.StringData(b.Endpoint),
		"status":           llx.StringData(string(b.Status)),
		"completionWindow": llx.StringData(b.CompletionWindow),
		"createdAt":        llx.TimeDataPtr(unixToNullableTime(b.CreatedAt)),
		"inProgressAt":     llx.TimeDataPtr(unixToNullableTime(b.InProgressAt)),
		"finalizingAt":     llx.TimeDataPtr(unixToNullableTime(b.FinalizingAt)),
		"completedAt":      llx.TimeDataPtr(unixToNullableTime(b.CompletedAt)),
		"failedAt":         llx.TimeDataPtr(unixToNullableTime(b.FailedAt)),
		"cancelledAt":      llx.TimeDataPtr(unixToNullableTime(b.CancelledAt)),
		"cancellingAt":     llx.TimeDataPtr(unixToNullableTime(b.CancellingAt)),
		"expiredAt":        llx.TimeDataPtr(unixToNullableTime(b.ExpiredAt)),
		"expiresAt":        llx.TimeDataPtr(unixToNullableTime(b.ExpiresAt)),
		"requestCounts":    llx.DictData(batchRequestCounts(b)),
		"metadata":         llx.DictData(batchMetadata(b)),
	}
}

// newBatch creates the resource and caches the model and file IDs needed by
// the model, inputFile, outputFile, and errorFile accessors.
func newBatch(runtime *plugin.Runtime, b openai.Batch) (*mqlOpenaiBatch, error) {
	res, err := CreateResource(runtime, "openai.batch", mapBatch(b))
	if err != nil {
		return nil, err
	}
	batch := res.(*mqlOpenaiBatch)
	batch.cacheModel = b.Model
	batch.cacheInputFileID = b.InputFileID
	batch.cacheOutputFileID = b.OutputFileID
	batch.cacheErrorFileID = b.ErrorFileID
	return batch, nil
}

func (r *mqlOpenai) batches() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.batches")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Batches.ListAutoPaging(ctx, openai.BatchListParams{}),
		func(b openai.Batch) string { return b.ID },
		func(b openai.Batch) error {
			batch, err := newBatch(r.MqlRuntime, b)
			if err != nil {
				return err
			}
			res = append(res, batch)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list batches: %w", err)
	}
	return res, nil
}

func initOpenaiBatch(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	batchID, ok := idRaw.Value.(string)
	if !ok || batchID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.batch")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch batch %s: no project API key configured", batchID)
	}
	b, err := client.Batches.Get(context.Background(), batchID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get batch %s: %w", batchID, err)
	}
	batch, err := newBatch(runtime, *b)
	if err != nil {
		return nil, nil, err
	}
	return nil, batch, nil
}

// fileRef resolves one of the batch's file references against the account file
// list. A batch keeps the ID of a file that has since been deleted, so a miss
// nulls the field instead of failing the whole collection.
func (r *mqlOpenaiBatch) fileRef(field *plugin.TValue[*mqlOpenaiFile], fileID string) (*mqlOpenaiFile, error) {
	if fileID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	file, err := resolveFile(r.MqlRuntime, fileID)
	if err != nil {
		return nil, err
	}
	if file == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return file, nil
}

func (r *mqlOpenaiBatch) inputFile() (*mqlOpenaiFile, error) {
	return r.fileRef(&r.InputFile, r.cacheInputFileID)
}

func (r *mqlOpenaiBatch) outputFile() (*mqlOpenaiFile, error) {
	return r.fileRef(&r.OutputFile, r.cacheOutputFileID)
}

func (r *mqlOpenaiBatch) errorFile() (*mqlOpenaiFile, error) {
	return r.fileRef(&r.ErrorFile, r.cacheErrorFileID)
}

func (r *mqlOpenaiBatch) model() (*mqlOpenaiModel, error) {
	if r.cacheModel == "" {
		r.Model.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	model, err := resolveModel(r.MqlRuntime, r.cacheModel)
	if err != nil {
		return nil, err
	}
	if model == nil {
		r.Model.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return model, nil
}

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

// mapVectorStore builds the resource args for an openai.vectorStore. Both the
// collection path and the single-object init share it so the two paths cannot
// diverge.
func mapVectorStore(vs openai.VectorStore) map[string]*llx.RawData {
	fileCounts := map[string]any{
		"in_progress": vs.FileCounts.InProgress,
		"completed":   vs.FileCounts.Completed,
		"failed":      vs.FileCounts.Failed,
		"cancelled":   vs.FileCounts.Cancelled,
		"total":       vs.FileCounts.Total,
	}

	var expiresAfter any
	if vs.ExpiresAfter.Days != 0 {
		expiresAfter = map[string]any{
			"anchor": string(vs.ExpiresAfter.Anchor),
			"days":   vs.ExpiresAfter.Days,
		}
	}

	metadata := make(map[string]any)
	for k, v := range vs.Metadata {
		metadata[k] = v
	}

	return map[string]*llx.RawData{
		"__id":         llx.StringData(vs.ID),
		"id":           llx.StringData(vs.ID),
		"name":         llx.StringData(vs.Name),
		"status":       llx.StringData(string(vs.Status)),
		"usageBytes":   llx.IntData(vs.UsageBytes),
		"createdAt":    llx.TimeDataPtr(unixToNullableTime(vs.CreatedAt)),
		"lastActiveAt": llx.TimeDataPtr(unixToNullableTime(vs.LastActiveAt)),
		"fileCounts":   llx.DictData(fileCounts),
		"expiresAfter": llx.DictData(expiresAfter),
		"expiresAt":    llx.TimeDataPtr(unixToNullableTime(vs.ExpiresAt)),
		"metadata":     llx.DictData(metadata),
	}
}

func (r *mqlOpenai) vectorStores() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.vectorStores")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.VectorStores.ListAutoPaging(ctx, openai.VectorStoreListParams{})
	var res []any
	for iter.Next() {
		vs := iter.Current()
		mqlVS, err := CreateResource(r.MqlRuntime, "openai.vectorStore", mapVectorStore(vs))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVS)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list vector stores: %w", err)
	}
	return res, nil
}

func initOpenaiVectorStore(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	vsID, ok := idRaw.Value.(string)
	if !ok || vsID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.vectorStore")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch vector store %s: no project API key configured", vsID)
	}
	vs, err := client.VectorStores.Get(context.Background(), vsID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get vector store %s: %w", vsID, err)
	}
	return mapVectorStore(*vs), nil, nil
}

type mqlOpenaiVectorStoreFileInternal struct {
	cacheFileID string
}

// vectorStoreFileArgs builds the resource args for an openai.vectorStore.file.
// The same uploaded file is attached to several stores, so the membership is
// keyed by store as well as by file while `id` stays the plain file identifier.
func vectorStoreFileArgs(storeID string, f openai.VectorStoreFile) map[string]*llx.RawData {
	// The last error object is absent while a file embedded cleanly. Reporting
	// "" for it would claim a file reported an error code with an empty value.
	var lastErrorCode, lastErrorMessage *string
	if f.JSON.LastError.Valid() && f.LastError.Code != "" {
		lastErrorCode = &f.LastError.Code
		lastErrorMessage = &f.LastError.Message
	}

	var chunkingStrategyType *string
	if f.JSON.ChunkingStrategy.Valid() && f.ChunkingStrategy.Type != "" {
		chunkingStrategyType = &f.ChunkingStrategy.Type
	}

	return map[string]*llx.RawData{
		"__id":                 llx.StringData(storeID + "/" + f.ID),
		"id":                   llx.StringData(f.ID),
		"createdAt":            llx.TimeDataPtr(unixToNullableTime(f.CreatedAt)),
		"status":               llx.StringData(string(f.Status)),
		"usageBytes":           llx.IntData(f.UsageBytes),
		"lastErrorCode":        llx.StringDataPtr(lastErrorCode),
		"lastErrorMessage":     llx.StringDataPtr(lastErrorMessage),
		"chunkingStrategyType": llx.StringDataPtr(chunkingStrategyType),
	}
}

func (r *mqlOpenaiVectorStore) files() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.vectorStore.files")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.VectorStores.Files.ListAutoPaging(ctx, r.Id.Data, openai.VectorStoreFileListParams{}),
		func(f openai.VectorStoreFile) string { return f.ID },
		func(f openai.VectorStoreFile) error {
			mqlFile, err := CreateResource(r.MqlRuntime, "openai.vectorStore.file",
				vectorStoreFileArgs(r.Id.Data, f))
			if err != nil {
				return err
			}
			mqlFile.(*mqlOpenaiVectorStoreFile).cacheFileID = f.ID
			res = append(res, mqlFile)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list files in vector store %s: %w", r.Id.Data, err)
	}
	return res, nil
}

func (r *mqlOpenaiVectorStoreFile) file() (*mqlOpenaiFile, error) {
	if r.cacheFileID == "" {
		r.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	file, err := resolveFile(r.MqlRuntime, r.cacheFileID)
	if err != nil {
		return nil, err
	}
	if file == nil {
		r.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return file, nil
}

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

// mapFile builds the resource args for an openai.file. Both the collection path
// and the single-object init share it so the two paths cannot diverge.
func mapFile(f openai.FileObject) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(f.ID),
		"id":        llx.StringData(f.ID),
		"filename":  llx.StringData(f.Filename),
		"bytes":     llx.IntData(f.Bytes),
		"createdAt": llx.TimeDataPtr(unixToNullableTime(f.CreatedAt)),
		"purpose":   llx.StringData(string(f.Purpose)),
		"status":    llx.StringData(string(f.Status)),
	}
}

func (r *mqlOpenai) files() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.files")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Files.ListAutoPaging(ctx, openai.FileListParams{})
	var res []any
	for iter.Next() {
		f := iter.Current()
		mqlFile, err := CreateResource(r.MqlRuntime, "openai.file", mapFile(f))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list files: %w", err)
	}
	return res, nil
}

func initOpenaiFile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	fileID, ok := idRaw.Value.(string)
	if !ok || fileID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.file")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch file %s: no project API key configured", fileID)
	}
	f, err := client.Files.Get(context.Background(), fileID)
	if err != nil {
		// Returning (args, nil, nil) here would let the runtime build a husk
		// resource from just the id, leaving every other field unset and
		// surfacing as "primitive with no type information" on access. Report
		// the failure instead.
		return nil, nil, fmt.Errorf("failed to get file %s: %w", fileID, err)
	}

	return mapFile(*f), nil, nil
}

// openaiFileList returns the account file collection through the openai
// resource so the underlying list call is made once per scan.
func openaiFileList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	files := obj.(*mqlOpenai).GetFiles()
	if files.Error != nil {
		return nil, files.Error
	}
	return files.Data, nil
}

// resolveFile finds the uploaded file with the given id in the account file
// list. Resolving through the cached list keeps a reference from costing a get
// per referring object. A reference outlives the upload it names (a batch
// keeps its input file id after the file is deleted), so a miss is reported as
// (nil, nil) for the caller to null rather than as an error that would take
// the referring collection down with it.
func resolveFile(runtime *plugin.Runtime, fileID string) (*mqlOpenaiFile, error) {
	files, err := openaiFileList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range files {
		f, ok := files[i].(*mqlOpenaiFile)
		if !ok {
			continue
		}
		if f.Id.Data == fileID {
			return f, nil
		}
	}
	return nil, nil
}

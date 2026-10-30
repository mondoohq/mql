// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
)

// bicepFileContent returns the raw text of the Bicep file at path, using the
// files already loaded by the connection. It never reads from disk, so a
// declaration can only ever reference the source it was parsed from.
func bicepFileContent(runtime *plugin.Runtime, path string) (string, bool) {
	conn, ok := runtime.Connection.(*connection.BicepConnection)
	if !ok {
		return "", false
	}
	for _, f := range conn.BicepFiles() {
		if f.Path == path {
			return f.Content, true
		}
	}
	return "", false
}

// newBicepContext builds a bicep.context spanning [startLine, endLine] in the
// file at path. It returns nil when no position is available (startLine <= 0),
// e.g. for nested resources re-parsed from a parent's body.
func newBicepContext(runtime *plugin.Runtime, path string, startLine, endLine int) (*mqlBicepContext, error) {
	if startLine <= 0 {
		return nil, nil
	}
	if endLine < startLine {
		endLine = startLine
	}
	rnge := llx.NewRange().AddLineRange(uint32(startLine), uint32(endLine))

	content := ""
	if src, ok := bicepFileContent(runtime, path); ok {
		content = rnge.ExtractString(src, llx.DefaultExtractConfig)
	}

	cobj, err := CreateResource(runtime, "bicep.context", map[string]*llx.RawData{
		"path":    llx.StringData(path),
		"range":   llx.RangeData(rnge),
		"content": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}
	return cobj.(*mqlBicepContext), nil
}

// contextArg adds a built context to a resource's creation args when non-nil.
func contextArg(args map[string]*llx.RawData, ctx *mqlBicepContext) {
	if ctx != nil {
		args["context"] = llx.ResourceData(ctx, "bicep.context")
	}
}

func (r *mqlBicepContext) id() (string, error) {
	if r.Path.Data == "" {
		return "", errors.New("need path to exist for bicep.context ID")
	}
	return r.Path.Data + ":" + r.Range.Data.String(), nil
}

func (r *mqlBicepContext) content(path string, rnge llx.Range) (string, error) {
	if path == "" {
		return "", errors.New("no path information for bicep.context")
	}
	src, ok := bicepFileContent(r.MqlRuntime, path)
	if !ok {
		return "", errors.New("missing bicep file content for '" + path + "'")
	}
	return rnge.ExtractString(src, llx.DefaultExtractConfig), nil
}

// context is populated at creation for each declaration, so these fallback
// resolvers only run if a resource was built without one (e.g. a nested
// resource, whose source position is not tracked). Mark the field null rather
// than erroring so a query touching .context resolves to null instead of
// failing.
func (x *mqlBicepParameter) context() (*mqlBicepContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlBicepVariable) context() (*mqlBicepContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlBicepResource) context() (*mqlBicepContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlBicepModule) context() (*mqlBicepContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (x *mqlBicepOutput) context() (*mqlBicepContext, error) {
	x.Context.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

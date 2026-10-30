// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	documentai "cloud.google.com/go/documentai/apiv1"
	"cloud.google.com/go/documentai/apiv1/documentaipb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// documentaiLocations lists the Document AI processing locations. Processors
// are created in one of these two multi-regions.
// See https://docs.cloud.google.com/document-ai/docs/regions
var documentaiLocations = []string{"us", "eu"}

// documentaiEndpoint returns the regional API endpoint for a location.
func documentaiEndpoint(location string) string {
	return fmt.Sprintf("%s-documentai.googleapis.com:443", location)
}

// documentaiLocationFromName extracts the location from a Document AI resource
// name of the form projects/{project}/locations/{location}/....
func documentaiLocationFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProject) documentai() (*mqlGcpProjectDocumentaiService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.documentaiService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDocumentaiService), nil
}

func initGcpProjectDocumentaiService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectDocumentaiService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/documentaiService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectDocumentaiService) listProcessorsInLocation(ctx context.Context, creds *googleoauth.Credentials, projectId, location string) ([]any, error) {
	client, err := documentai.NewDocumentProcessorClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(documentaiEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListProcessors(ctx, &documentaipb.ListProcessorsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location),
	})
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}

		res, err := CreateResource(g.MqlRuntime, "gcp.project.documentaiService.processor", map[string]*llx.RawData{
			"name":            llx.StringData(p.Name),
			"type":            llx.StringData(p.Type),
			"displayName":     llx.StringData(p.DisplayName),
			"state":           llx.StringData(p.State.String()),
			"location":        llx.StringData(location),
			"processEndpoint": llx.StringData(p.ProcessEndpoint),
			"satisfiesPzs":    llx.BoolData(p.SatisfiesPzs),
			"createdAt":       llx.TimeDataPtr(timestampAsTimePtr(p.CreateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlProcessor := res.(*mqlGcpProjectDocumentaiServiceProcessor)
		mqlProcessor.cacheKmsKeyName = p.KmsKeyName
		mqlProcessor.cacheDefaultProcessorVersion = p.DefaultProcessorVersion
		items = append(items, mqlProcessor)
	}
	return items, nil
}

func (g *mqlGcpProjectDocumentaiService) processors() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(documentai.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var items []any
	for _, location := range documentaiLocations {
		locationItems, err := g.listProcessorsInLocation(ctx, creds, projectId, location)
		if err != nil {
			return nil, err
		}
		items = append(items, locationItems...)
	}
	return items, nil
}

func (g *mqlGcpProjectDocumentaiServiceProcessor) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDocumentaiServiceProcessorInternal struct {
	cacheKmsKeyName              string
	cacheDefaultProcessorVersion string
}

func (g *mqlGcpProjectDocumentaiServiceProcessor) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func (g *mqlGcpProjectDocumentaiServiceProcessor) defaultProcessorVersion() (*mqlGcpProjectDocumentaiServiceProcessorVersion, error) {
	return documentaiProcessorVersionRef(g.MqlRuntime, &g.DefaultProcessorVersion, g.cacheDefaultProcessorVersion)
}

func (g *mqlGcpProjectDocumentaiServiceProcessor) versions() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	processorName := g.Name.Data
	location := documentaiLocationFromName(processorName)
	if location == "" {
		return []any{}, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(documentai.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := documentai.NewDocumentProcessorClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(documentaiEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListProcessorVersions(ctx, &documentaipb.ListProcessorVersionsRequest{Parent: processorName})
	for {
		v, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}
		mqlVersion, err := newMqlDocumentaiProcessorVersion(g.MqlRuntime, v)
		if err != nil {
			return nil, err
		}
		items = append(items, mqlVersion)
	}
	return items, nil
}

// newMqlDocumentaiProcessorVersion maps a Document AI ProcessorVersion proto
// into an MQL resource, caching the KMS key and replacement-version names for
// the kmsKey and replacementVersion accessors. Shared by the versions() lister
// and the version init so both paths resolve the same fields.
func newMqlDocumentaiProcessorVersion(runtime *plugin.Runtime, v *documentaipb.ProcessorVersion) (*mqlGcpProjectDocumentaiServiceProcessorVersion, error) {
	deprecated := false
	deprecationTime := llx.TimeDataPtr(nil)
	replacementVersion := ""
	if v.DeprecationInfo != nil {
		deprecated = true
		deprecationTime = llx.TimeDataPtr(timestampAsTimePtr(v.DeprecationInfo.DeprecationTime))
		replacementVersion = v.DeprecationInfo.ReplacementProcessorVersion
	}

	res, err := CreateResource(runtime, "gcp.project.documentaiService.processor.version", map[string]*llx.RawData{
		"name":            llx.StringData(v.Name),
		"displayName":     llx.StringData(v.DisplayName),
		"state":           llx.StringData(v.State.String()),
		"googleManaged":   llx.BoolData(v.GoogleManaged),
		"modelType":       llx.StringData(v.ModelType.String()),
		"deprecated":      llx.BoolData(deprecated),
		"deprecationTime": deprecationTime,
		"createdAt":       llx.TimeDataPtr(timestampAsTimePtr(v.CreateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlVersion := res.(*mqlGcpProjectDocumentaiServiceProcessorVersion)
	mqlVersion.cacheKmsKeyName = v.KmsKeyName
	mqlVersion.cacheReplacementVersion = replacementVersion
	return mqlVersion, nil
}

// initGcpProjectDocumentaiServiceProcessorVersion resolves a processor version
// by resource name when a typed reference points at one that was not part of a
// versions() listing. A missing version returns an error rather than a partially
// populated resource.
func initGcpProjectDocumentaiServiceProcessorVersion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok || nameRaw == nil {
		return nil, nil, errors.New("gcp.project.documentaiService.processor.version requires a name")
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("gcp.project.documentaiService.processor.version requires a name")
	}
	location := documentaiLocationFromName(name)
	if location == "" {
		return nil, nil, fmt.Errorf("cannot determine location from processor version name %q", name)
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	projectId := parseProjectFromPath(name)
	if projectId == "" {
		return nil, nil, fmt.Errorf("cannot determine project from processor version name %q", name)
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_documentai); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Document AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(documentai.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := documentai.NewDocumentProcessorClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(documentaiEndpoint(location)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	v, err := client.GetProcessorVersion(ctx, &documentaipb.GetProcessorVersionRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}
	mqlVersion, err := newMqlDocumentaiProcessorVersion(runtime, v)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlVersion, nil
}

// documentaiProcessorVersionRef resolves a processor-version resource name to a
// typed version resource, or marks the field null when the name is empty.
func documentaiProcessorVersionRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectDocumentaiServiceProcessorVersion], name string) (*mqlGcpProjectDocumentaiServiceProcessorVersion, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.documentaiService.processor.version", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDocumentaiServiceProcessorVersion), nil
}

func (g *mqlGcpProjectDocumentaiServiceProcessorVersion) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDocumentaiServiceProcessorVersionInternal struct {
	cacheKmsKeyName         string
	cacheReplacementVersion string
}

func (g *mqlGcpProjectDocumentaiServiceProcessorVersion) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func (g *mqlGcpProjectDocumentaiServiceProcessorVersion) replacementVersion() (*mqlGcpProjectDocumentaiServiceProcessorVersion, error) {
	return documentaiProcessorVersionRef(g.MqlRuntime, &g.ReplacementVersion, g.cacheReplacementVersion)
}

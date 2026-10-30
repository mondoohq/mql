// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/healthcare/v1"
	"google.golang.org/api/option"
)

func newHealthcareService(conn *connection.GcpConnection) (*healthcare.Service, error) {
	client, err := conn.Client(healthcare.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return healthcare.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProject) healthcare() (*mqlGcpProjectHealthcareService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.healthcareService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectHealthcareService), nil
}

func (g *mqlGcpProjectHealthcareService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/healthcareService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectHealthcareService) datasets() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newHealthcareService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	// The datasets.list API rejects the "-" location wildcard, so enumerate
	// the project's healthcare locations and list datasets in each.
	if err := svc.Projects.Locations.List("projects/"+projectId).Pages(ctx, func(locPage *healthcare.ListLocationsResponse) error {
		for _, loc := range locPage.Locations {
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, loc.LocationId)
			listErr := svc.Projects.Locations.Datasets.List(parent).Pages(ctx, func(page *healthcare.ListDatasetsResponse) error {
				for _, d := range page.Datasets {
					encryptionSpec, err := healthcareConvertEncryptionSpec(d.EncryptionSpec)
					if err != nil {
						return err
					}

					mqlDataset, err := CreateResource(g.MqlRuntime, "gcp.project.healthcareService.dataset", map[string]*llx.RawData{
						"projectId":      llx.StringData(projectId),
						"name":           llx.StringData(d.Name),
						"timeZone":       llx.StringData(d.TimeZone),
						"encryptionSpec": llx.DictData(encryptionSpec),
					})
					if err != nil {
						return err
					}
					if d.EncryptionSpec != nil {
						mqlDataset.(*mqlGcpProjectHealthcareServiceDataset).cacheKmsKeyName = d.EncryptionSpec.KmsKeyName
					}
					res = append(res, mqlDataset)
				}
				return nil
			})
			if listErr != nil {
				if isSkippable(listErr) {
					continue
				}
				return listErr
			}
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

type mqlGcpProjectHealthcareServiceDatasetInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectHealthcareServiceDataset) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectHealthcareServiceDataset) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func (g *mqlGcpProjectHealthcareServiceDataset) dicomStores() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	datasetName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newHealthcareService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Projects.Locations.Datasets.DicomStores.List(datasetName)
	if err := req.Pages(ctx, func(page *healthcare.ListDicomStoresResponse) error {
		for _, s := range page.DicomStores {
			notificationConfig, err := convert.JsonToDict(s.NotificationConfig)
			if err != nil {
				return err
			}

			mqlStore, err := CreateResource(g.MqlRuntime, "gcp.project.healthcareService.dicomStore", map[string]*llx.RawData{
				"projectId":          llx.StringData(projectId),
				"name":               llx.StringData(s.Name),
				"labels":             llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
				"notificationConfig": llx.DictData(notificationConfig),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlStore)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectHealthcareServiceDataset) fhirStores() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	datasetName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newHealthcareService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Projects.Locations.Datasets.FhirStores.List(datasetName)
	if err := req.Pages(ctx, func(page *healthcare.ListFhirStoresResponse) error {
		for _, s := range page.FhirStores {
			mqlStore, err := CreateResource(g.MqlRuntime, "gcp.project.healthcareService.fhirStore", map[string]*llx.RawData{
				"projectId":                       llx.StringData(projectId),
				"name":                            llx.StringData(s.Name),
				"labels":                          llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
				"version":                         llx.StringData(s.Version),
				"disableReferentialIntegrity":     llx.BoolData(s.DisableReferentialIntegrity),
				"enableUpdateCreate":              llx.BoolData(s.EnableUpdateCreate),
				"complexDataTypeReferenceParsing": llx.StringData(s.ComplexDataTypeReferenceParsing),
				"defaultSearchHandlingStrict":     llx.BoolData(s.DefaultSearchHandlingStrict),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlStore)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectHealthcareServiceDataset) hl7v2Stores() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	datasetName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newHealthcareService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Projects.Locations.Datasets.Hl7V2Stores.List(datasetName)
	if err := req.Pages(ctx, func(page *healthcare.ListHl7V2StoresResponse) error {
		for _, s := range page.Hl7V2Stores {
			parserConfig, err := convert.JsonToDict(s.ParserConfig)
			if err != nil {
				return err
			}

			mqlStore, err := CreateResource(g.MqlRuntime, "gcp.project.healthcareService.hl7v2Store", map[string]*llx.RawData{
				"projectId":              llx.StringData(projectId),
				"name":                   llx.StringData(s.Name),
				"labels":                 llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
				"parserConfig":           llx.DictData(parserConfig),
				"rejectDuplicateMessage": llx.BoolData(s.RejectDuplicateMessage),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlStore)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectHealthcareServiceDicomStore) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectHealthcareServiceFhirStore) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectHealthcareServiceHl7v2Store) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func healthcareConvertEncryptionSpec(spec *healthcare.EncryptionSpec) (map[string]any, error) {
	if spec == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		KmsKeyName string `json:"kmsKeyName"`
	}{
		KmsKeyName: spec.KmsKeyName,
	})
}

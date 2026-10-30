// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

type mqlGcpProjectContainerAnalysisServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) containerAnalysis() (*mqlGcpProjectContainerAnalysisService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.containerAnalysisService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_containeranalysis)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectContainerAnalysisService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_containeranalysis).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectContainerAnalysisService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_containeranalysis)
}

func initGcpProjectContainerAnalysisService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectContainerAnalysisService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.containerAnalysisService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectContainerAnalysisServiceOccurrence) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectContainerAnalysisServiceNote) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectContainerAnalysisService) notes() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(containeranalysis.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	grafeasClient := client.GetGrafeasClient()

	it := grafeasClient.ListNotes(ctx, &grafeaspb.ListNotesRequest{
		Parent:   fmt.Sprintf("projects/%s", projectId),
		PageSize: 1000,
	})

	var res []any
	for {
		note, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Container Analysis notes")
				break
			}
			return nil, err
		}

		attestationAuthority, err := protoToDict(note.GetAttestation())
		if err != nil {
			return nil, err
		}
		vulnerability, err := protoToDict(note.GetVulnerability())
		if err != nil {
			return nil, err
		}
		build, err := protoToDict(note.GetBuild())
		if err != nil {
			return nil, err
		}

		relatedNoteNames := make([]any, len(note.RelatedNoteNames))
		for i, n := range note.RelatedNoteNames {
			relatedNoteNames[i] = n
		}

		mqlNote, err := CreateResource(g.MqlRuntime, "gcp.project.containerAnalysisService.note", map[string]*llx.RawData{
			"name":                 llx.StringData(note.Name),
			"shortDescription":     llx.StringData(note.ShortDescription),
			"longDescription":      llx.StringData(note.LongDescription),
			"kind":                 llx.StringData(note.Kind.String()),
			"attestationAuthority": llx.DictData(attestationAuthority),
			"vulnerability":        llx.DictData(vulnerability),
			"build":                llx.DictData(build),
			"relatedNoteNames":     llx.ArrayData(relatedNoteNames, types.String),
			"created":              llx.TimeDataPtr(timestampAsTimePtr(note.CreateTime)),
			"updated":              llx.TimeDataPtr(timestampAsTimePtr(note.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNote)
	}

	return res, nil
}

func (g *mqlGcpProjectContainerAnalysisService) occurrences() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(containeranalysis.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	grafeasClient := client.GetGrafeasClient()

	it := grafeasClient.ListOccurrences(ctx, &grafeaspb.ListOccurrencesRequest{
		Parent:   fmt.Sprintf("projects/%s", projectId),
		PageSize: 1000,
	})

	var res []any
	for {
		occ, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Container Analysis occurrences")
				break
			}
			return nil, err
		}

		var (
			vulnSeverity, vulnEffectiveSeverity       string
			vulnCvssScore                             float64
			vulnFixAvailable                          bool
			vulnShortDescription, vulnLongDescription string
			vulnPackageIssues                         []any
		)
		if v := occ.GetVulnerability(); v != nil {
			// Leave severity empty when unspecified so audits can filter on
			// `vulnerabilitySeverity != ""` without matching the proto zero value.
			if v.Severity != grafeaspb.Severity_SEVERITY_UNSPECIFIED {
				vulnSeverity = v.Severity.String()
			}
			if v.EffectiveSeverity != grafeaspb.Severity_SEVERITY_UNSPECIFIED {
				vulnEffectiveSeverity = v.EffectiveSeverity.String()
			}
			vulnCvssScore = float64(v.CvssScore)
			vulnFixAvailable = v.FixAvailable
			vulnShortDescription = v.ShortDescription
			vulnLongDescription = v.LongDescription
			for _, pi := range v.PackageIssue {
				d, err := protoToDict(pi)
				if err != nil {
					return nil, err
				}
				vulnPackageIssues = append(vulnPackageIssues, d)
			}
		}

		image, err := protoToDict(occ.GetImage())
		if err != nil {
			return nil, err
		}

		packageInfo, err := protoToDict(occ.GetPackage())
		if err != nil {
			return nil, err
		}

		deployment, err := protoToDict(occ.GetDeployment())
		if err != nil {
			return nil, err
		}

		discovery, err := protoToDict(occ.GetDiscovery())
		if err != nil {
			return nil, err
		}

		// Flatten build provenance into scalar fields for direct querying
		// (e.g. occurrences.where(kind == "BUILD").buildCreator).
		var (
			buildProvenanceID, buildCreator             string
			buildLogsURI, buildTriggerID, buildBuilderV string
			buildCreateTime, buildStartTime, buildEnd   *time.Time
			buildArtifacts, buildCommands               []any
		)
		if b := occ.GetBuild(); b != nil && b.Provenance != nil {
			p := b.Provenance
			buildProvenanceID = p.Id
			buildCreator = p.Creator
			buildLogsURI = p.LogsUri
			buildTriggerID = p.TriggerId
			buildBuilderV = p.BuilderVersion
			buildCreateTime = timestampAsTimePtr(p.CreateTime)
			buildStartTime = timestampAsTimePtr(p.StartTime)
			buildEnd = timestampAsTimePtr(p.EndTime)
			for _, a := range p.BuiltArtifacts {
				d, err := protoToDict(a)
				if err != nil {
					return nil, err
				}
				buildArtifacts = append(buildArtifacts, d)
			}
			for _, c := range p.Commands {
				d, err := protoToDict(c)
				if err != nil {
					return nil, err
				}
				buildCommands = append(buildCommands, d)
			}
		}

		// Flatten attestation signatures so audits can inspect the signing
		// public key IDs without decoding the raw dict.
		var attestationSerializedPayload string
		var attestationSignatures []any
		if at := occ.GetAttestation(); at != nil {
			attestationSerializedPayload = base64.StdEncoding.EncodeToString(at.SerializedPayload)
			for _, s := range at.Signatures {
				attestationSignatures = append(attestationSignatures, map[string]any{
					"signature":   base64.StdEncoding.EncodeToString(s.Signature),
					"publicKeyId": s.PublicKeyId,
				})
			}
		}

		mqlOcc, err := CreateResource(g.MqlRuntime, "gcp.project.containerAnalysisService.occurrence", map[string]*llx.RawData{
			"name":                           llx.StringData(occ.Name),
			"resourceUri":                    llx.StringData(occ.ResourceUri),
			"noteName":                       llx.StringData(occ.NoteName),
			"kind":                           llx.StringData(occ.Kind.String()),
			"remediation":                    llx.StringData(occ.Remediation),
			"vulnerabilitySeverity":          llx.StringData(vulnSeverity),
			"vulnerabilityEffectiveSeverity": llx.StringData(vulnEffectiveSeverity),
			"vulnerabilityCvssScore":         llx.FloatData(vulnCvssScore),
			"vulnerabilityFixAvailable":      llx.BoolData(vulnFixAvailable),
			"vulnerabilityShortDescription":  llx.StringData(vulnShortDescription),
			"vulnerabilityLongDescription":   llx.StringData(vulnLongDescription),
			"vulnerabilityPackageIssues":     llx.ArrayData(vulnPackageIssues, types.Dict),
			"buildProvenanceId":              llx.StringData(buildProvenanceID),
			"buildCreator":                   llx.StringData(buildCreator),
			"buildCreateTime":                llx.TimeDataPtr(buildCreateTime),
			"buildStartTime":                 llx.TimeDataPtr(buildStartTime),
			"buildEndTime":                   llx.TimeDataPtr(buildEnd),
			"buildLogsUri":                   llx.StringData(buildLogsURI),
			"buildTriggerId":                 llx.StringData(buildTriggerID),
			"buildBuilderVersion":            llx.StringData(buildBuilderV),
			"buildArtifacts":                 llx.ArrayData(buildArtifacts, types.Dict),
			"buildCommands":                  llx.ArrayData(buildCommands, types.Dict),
			"image":                          llx.DictData(image),
			"packageInfo":                    llx.DictData(packageInfo),
			"deployment":                     llx.DictData(deployment),
			"discovery":                      llx.DictData(discovery),
			"attestationSerializedPayload":   llx.StringData(attestationSerializedPayload),
			"attestationSignatures":          llx.ArrayData(attestationSignatures, types.Dict),
			"created":                        llx.TimeDataPtr(timestampAsTimePtr(occ.CreateTime)),
			"updated":                        llx.TimeDataPtr(timestampAsTimePtr(occ.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlOcc)
	}

	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// extractCaPoolName extracts the CA pool name from a GCP Certificate Authority Service resource path.
// Path format: projects/{project}/locations/{location}/caPools/{caPoolName}/...
// Returns an empty string if the "caPools" segment is not found.
func extractCaPoolName(resourcePath string) string {
	parts := strings.Split(resourcePath, "/")
	for i, p := range parts {
		if p == "caPools" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProject) certificateAuthority() (*mqlGcpProjectCertificateAuthorityService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCertificateAuthorityService), nil
}

func initGcpProjectCertificateAuthorityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectCertificateAuthorityService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/certificateAuthorityService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCertificateAuthorityService) caPools() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListCaPools(ctx, &privatecapb.ListCaPoolsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		pool, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		issuancePolicy, err := protoToDict(pool.IssuancePolicy)
		if err != nil {
			return nil, err
		}
		publishingOptions, err := protoToDict(pool.PublishingOptions)
		if err != nil {
			return nil, err
		}

		var publishCaCert, publishCrl bool
		if pool.PublishingOptions != nil {
			publishCaCert = pool.PublishingOptions.PublishCaCert
			publishCrl = pool.PublishingOptions.PublishCrl
		}

		mqlPool, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService.caPool", map[string]*llx.RawData{
			"projectId":         llx.StringData(projectId),
			"resourcePath":      llx.StringData(pool.Name),
			"name":              llx.StringData(parseResourceName(pool.Name)),
			"location":          llx.StringData(parseLocationFromPath(pool.Name)),
			"tier":              llx.StringData(pool.Tier.String()),
			"issuancePolicy":    llx.DictData(issuancePolicy),
			"publishingOptions": llx.DictData(publishingOptions),
			"publishCaCert":     llx.BoolData(publishCaCert),
			"publishCrl":        llx.BoolData(publishCrl),
			"labels":            llx.MapData(convert.MapToInterfaceMap(pool.Labels), types.String),
		})
		if err != nil {
			return nil, err
		}
		if pool.EncryptionSpec != nil {
			mqlPool.(*mqlGcpProjectCertificateAuthorityServiceCaPool).cacheKmsKeyName = pool.EncryptionSpec.CloudKmsKey
		}
		res = append(res, mqlPool)
	}

	return res, nil
}

type mqlGcpProjectCertificateAuthorityServiceCaPoolInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectCertificateAuthorityServiceCaPool) id() (string, error) {
	if g.ResourcePath.Error != nil {
		return "", g.ResourcePath.Error
	}
	return g.ResourcePath.Data, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCaPool) iamPolicy() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	poolPath := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Request policy schema version 3 so conditional bindings aren't silently
	// stripped from the result.
	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: poolPath,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Warn().Str("caPool", poolPath).Err(err).Msg("could not retrieve CA pool IAM policy")
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, poolPath, policy.Bindings)
}

func (g *mqlGcpProjectCertificateAuthorityServiceCaPool) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCaPool) certificateAuthorities() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	projectId := g.ProjectId.Data
	poolPath := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
		Parent: poolPath,
	})

	var res []any
	for {
		ca, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		keySpec, err := protoToDict(ca.KeySpec)
		if err != nil {
			return nil, err
		}
		config, err := protoToDict(ca.Config)
		if err != nil {
			return nil, err
		}
		subordinateConfig, err := protoToDict(ca.SubordinateConfig)
		if err != nil {
			return nil, err
		}
		accessUrls, err := protoToDict(ca.AccessUrls)
		if err != nil {
			return nil, err
		}

		caPoolName := extractCaPoolName(ca.Name)

		var createdAt *llx.RawData
		if ca.CreateTime != nil {
			createdAt = llx.TimeData(ca.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var updatedAt *llx.RawData
		if ca.UpdateTime != nil {
			updatedAt = llx.TimeData(ca.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		var deletedAt *llx.RawData
		if ca.DeleteTime != nil {
			deletedAt = llx.TimeData(ca.DeleteTime.AsTime())
		} else {
			deletedAt = llx.NilData
		}

		var expireTime *llx.RawData
		if ca.ExpireTime != nil {
			expireTime = llx.TimeData(ca.ExpireTime.AsTime())
		} else {
			expireTime = llx.NilData
		}

		mqlCa, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService.certificateAuthority", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"resourcePath": llx.StringData(ca.Name),
			"name":         llx.StringData(parseResourceName(ca.Name)),
			"location":     llx.StringData(parseLocationFromPath(ca.Name)),
			"caPool":       llx.StringData(caPoolName),
			"type":         llx.StringData(ca.Type.String()),
			"state":        llx.StringData(ca.State.String()),
			"keySpec":      llx.DictData(keySpec),
			"config":       llx.DictData(config),
			// durationToString, not (*durationpb.Duration).String(): the latter
			// renders protobuf TEXT ("seconds:31536000") and "<nil>" when absent.
			"lifetime":          llx.StringData(durationToString(ca.Lifetime)),
			"pemCaCertificates": llx.ArrayData(convert.SliceAnyToInterface(ca.PemCaCertificates), types.String),
			"subordinateConfig": llx.DictData(subordinateConfig),
			"labels":            llx.MapData(convert.MapToInterfaceMap(ca.Labels), types.String),
			"gcsBucket":         llx.StringData(ca.GcsBucket),
			"accessUrls":        llx.DictData(accessUrls),
			"createdAt":         createdAt,
			"updatedAt":         updatedAt,
			"deletedAt":         deletedAt,
			"expireTime":        expireTime,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCa)
	}

	return res, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateAuthority) id() (string, error) {
	if g.ResourcePath.Error != nil {
		return "", g.ResourcePath.Error
	}
	return g.ResourcePath.Data, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateAuthority) expired() (bool, error) {
	return certExpired(g.ExpireTime)
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateAuthority) daysUntilExpiry() (int64, error) {
	return certDaysUntilExpiry(g.ExpireTime)
}

func (g *mqlGcpProjectCertificateAuthorityServiceCaPool) certificates() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	projectId := g.ProjectId.Data
	poolPath := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListCertificates(ctx, &privatecapb.ListCertificatesRequest{
		Parent: poolPath,
	})

	var res []any
	for {
		cert, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		subjectDescription, err := protoToDict(cert.CertificateDescription)
		if err != nil {
			return nil, err
		}
		certConfig, err := protoToDict(cert.GetConfig())
		if err != nil {
			return nil, err
		}
		revocationDetails, err := protoToDict(cert.RevocationDetails)
		if err != nil {
			return nil, err
		}

		caPoolName := extractCaPoolName(cert.Name)

		var createdAt *llx.RawData
		if cert.CreateTime != nil {
			createdAt = llx.TimeData(cert.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var updatedAt *llx.RawData
		if cert.UpdateTime != nil {
			updatedAt = llx.TimeData(cert.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		var requestedNotBeforeTime *llx.RawData
		if cert.RequestedNotBeforeTime != nil {
			requestedNotBeforeTime = llx.TimeData(cert.RequestedNotBeforeTime.AsTime())
		} else {
			requestedNotBeforeTime = llx.NilData
		}

		mqlCert, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService.certificate", map[string]*llx.RawData{
			"projectId":                  llx.StringData(projectId),
			"resourcePath":               llx.StringData(cert.Name),
			"name":                       llx.StringData(parseResourceName(cert.Name)),
			"location":                   llx.StringData(parseLocationFromPath(cert.Name)),
			"caPool":                     llx.StringData(caPoolName),
			"issuerCertificateAuthority": llx.StringData(cert.IssuerCertificateAuthority),
			"lifetime":                   llx.StringData(durationToString(cert.Lifetime)),
			"requestedNotBeforeTime":     requestedNotBeforeTime,
			"subjectDescription":         llx.DictData(subjectDescription),
			"certDescription":            llx.DictData(certConfig),
			"pemCertificate":             llx.StringData(cert.PemCertificate),
			"pemCertificateChain":        llx.ArrayData(convert.SliceAnyToInterface(cert.PemCertificateChain), types.String),
			"revocationDetails":          llx.DictData(revocationDetails),
			"labels":                     llx.MapData(convert.MapToInterfaceMap(cert.Labels), types.String),
			"createdAt":                  createdAt,
			"updatedAt":                  updatedAt,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCert)
	}

	return res, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificate) id() (string, error) {
	if g.ResourcePath.Error != nil {
		return "", g.ResourcePath.Error
	}
	return g.ResourcePath.Data, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateRevocationList) id() (string, error) {
	if g.ResourcePath.Error != nil {
		return "", g.ResourcePath.Error
	}
	return g.ResourcePath.Data, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateAuthority) certificateRevocationLists() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	projectId := g.ProjectId.Data
	caPath := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListCertificateRevocationLists(ctx, &privatecapb.ListCertificateRevocationListsRequest{
		Parent: caPath,
	})

	var res []any
	for {
		crl, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		revoked := make([]any, 0, len(crl.RevokedCertificates))
		for _, rc := range crl.RevokedCertificates {
			revoked = append(revoked, map[string]any{
				"certificate":      rc.Certificate,
				"hexSerialNumber":  rc.HexSerialNumber,
				"revocationReason": rc.RevocationReason.String(),
			})
		}

		mqlCrl, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService.certificateRevocationList", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"resourcePath":        llx.StringData(crl.Name),
			"name":                llx.StringData(parseResourceName(crl.Name)),
			"location":            llx.StringData(parseLocationFromPath(crl.Name)),
			"sequenceNumber":      llx.IntData(crl.SequenceNumber),
			"state":               llx.StringData(crl.State.String()),
			"revisionId":          llx.StringData(crl.RevisionId),
			"accessUrl":           llx.StringData(crl.AccessUrl),
			"pemCrl":              llx.StringData(crl.PemCrl),
			"revokedCertificates": llx.ArrayData(revoked, types.Dict),
			"labels":              llx.MapData(convert.MapToInterfaceMap(crl.Labels), types.String),
			"createdAt":           llx.TimeDataPtr(timestampAsTimePtr(crl.CreateTime)),
			"updatedAt":           llx.TimeDataPtr(timestampAsTimePtr(crl.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCrl)
	}

	return res, nil
}

func (g *mqlGcpProjectCertificateAuthorityServiceCertificateTemplate) id() (string, error) {
	if g.ResourcePath.Error != nil {
		return "", g.ResourcePath.Error
	}
	return g.ResourcePath.Data, nil
}

func (g *mqlGcpProjectCertificateAuthorityService) certificateTemplates() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(privateca.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := privateca.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListCertificateTemplates(ctx, &privatecapb.ListCertificateTemplatesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		tmpl, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list resources (API disabled or access denied), skipping")
				break
			}
			return nil, err
		}

		predefinedValues, err := protoToDict(tmpl.PredefinedValues)
		if err != nil {
			return nil, err
		}
		identityConstraints, err := protoToDict(tmpl.IdentityConstraints)
		if err != nil {
			return nil, err
		}
		passthroughExtensions, err := protoToDict(tmpl.PassthroughExtensions)
		if err != nil {
			return nil, err
		}

		maximumLifetime := ""
		if tmpl.MaximumLifetime != nil {
			maximumLifetime = tmpl.MaximumLifetime.AsDuration().String()
		}

		mqlTmpl, err := CreateResource(g.MqlRuntime, "gcp.project.certificateAuthorityService.certificateTemplate", map[string]*llx.RawData{
			"projectId":             llx.StringData(projectId),
			"resourcePath":          llx.StringData(tmpl.Name),
			"name":                  llx.StringData(parseResourceName(tmpl.Name)),
			"location":              llx.StringData(parseLocationFromPath(tmpl.Name)),
			"description":           llx.StringData(tmpl.Description),
			"maximumLifetime":       llx.StringData(maximumLifetime),
			"predefinedValues":      llx.DictData(predefinedValues),
			"identityConstraints":   llx.DictData(identityConstraints),
			"passthroughExtensions": llx.DictData(passthroughExtensions),
			"labels":                llx.MapData(convert.MapToInterfaceMap(tmpl.Labels), types.String),
			"createdAt":             llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
			"updatedAt":             llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTmpl)
	}

	return res, nil
}

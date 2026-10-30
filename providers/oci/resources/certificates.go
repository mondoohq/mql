// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciCertificates) id() (string, error) {
	return "oci.certificates", nil
}

// Certificates

func (o *mqlOciCertificates) certificates() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Certificates are issued into the compartment of the load balancer or
	// gateway that terminates TLS, and ListCertificates cannot look below the
	// compartment it is given. A root-only listing reported no certificates at
	// all, so expiry and renewal checks silently had nothing to inspect.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci certificates with region %s", region)

			svc, err := conn.CertificatesManagementClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]certificatesmanagement.CertificateSummary, *string, error) {
				response, err := svc.ListCertificates(ctx, certificatesmanagement.ListCertificatesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				c := items[i]

				var created, notBefore, notAfter *time.Time
				if c.TimeCreated != nil {
					created = &c.TimeCreated.Time
				}

				var subject string
				if c.Subject != nil {
					subject = stringValue(c.Subject.CommonName)
				}

				var sans []any
				var versionNumber int64
				if c.CurrentVersionSummary != nil {
					if c.CurrentVersionSummary.Validity != nil {
						v := c.CurrentVersionSummary.Validity
						if v.TimeOfValidityNotBefore != nil {
							notBefore = &v.TimeOfValidityNotBefore.Time
						}
						if v.TimeOfValidityNotAfter != nil {
							notAfter = &v.TimeOfValidityNotAfter.Time
						}
					}
					sans = sanSliceToAny(c.CurrentVersionSummary.SubjectAlternativeNames)
					versionNumber = int64Value(c.CurrentVersionSummary.VersionNumber)
				}
				if sans == nil {
					sans = []any{}
				}

				autoRenewal, renewalInterval := extractCertificateRenewal(c.CertificateRules)

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.certificates.certificate", stringValue(c.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(c.Id),
					"name":               llx.StringDataPtr(c.Name),
					"description":        llx.StringDataPtr(c.Description),
					"configType":         llx.StringData(string(c.ConfigType)),
					"subject":            llx.StringData(subject),
					"sans":               llx.ArrayData(sans, types.String),
					"validityNotBefore":  llx.TimeDataPtr(notBefore),
					"validityNotAfter":   llx.TimeDataPtr(notAfter),
					"keyAlgorithm":       llx.StringData(string(c.KeyAlgorithm)),
					"signatureAlgorithm": llx.StringData(string(c.SignatureAlgorithm)),
					"profileType":        llx.StringData(string(c.CertificateProfileType)),
					"currentVersion":     llx.IntData(versionNumber),
					"autoRenewalEnabled": llx.BoolData(autoRenewal),
					"renewalInterval":    llx.StringData(renewalInterval),
					"state":              llx.StringData(string(c.LifecycleState)),
					"created":            llx.TimeDataPtr(created),
					"freeformTags":       llx.MapData(strMapToAny(c.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlCert := mqlInstance.(*mqlOciCertificatesCertificate)
				mqlCert.cacheIssuerCaID = stringValue(c.IssuerCertificateAuthorityId)
				res = append(res, mqlCert)
			}
			return res, nil
		})
}

type mqlOciCertificatesCertificateInternal struct {
	ociCompartmentRef
	cacheIssuerCaID string
}

func (o *mqlOciCertificatesCertificate) id() (string, error) {
	return "oci.certificates.certificate/" + o.Id.Data, nil
}

func initOciCertificatesCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idArg := args["id"]
	if idArg == nil {
		return nil, nil, errors.New("id required to fetch oci.certificates.certificate")
	}
	idVal, ok := idArg.Value.(string)
	if !ok || idVal == "" {
		return nil, nil, errors.New("id must be a non-empty string to fetch oci.certificates.certificate")
	}

	obj, err := CreateResource(runtime, "oci.certificates", nil)
	if err != nil {
		return nil, nil, err
	}
	certs := obj.(*mqlOciCertificates)
	rawCerts := certs.GetCertificates()
	if rawCerts.Error != nil {
		return nil, nil, rawCerts.Error
	}
	for _, raw := range rawCerts.Data {
		c := raw.(*mqlOciCertificatesCertificate)
		if c.Id.Data == idVal {
			return args, c, nil
		}
	}
	return nil, nil, errors.New("oci.certificates.certificate not found: " + idVal)
}

func (o *mqlOciCertificatesCertificate) issuerCertificateAuthority() (*mqlOciCertificatesCertificateAuthority, error) {
	if o.cacheIssuerCaID == "" || !isOcid(o.cacheIssuerCaID) {
		o.IssuerCertificateAuthority.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.certificates.certificateAuthority", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheIssuerCaID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciCertificatesCertificateAuthority), nil
}

func initOciCertificatesCertificateAuthority(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.certificates.certificateAuthority")
	}

	obj, err := CreateResource(runtime, "oci.certificates", nil)
	if err != nil {
		return nil, nil, err
	}
	certs := obj.(*mqlOciCertificates)
	rawCas := certs.GetCertificateAuthorities()
	if rawCas.Error != nil {
		return nil, nil, rawCas.Error
	}
	for _, raw := range rawCas.Data {
		ca := raw.(*mqlOciCertificatesCertificateAuthority)
		if ca.Id.Data == idVal {
			return args, ca, nil
		}
	}
	return nil, nil, errors.New("oci.certificates.certificateAuthority not found: " + idVal)
}

// Certificate Authorities

func (o *mqlOciCertificates) certificateAuthorities() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci certificate authorities with region %s", region)

			svc, err := conn.CertificatesManagementClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]certificatesmanagement.CertificateAuthoritySummary, *string, error) {
				response, err := svc.ListCertificateAuthorities(ctx, certificatesmanagement.ListCertificateAuthoritiesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				ca := items[i]

				var created, notBefore, notAfter *time.Time
				if ca.TimeCreated != nil {
					created = &ca.TimeCreated.Time
				}

				var subject string
				if ca.Subject != nil {
					subject = stringValue(ca.Subject.CommonName)
				}

				if ca.CurrentVersionSummary != nil && ca.CurrentVersionSummary.Validity != nil {
					v := ca.CurrentVersionSummary.Validity
					if v.TimeOfValidityNotBefore != nil {
						notBefore = &v.TimeOfValidityNotBefore.Time
					}
					if v.TimeOfValidityNotAfter != nil {
						notAfter = &v.TimeOfValidityNotAfter.Time
					}
				}

				kind := caKindFromConfigType(string(ca.ConfigType))

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.certificates.certificateAuthority", stringValue(ca.CompartmentId), map[string]*llx.RawData{
					"id":                llx.StringDataPtr(ca.Id),
					"name":              llx.StringDataPtr(ca.Name),
					"description":       llx.StringDataPtr(ca.Description),
					"kind":              llx.StringData(kind),
					"configType":        llx.StringData(string(ca.ConfigType)),
					"subject":           llx.StringData(subject),
					"validityNotBefore": llx.TimeDataPtr(notBefore),
					"validityNotAfter":  llx.TimeDataPtr(notAfter),
					"signingAlgorithm":  llx.StringData(string(ca.SigningAlgorithm)),
					"state":             llx.StringData(string(ca.LifecycleState)),
					"created":           llx.TimeDataPtr(created),
					"freeformTags":      llx.MapData(strMapToAny(ca.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(ca.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlCa := mqlInstance.(*mqlOciCertificatesCertificateAuthority)
				mqlCa.cacheIssuerCaID = stringValue(ca.IssuerCertificateAuthorityId)
				mqlCa.cacheKmsKeyID = stringValue(ca.KmsKeyId)
				res = append(res, mqlCa)
			}
			return res, nil
		})
}

type mqlOciCertificatesCertificateAuthorityInternal struct {
	ociCompartmentRef
	cacheIssuerCaID string
	cacheKmsKeyID   string
}

func (o *mqlOciCertificatesCertificateAuthority) id() (string, error) {
	return "oci.certificates.certificateAuthority/" + o.Id.Data, nil
}

func (o *mqlOciCertificatesCertificateAuthority) issuerCertificateAuthority() (*mqlOciCertificatesCertificateAuthority, error) {
	// Root CAs report themselves as their own issuer; treat that as
	// "no separate issuer" to keep the typed traversal useful for
	// subordinate-only queries.
	if o.cacheIssuerCaID == "" || o.cacheIssuerCaID == o.Id.Data || !isOcid(o.cacheIssuerCaID) {
		o.IssuerCertificateAuthority.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.certificates.certificateAuthority", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheIssuerCaID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciCertificatesCertificateAuthority), nil
}

func (o *mqlOciCertificatesCertificateAuthority) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" || !isOcid(o.cacheKmsKeyID) {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciKmsKey), nil
}

// CA Bundles

func initOciCertificatesCaBundle(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idArg := args["id"]
	if idArg == nil {
		return nil, nil, errors.New("id required to fetch oci.certificates.caBundle")
	}
	idVal, ok := idArg.Value.(string)
	if !ok || idVal == "" {
		return nil, nil, errors.New("id must be a non-empty string to fetch oci.certificates.caBundle")
	}

	obj, err := CreateResource(runtime, "oci.certificates", nil)
	if err != nil {
		return nil, nil, err
	}
	certs := obj.(*mqlOciCertificates)
	rawBundles := certs.GetCaBundles()
	if rawBundles.Error != nil {
		return nil, nil, rawBundles.Error
	}
	for _, raw := range rawBundles.Data {
		b := raw.(*mqlOciCertificatesCaBundle)
		if b.Id.Data == idVal {
			return args, b, nil
		}
	}
	return nil, nil, errors.New("oci.certificates.caBundle not found: " + idVal)
}

func (o *mqlOciCertificates) caBundles() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci CA bundles with region %s", region)

			svc, err := conn.CertificatesManagementClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]certificatesmanagement.CaBundleSummary, *string, error) {
				response, err := svc.ListCaBundles(ctx, certificatesmanagement.ListCaBundlesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				b := items[i]

				var created *time.Time
				if b.TimeCreated != nil {
					created = &b.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.certificates.caBundle", stringValue(b.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(b.Id),
					"name":         llx.StringDataPtr(b.Name),
					"description":  llx.StringDataPtr(b.Description),
					"state":        llx.StringData(string(b.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(b.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(b.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}
			return res, nil
		})
}

func (o *mqlOciCertificatesCaBundle) id() (string, error) {
	return "oci.certificates.caBundle/" + o.Id.Data, nil
}

// helpers

// caKindFromConfigType maps OCI CA configType enum values onto the simpler
// ROOT/SUBORDINATE taxonomy callers want to filter on.
func caKindFromConfigType(cfg string) string {
	switch cfg {
	case string(certificatesmanagement.CertificateAuthorityConfigTypeRootCaGeneratedInternally),
		string(certificatesmanagement.CertificateAuthorityConfigTypeRootCaManagedExternally):
		return "ROOT"
	case string(certificatesmanagement.CertificateAuthorityConfigTypeSubordinateCaIssuedByInternalCa),
		string(certificatesmanagement.CertificateAuthorityConfigTypeSubordinateCaManagedInternallyIssuedByExternalCa):
		return "SUBORDINATE"
	}
	return ""
}

// extractCertificateRenewal pulls the renewal-rule fields out of the
// polymorphic CertificateRule slice, returning (enabled, interval ISO8601).
// Only the CERTIFICATE_RENEWAL_RULE variant is currently modeled by OCI.
func extractCertificateRenewal(rules []certificatesmanagement.CertificateRule) (bool, string) {
	for _, r := range rules {
		if rr, ok := r.(certificatesmanagement.CertificateRenewalRule); ok {
			return true, stringValue(rr.RenewalInterval)
		}
	}
	return false, ""
}

// sanSliceToAny materializes the typed SAN list as a plain []any of
// "<type>:<value>" strings — matches the on-the-wire format and keeps the
// lr schema simple.
func sanSliceToAny(sans []certificatesmanagement.CertificateSubjectAlternativeName) []any {
	if len(sans) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(sans))
	for i := range sans {
		// Materialize as type:value for parity with how OCI renders SANs
		// in certificate PEM fields (DNS:example.com, IP:10.0.0.1).
		out = append(out, string(sans[i].Type)+":"+stringValue(sans[i].Value))
	}
	return out
}

type mqlOciCertificatesCaBundleInternal struct {
	ociCompartmentRef
}

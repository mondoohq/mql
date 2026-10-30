// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
)

// certificateArgs builds the resource args for an openai.certificate. The same
// certificate is listed at the organization and again at every project it is
// activated for, and `active` means something different at each scope, so the
// scope prefix keeps the two apart in the resource cache while `id` stays the
// plain certificate identifier.
func certificateArgs(scope, id, name string, active bool, createdAt, validAt, expiresAt int64) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(scope + "/" + id),
		"id":        llx.StringData(id),
		"name":      llx.StringData(name),
		"active":    llx.BoolData(active),
		"createdAt": llx.TimeDataPtr(unixToNullableTime(createdAt)),
		"validAt":   llx.TimeDataPtr(unixToNullableTime(validAt)),
		"expiresAt": llx.TimeDataPtr(unixToNullableTime(expiresAt)),
	}
}

func (r *mqlOpenai) certificates() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.certificates")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Certificates.ListAutoPaging(ctx, openai.AdminOrganizationCertificateListParams{})
	var res []any
	for iter.Next() {
		c := iter.Current()
		mqlCert, err := CreateResource(r.MqlRuntime, "openai.certificate", certificateArgs(
			"org", c.ID, c.Name, c.Active, c.CreatedAt, c.CertificateDetails.ValidAt, c.CertificateDetails.ExpiresAt))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCert)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list organization certificates: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiProject) certificates() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.certificates")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.Certificates.ListAutoPaging(ctx, r.Id.Data,
		openai.AdminOrganizationProjectCertificateListParams{})
	var res []any
	for iter.Next() {
		c := iter.Current()
		mqlCert, err := CreateResource(r.MqlRuntime, "openai.certificate", certificateArgs(
			"project/"+r.Id.Data, c.ID, c.Name, c.Active, c.CreatedAt,
			c.CertificateDetails.ValidAt, c.CertificateDetails.ExpiresAt))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCert)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list certificates for project %s: %w", r.Id.Data, err)
	}
	return res, nil
}

func (r *mqlOpenai) containers() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.containers")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Containers.ListAutoPaging(ctx, openai.ContainerListParams{})
	var res []any
	for iter.Next() {
		c := iter.Current()

		// A container without an expiration policy, or without a network policy,
		// leaves the whole object out of the response rather than sending an
		// empty one. Reporting those as "" or an empty domain list would claim a
		// policy that is not there.
		var expiresAfterAnchor *string
		var expiresAfterMinutes *int64
		if c.JSON.ExpiresAfter.Valid() {
			expiresAfterAnchor = &c.ExpiresAfter.Anchor
			expiresAfterMinutes = &c.ExpiresAfter.Minutes
		}

		var networkPolicyType *string
		var allowedDomains *llx.RawData
		if c.JSON.NetworkPolicy.Valid() {
			networkPolicyType = &c.NetworkPolicy.Type
			allowedDomains = llx.ArrayData(convertStringSlice(c.NetworkPolicy.AllowedDomains), "string")
		} else {
			allowedDomains = llx.NilData
		}

		mqlContainer, err := CreateResource(r.MqlRuntime, "openai.container", map[string]*llx.RawData{
			"__id":                        llx.StringData(c.ID),
			"id":                          llx.StringData(c.ID),
			"name":                        llx.StringData(c.Name),
			"status":                      llx.StringData(c.Status),
			"createdAt":                   llx.TimeDataPtr(unixToNullableTime(c.CreatedAt)),
			"lastActiveAt":                llx.TimeDataPtr(unixToNullableTime(c.LastActiveAt)),
			"expiresAfterAnchor":          llx.StringDataPtr(expiresAfterAnchor),
			"expiresAfterMinutes":         llx.IntDataPtr(expiresAfterMinutes),
			"networkPolicyType":           llx.StringDataPtr(networkPolicyType),
			"networkPolicyAllowedDomains": allowedDomains,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlContainer)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiContainer) files() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.container.files")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Containers.Files.ListAutoPaging(ctx, r.Id.Data, openai.ContainerFileListParams{}),
		func(f openai.ContainerFileListResponse) string { return f.ID },
		func(f openai.ContainerFileListResponse) error {
			// the same file path exists in more than one sandbox, so the entry
			// is keyed by container as well as by file
			mqlFile, err := CreateResource(r.MqlRuntime, "openai.container.file", map[string]*llx.RawData{
				"__id":      llx.StringData(r.Id.Data + "/" + f.ID),
				"id":        llx.StringData(f.ID),
				"path":      llx.StringData(f.Path),
				"source":    llx.StringData(f.Source),
				"bytes":     llx.IntData(f.Bytes),
				"createdAt": llx.TimeDataPtr(unixToNullableTime(f.CreatedAt)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlFile)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list files in container %s: %w", r.Id.Data, err)
	}
	return res, nil
}

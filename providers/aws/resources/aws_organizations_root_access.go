// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isRootAccessNotConfigured reports whether the error means centralized root
// access has simply never been turned on, rather than that the read failed.
//
// ListOrganizationsFeatures models exactly four errors, and this covers the
// three that establish an answer:
//
//   - OrganizationNotFoundException - the calling account is in no
//     organization, so there is nothing to enable the feature on.
//   - OrganizationNotInAllFeaturesModeException - the organization runs in
//     consolidated-billing mode, where the feature cannot be enabled.
//   - ServiceAccessNotEnabledException - IAM has no trusted access in the
//     organization, which is the prerequisite, so nothing is enabled.
//
// The fourth, AccountNotManagementOrDelegatedAdministratorException, is
// deliberately absent: it fires on a plain member account, which leaves the
// organization's setting unknown rather than off. It stays an error for the
// reason given at the call site.
func isRootAccessNotConfigured(err error) bool {
	var noOrg *iamtypes.OrganizationNotFoundException
	var notAllFeatures *iamtypes.OrganizationNotInAllFeaturesModeException
	var svcAccessNotEnabled *iamtypes.ServiceAccessNotEnabledException
	return errors.As(err, &noOrg) ||
		errors.As(err, &notAllFeatures) ||
		errors.As(err, &svcAccessNotEnabled)
}

// enabledRootFeatures reports which centralized root access features the
// organization has turned on. Empty means none, which is the state CIS AWS
// Foundations 2.1.1 flags.
func (a *mqlAwsOrganization) enabledRootFeatures() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Iam("") // IAM is global, like every other aws.iam.* call

	resp, err := client.ListOrganizationsFeatures(context.Background(), &iam.ListOrganizationsFeaturesInput{})
	if err != nil {
		if isRootAccessNotConfigured(err) {
			return []any{}, nil
		}
		// Anything else - a plain member account
		// (AccountNotManagementOrDelegatedAdministratorException), a denial, a
		// transport failure - leaves the answer unknown rather than empty, so
		// it stays an error. An empty list here would read as "centralized root
		// access is off", which is the finding an audit acts on.
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.EnabledFeatures))
	for _, feature := range resp.EnabledFeatures {
		res = append(res, string(feature))
	}
	return res, nil
}

// trustedAccessServicePrincipals lists the services allowed to act across the
// organization's accounts. This is the prerequisite for any service to be
// administered organization-wide, including IAM for centralized root access.
func (a *mqlAwsOrganization) trustedAccessServicePrincipals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	res := []any{}
	paginator := organizations.NewListAWSServiceAccessForOrganizationPaginator(client,
		&organizations.ListAWSServiceAccessForOrganizationInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// A standalone account has no organization, so it has no trusted
			// access to report. That is the only error this operation models
			// that establishes an answer rather than hiding one: the rest are
			// AccessDenied, ConstraintViolation, InvalidInput, Service,
			// TooManyRequests and UnsupportedAPIEndpoint, none of which say
			// anything about which services are trusted.
			//
			// Note that a consolidated-billing organization is *not* an error
			// here - it is a real organization and answers normally, with a
			// list that is simply short.
			if isOrganizationsNotInUseError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, principal := range page.EnabledServicePrincipals {
			if principal.ServicePrincipal == nil {
				continue
			}
			res = append(res, *principal.ServicePrincipal)
		}
	}
	return res, nil
}

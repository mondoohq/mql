// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/aws/connection"
)

type mqlAwsAccountInternal struct {
	descLock    sync.Mutex
	descFetched atomic.Bool
	descAccount *orgtypes.Account
}

// fetchOrgAccountDescription retrieves and caches the AWS Organizations
// DescribeAccount response. Returns (nil, nil) when the call is denied — the
// caller is not in the management or a delegated administrator account.
func (a *mqlAwsAccount) fetchOrgAccountDescription() (*orgtypes.Account, error) {
	if a.descFetched.Load() {
		return a.descAccount, nil
	}
	a.descLock.Lock()
	defer a.descLock.Unlock()
	if a.descFetched.Load() {
		return a.descAccount, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	accountId := a.Id.Data
	resp, err := client.DescribeAccount(context.Background(), &organizations.DescribeAccountInput{
		AccountId: &accountId,
	})
	if err != nil {
		// A denial leaves the description unknown; a standalone account has no
		// description to read. Both mean there is nothing to report, and
		// neither is a reason to fail the field.
		if Is400AccessDeniedError(err) || isOrganizationsNotInUseError(err) {
			a.descFetched.Store(true)
			return nil, nil
		}
		return nil, err
	}
	// set descAccount before the flag so the lock-free fast path can't observe
	// descFetched == true with descAccount still unwritten.
	a.descAccount = resp.Account
	a.descFetched.Store(true)
	return a.descAccount, nil
}

func (a *mqlAwsAccount) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsAccount) aliases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Iam("") // no region for iam, use configured region

	res, err := client.ListAccountAliases(context.TODO(), &iam.ListAccountAliasesInput{})
	if err != nil {
		return nil, err
	}
	result := []any{}
	for i := range res.AccountAliases {
		result = append(result, res.AccountAliases[i])
	}
	return result, nil
}

// fetchOrganization describes the caller's AWS organization and maps it onto a
// new aws.organization resource. Both aws.account.organization and the
// aws.organization init go through here so the two paths cannot drift apart.
func fetchOrganization(runtime *plugin.Runtime) (*mqlAwsOrganization, error) {
	conn, ok := runtime.Connection.(*connection.AwsConnection)
	if !ok {
		return nil, errors.New("aws.organization requires an AWS connection")
	}
	client := conn.Organizations("") // no region for orgs, use configured region

	org, err := client.DescribeOrganization(context.TODO(), &organizations.DescribeOrganizationInput{})
	if err != nil {
		// A standalone account has no organization to describe. Report that as
		// absence, so callers can tell it apart from a read that failed.
		if isOrganizationsNotInUseError(err) {
			return nil, nil
		}
		return nil, err
	}
	if org == nil {
		return nil, nil
	}
	if org.Organization == nil {
		return nil, errors.New("aws.organization: no organization returned for this account")
	}

	res, err := CreateResource(runtime, ResourceAwsOrganization,
		map[string]*llx.RawData{
			"arn":                llx.StringDataPtr(org.Organization.Arn),
			"id":                 llx.StringDataPtr(org.Organization.Id),
			"featureSet":         llx.StringData(string(org.Organization.FeatureSet)),
			"masterAccountId":    llx.StringDataPtr(org.Organization.MasterAccountId),
			"masterAccountArn":   llx.StringDataPtr(org.Organization.MasterAccountArn),
			"masterAccountEmail": llx.StringDataPtr(org.Organization.MasterAccountEmail),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsOrganization), nil
}

func (a *mqlAwsAccount) organization() (*mqlAwsOrganization, error) {
	org, err := fetchOrganization(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if org == nil {
		// Null rather than an error, so `organization == null` is a usable
		// signal for scoping a check to multi-account environments instead of
		// something that fails on the accounts it means to exclude.
		a.Organization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return org, nil
}

// isOrganizationMember reports whether the account belongs to an AWS
// organization.
//
// The same fact as `organization != null`, as a plain bool. A filter is where
// this gets used, and MQL's three-valued logic makes a null awkward to test
// safely, so the boolean keeps the scoping predicate unambiguous.
func (a *mqlAwsAccount) isOrganizationMember() (bool, error) {
	org, err := fetchOrganization(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	return org != nil, nil
}

// initAwsOrganization populates the organization from the API when it is
// reached directly rather than through aws.account.organization. Without this,
// a bare `aws.organization` query creates the resource with every field unset,
// which surfaces client-side as null values with no attribution.
func initAwsOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) >= 2 {
		return args, nil, nil
	}

	res, err := fetchOrganization(runtime)
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		// An init has to produce a resource or an error, so unlike the accessor
		// it cannot report absence as null. Name the condition and point at the
		// form that can, rather than surfacing a bare SDK exception.
		return nil, nil, errors.New("this account is not part of an AWS organization; " +
			"use aws.account.organization, which is null for a standalone account, " +
			"or aws.account.isOrganizationMember")
	}
	return args, res, nil
}

func (a *mqlAwsOrganization) accounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("") // no region for orgs, use configured region
	ctx := context.Background()

	accounts := []any{}
	paginator := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, account := range page.Accounts {
			res, err := CreateResource(a.MqlRuntime, ResourceAwsAccount,
				map[string]*llx.RawData{
					"id": llx.StringDataPtr(account.Id),
				})
			if err != nil {
				return nil, err
			}
			accounts = append(accounts, res.(*mqlAwsAccount))
		}
	}
	return accounts, nil
}

// tags retrieves a map of tags for a given AWS resource.
func (c *mqlAwsAccount) tags() (map[string]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("") // no region for orgs, use configured region

	// c.Id.Data is the internal MQL id (e.g. "aws.account/123456789012"); AWS
	// Organizations expects the bare account id.
	accountId := trimAwsAccountIdToJustId(c.Id.Data)
	input := &organizations.ListTagsForResourceInput{
		ResourceId: &accountId,
	}

	// Note: This operation can only be called from the organization's management
	// account or by a member account that is a delegated administrator for an
	// Amazon Web Services service.
	tags := make(map[string]any)
	paginator := organizations.NewListTagsForResourcePaginator(client, input)
	for paginator.HasMorePages() {
		res, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, err
		}

		for _, tag := range res.Tags {
			if tag.Key != nil && tag.Value != nil {
				tags[*tag.Key] = *tag.Value
			}
		}
	}

	return tags, nil
}

func (a *mqlAwsAccount) contactInformation() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Account("") // no region for account service, use configured region

	resp, err := client.GetContactInformation(context.TODO(), &account.GetContactInformationInput{})
	if err != nil {
		return nil, err
	}

	// Convert the contact information to map[string]any
	result := make(map[string]any)
	if resp.ContactInformation != nil {
		if resp.ContactInformation.AddressLine1 != nil {
			result["addressLine1"] = *resp.ContactInformation.AddressLine1
		}
		if resp.ContactInformation.AddressLine2 != nil {
			result["addressLine2"] = *resp.ContactInformation.AddressLine2
		}
		if resp.ContactInformation.AddressLine3 != nil {
			result["addressLine3"] = *resp.ContactInformation.AddressLine3
		}
		if resp.ContactInformation.City != nil {
			result["city"] = *resp.ContactInformation.City
		}
		if resp.ContactInformation.CompanyName != nil {
			result["companyName"] = *resp.ContactInformation.CompanyName
		}
		if resp.ContactInformation.CountryCode != nil {
			result["countryCode"] = *resp.ContactInformation.CountryCode
		}
		if resp.ContactInformation.DistrictOrCounty != nil {
			result["districtOrCounty"] = *resp.ContactInformation.DistrictOrCounty
		}
		if resp.ContactInformation.FullName != nil {
			result["fullName"] = *resp.ContactInformation.FullName
		}
		if resp.ContactInformation.PhoneNumber != nil {
			result["phoneNumber"] = *resp.ContactInformation.PhoneNumber
		}
		if resp.ContactInformation.PostalCode != nil {
			result["postalCode"] = *resp.ContactInformation.PostalCode
		}
		if resp.ContactInformation.StateOrRegion != nil {
			result["stateOrRegion"] = *resp.ContactInformation.StateOrRegion
		}
		if resp.ContactInformation.WebsiteUrl != nil {
			result["websiteUrl"] = *resp.ContactInformation.WebsiteUrl
		}
	}
	return result, nil
}

func (a *mqlAwsAccount) alternateContacts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Account("") // no region for account service, use configured region

	contactTypes := []types.AlternateContactType{
		types.AlternateContactTypeBilling,
		types.AlternateContactTypeOperations,
		types.AlternateContactTypeSecurity,
	}

	var contacts []any

	for _, cType := range contactTypes {
		resp, err := client.GetAlternateContact(context.TODO(), &account.GetAlternateContactInput{
			AlternateContactType: cType,
		})

		// Treat both ResourceNotFoundException and a 200-with-nil-body as
		// "contact not configured" — the only signal MQL needs is exists=false.
		notConfigured := false
		if err != nil {
			var notFoundErr *types.ResourceNotFoundException
			if !errors.As(err, &notFoundErr) {
				return nil, err
			}
			notConfigured = true
		} else if resp.AlternateContact == nil {
			notConfigured = true
		}

		if notConfigured {
			contact, resErr := CreateResource(a.MqlRuntime, ResourceAwsAccountAlternateContact,
				map[string]*llx.RawData{
					"accountId":    llx.StringData(a.Id.Data),
					"contactType":  llx.StringData(string(cType)),
					"emailAddress": llx.StringData(""),
					"name":         llx.StringData(""),
					"phoneNumber":  llx.StringData(""),
					"title":        llx.StringData(""),
					"exists":       llx.BoolData(false),
				})
			if resErr != nil {
				return nil, resErr
			}
			contacts = append(contacts, contact)
			continue
		}

		ac := resp.AlternateContact
		contact, err := CreateResource(a.MqlRuntime, ResourceAwsAccountAlternateContact,
			map[string]*llx.RawData{
				"accountId":    llx.StringData(a.Id.Data),
				"contactType":  llx.StringData(string(cType)),
				"emailAddress": llx.StringData(aws.ToString(ac.EmailAddress)),
				"name":         llx.StringData(aws.ToString(ac.Name)),
				"phoneNumber":  llx.StringData(aws.ToString(ac.PhoneNumber)),
				"title":        llx.StringData(aws.ToString(ac.Title)),
				"exists":       llx.BoolData(true),
			})
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, contact)
	}

	return contacts, nil
}

func (a *mqlAwsAccount) securityContact() (*mqlAwsAccountAlternateContact, error) {
	contacts, err := a.alternateContacts()
	if err != nil {
		return nil, err
	}

	for _, c := range contacts {
		contact := c.(*mqlAwsAccountAlternateContact)
		if contact.ContactType.Data == string(types.AlternateContactTypeSecurity) {
			return contact, nil
		}
	}

	// Should not happen as alternateContacts() always returns all three types
	return nil, errors.New("security contact not found")
}

func (a *mqlAwsAccount) billingContact() (*mqlAwsAccountAlternateContact, error) {
	contacts, err := a.alternateContacts()
	if err != nil {
		return nil, err
	}

	for _, c := range contacts {
		contact := c.(*mqlAwsAccountAlternateContact)
		if contact.ContactType.Data == string(types.AlternateContactTypeBilling) {
			return contact, nil
		}
	}

	// Should not happen as alternateContacts() always returns all three types
	return nil, errors.New("billing contact not found")
}

func (a *mqlAwsAccount) operationsContact() (*mqlAwsAccountAlternateContact, error) {
	contacts, err := a.alternateContacts()
	if err != nil {
		return nil, err
	}

	for _, c := range contacts {
		contact := c.(*mqlAwsAccountAlternateContact)
		if contact.ContactType.Data == string(types.AlternateContactTypeOperations) {
			return contact, nil
		}
	}

	// Should not happen as alternateContacts() always returns all three types
	return nil, errors.New("operations contact not found")
}

func initAwsAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) >= 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		conn, ok := runtime.Connection.(*connection.AwsConnection)
		if !ok {
			return nil, nil, errors.New("aws.account requires an AWS connection")
		}
		args["id"] = llx.StringData(conn.AccountId())
	}
	if args["id"] == nil {
		return args, nil, errors.New("no account id specified")
	}
	id := args["id"].Value.(string)
	res, err := CreateResource(runtime, ResourceAwsAccount,
		map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsAccountAlternateContact) id() (string, error) {
	return a.AccountId.Data + "/" + a.ContactType.Data, nil
}

func initAwsAccountAlternateContact(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return args, nil, nil
}

type mqlAwsOrganizationDelegatedAdministratorInternal struct {
	cacheAccountId string
}

func (a *mqlAwsOrganization) delegatedAdministrators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	res := []any{}
	paginator := organizations.NewListDelegatedAdministratorsPaginator(client, &organizations.ListDelegatedAdministratorsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, da := range page.DelegatedAdministrators {
			mqlDA, err := CreateResource(a.MqlRuntime, "aws.organization.delegatedAdministrator",
				map[string]*llx.RawData{
					"arn":                   llx.StringDataPtr(da.Arn),
					"accountId":             llx.StringDataPtr(da.Id),
					"name":                  llx.StringDataPtr(da.Name),
					"email":                 llx.StringDataPtr(da.Email),
					"status":                llx.StringData(string(da.Status)),
					"joinedMethod":          llx.StringData(string(da.JoinedMethod)),
					"joinedTimestamp":       llx.TimeDataPtr(da.JoinedTimestamp),
					"delegationEnabledDate": llx.TimeDataPtr(da.DelegationEnabledDate),
				})
			if err != nil {
				return nil, err
			}
			mqlDATyped := mqlDA.(*mqlAwsOrganizationDelegatedAdministrator)
			mqlDATyped.cacheAccountId = aws.ToString(da.Id)
			res = append(res, mqlDATyped)
		}
	}
	return res, nil
}

func (a *mqlAwsOrganizationDelegatedAdministrator) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsOrganizationDelegatedAdministrator) delegatedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	accountId := a.cacheAccountId
	res := []any{}
	paginator := organizations.NewListDelegatedServicesForAccountPaginator(client, &organizations.ListDelegatedServicesForAccountInput{
		AccountId: &accountId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, ds := range page.DelegatedServices {
			mqlDS, err := CreateResource(a.MqlRuntime, "aws.organization.delegatedService",
				map[string]*llx.RawData{
					"servicePrincipal":      llx.StringDataPtr(ds.ServicePrincipal),
					"delegationEnabledDate": llx.TimeDataPtr(ds.DelegationEnabledDate),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDS)
		}
	}
	return res, nil
}

// delegatedServiceCacheKey builds a stable cache key for a delegated service.
// DelegationEnabledDate is optional, so guard against a nil time pointer to avoid
// dereferencing nil (which would panic in a field-resolver goroutine).
func delegatedServiceCacheKey(servicePrincipal string, date *time.Time) string {
	if date == nil {
		return servicePrincipal
	}
	return servicePrincipal + "/" + date.String()
}

func (a *mqlAwsOrganizationDelegatedService) id() (string, error) {
	return delegatedServiceCacheKey(a.ServicePrincipal.Data, a.DelegationEnabledDate.Data), nil
}

func (a *mqlAwsAccount) paths() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	accountId := a.Id.Data
	resp, err := client.DescribeAccount(ctx, &organizations.DescribeAccountInput{
		AccountId: &accountId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}
	if resp.Account == nil {
		return []any{}, nil
	}
	return toInterfaceArr(resp.Account.Paths), nil
}

func (a *mqlAwsOrganization) organizationalUnits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	var ous []any

	// Recursive function to list all OUs under a given parent
	var listOUs func(parentId string) error
	listOUs = func(parentId string) error {
		paginator := organizations.NewListOrganizationalUnitsForParentPaginator(client, &organizations.ListOrganizationalUnitsForParentInput{
			ParentId: &parentId,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if Is400AccessDeniedError(err) {
					return nil
				}
				return err
			}
			for _, ou := range page.OrganizationalUnits {
				mqlOU, err := CreateResource(a.MqlRuntime, "aws.organization.organizationalUnit",
					map[string]*llx.RawData{
						"arn":  llx.StringDataPtr(ou.Arn),
						"id":   llx.StringDataPtr(ou.Id),
						"name": llx.StringDataPtr(ou.Name),
						"path": llx.StringDataPtr(ou.Path),
					})
				if err != nil {
					return err
				}
				ous = append(ous, mqlOU)
				// Recurse into child OUs
				if err := listOUs(aws.ToString(ou.Id)); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Start from the organization roots
	rootsPaginator := organizations.NewListRootsPaginator(client, &organizations.ListRootsInput{})
	for rootsPaginator.HasMorePages() {
		page, err := rootsPaginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, root := range page.Roots {
			if err := listOUs(aws.ToString(root.Id)); err != nil {
				return nil, err
			}
		}
	}

	return ous, nil
}

func (a *mqlAwsOrganizationOrganizationalUnit) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func newServiceControlPolicyResource(runtime *plugin.Runtime, p orgtypes.PolicySummary) (plugin.Resource, error) {
	return CreateResource(runtime, "aws.organization.serviceControlPolicy",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(p.Id),
			"id":          llx.StringDataPtr(p.Id),
			"arn":         llx.StringDataPtr(p.Arn),
			"name":        llx.StringDataPtr(p.Name),
			"description": llx.StringDataPtr(p.Description),
			"awsManaged":  llx.BoolData(p.AwsManaged),
		})
}

func (a *mqlAwsOrganization) serviceControlPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	res := []any{}
	paginator := organizations.NewListPoliciesPaginator(client, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for i := range page.Policies {
			mqlPolicy, err := newServiceControlPolicyResource(a.MqlRuntime, page.Policies[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAwsOrganizationOrganizationalUnit) serviceControlPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()

	targetId := a.Id.Data
	res := []any{}
	paginator := organizations.NewListPoliciesForTargetPaginator(client, &organizations.ListPoliciesForTargetInput{
		TargetId: &targetId,
		Filter:   orgtypes.PolicyTypeServiceControlPolicy,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for i := range page.Policies {
			mqlPolicy, err := newServiceControlPolicyResource(a.MqlRuntime, page.Policies[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAwsOrganizationServiceControlPolicy) content() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return describePolicyContent(context.Background(), conn.Organizations(""), a.Id.Data)
}

func (a *mqlAwsOrganizationServiceControlPolicy) statements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetContent())
}

func (a *mqlAwsOrganizationDelegatedAdministrator) account() (*mqlAwsAccount, error) {
	mqlAccount, err := NewResource(a.MqlRuntime, "aws.account",
		map[string]*llx.RawData{
			"id": llx.StringData(a.cacheAccountId),
		})
	if err != nil {
		return nil, err
	}
	return mqlAccount.(*mqlAwsAccount), nil
}

func (a *mqlAwsAccount) regionOptInStatus() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Account("")
	ctx := context.Background()

	res := map[string]any{}
	paginator := account.NewListRegionsPaginator(client, &account.ListRegionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, r := range page.Regions {
			if r.RegionName == nil {
				continue
			}
			res[*r.RegionName] = string(r.RegionOptStatus)
		}
	}
	return res, nil
}

func (a *mqlAwsAccount) name() (string, error) {
	acc, err := a.fetchOrgAccountDescription()
	if err != nil {
		return "", err
	}
	if acc == nil {
		// No description to read. Empty would be a name the account has, and
		// an account with a blank name is a different finding from one whose
		// name could not be read.
		a.Name.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return aws.ToString(acc.Name), nil
}

func (a *mqlAwsAccount) email() (string, error) {
	acc, err := a.fetchOrgAccountDescription()
	if err != nil {
		return "", err
	}
	if acc == nil {
		a.Email.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return aws.ToString(acc.Email), nil
}

func (a *mqlAwsAccount) state() (string, error) {
	acc, err := a.fetchOrgAccountDescription()
	if err != nil {
		return "", err
	}
	if acc == nil {
		// No description to read, which is not the same as a lifecycle state of
		// "". Empty would be a value the account does not have.
		a.State.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(acc.State), nil
}

func (a *mqlAwsAccount) joinedMethod() (string, error) {
	acc, err := a.fetchOrgAccountDescription()
	if err != nil {
		return "", err
	}
	if acc == nil {
		a.JoinedMethod.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(acc.JoinedMethod), nil
}

func (a *mqlAwsAccount) joinedTimestamp() (*time.Time, error) {
	acc, err := a.fetchOrgAccountDescription()
	if err != nil || acc == nil {
		return nil, err
	}
	return acc.JoinedTimestamp, nil
}

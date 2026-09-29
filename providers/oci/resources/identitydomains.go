// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ociScimPageSize is how many SCIM resources to request per call.
//
// Identity Domains paginates with startIndex/count rather than a page token,
// so the loop has to drive the offset itself. 200 is well inside the service
// maximum and keeps the request count low on domains with many users.
const ociScimPageSize = 200

// ociScimAttributeSets selects which groups of attributes a SCIM listing
// returns.
//
// A plain SCIM list returns only the attributes a schema marks
// returned=always or returned=default. Anything marked returned=request is
// omitted unless the caller asks for it, and the fields that carry the
// security signal are exactly the ones marked that way: a user's login
// history and MFA enrollment date, a user's group memberships, and a group's
// member list. Without this the provider reported every account as never
// having signed in and every group as empty, which reads as fact rather than
// as a missing request parameter.
//
// The default set has to be listed alongside request, because naming
// attributes narrows the response to what was named; asking for both keeps
// everything a plain listing already returned.
var ociScimAttributeSets = []identitydomains.AttributeSetsEnum{
	identitydomains.AttributeSetsDefault,
	identitydomains.AttributeSetsRequest,
}

// ociScimError annotates a failed SCIM call with the domain it was made
// against and, for an authorization failure, what is actually missing.
//
// Reading a domain's users or groups needs a role granted inside that domain,
// which is separate from the tenancy-level policy that lets ListDomains
// enumerate it. A principal set up to read the tenancy therefore lists every
// domain and then fails on all of them, and the bare SCIM error says only that
// something was not authorized, naming neither the domain nor the role.
//
// The error is deliberately not degraded to an empty collection. An empty user
// list is indistinguishable from a domain with no users, and a scan that
// reports no users where it simply could not look is the failure mode this
// provider is most concerned with.
func ociScimError(err error, domainName string, collection string) error {
	if err == nil {
		return nil
	}
	if svcErr, ok := common.IsServiceError(err); ok {
		switch svcErr.GetHTTPStatusCode() {
		case 401, 403, 404:
			return fmt.Errorf(
				"cannot read %s of identity domain %q: the scanning principal needs a role within the domain, such as Identity Domain Administrator or User Administrator, which tenancy-level policy does not grant: %w",
				collection, domainName, err)
		}
	}
	return fmt.Errorf("cannot read %s of identity domain %q: %w", collection, domainName, err)
}

func (o *mqlOciIdentity) domains() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	// Domains are an identity-plane resource and live in the home region, so
	// this is a single listing rather than a region fan-out. They can be
	// created in any compartment, though, so the compartment tree still has to
	// be walked.
	//
	// Concurrently, because GetCompartments returns the entire subtree and a
	// tenancy with a few hundred compartments turned one field access into a
	// few hundred sequential round-trips.
	compartments, err := conn.GetCompartments(ctx)
	if err != nil {
		return nil, err
	}

	jobs := make([]*jobpool.Job, 0, len(compartments))
	for i := range compartments {
		compartmentID := stringValue(compartments[i].Id)
		if compartmentID == "" {
			continue
		}

		jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
			summaries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.DomainSummary, *string, error) {
				response, err := client.ListDomains(ctx, identity.ListDomainsRequest{
					CompartmentId: common.String(compartmentID),
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

			// []any rather than []identity.DomainSummary: the collector joins
			// results by asserting []any and silently drops anything else.
			domains := make([]any, 0, len(summaries))
			for i := range summaries {
				domains = append(domains, summaries[i])
			}

			return jobpool.JobResult(domains), nil
		}))
	}

	// The same accounting the resource listers get from ociCollect, applied
	// directly because identity domains are global: they are listed per
	// compartment but not per region, so there is no region dimension to fan out
	// over. A compartment the caller cannot read is skipped, but every
	// compartment refusing access is an under-scoped token rather than a tenancy
	// without identity domains.
	collected, err := ociJoinCompartmentJobs(jobs, ociScopeAllCompartments.concurrency())
	if err != nil {
		return nil, err
	}

	res := []any{}
	for j := range collected {
		d, ok := collected[j].(identity.DomainSummary)
		if !ok {
			continue
		}

		replicaRegions := make([]string, 0, len(d.ReplicaRegions))
		for _, r := range d.ReplicaRegions {
			replicaRegions = append(replicaRegions, stringValue(r.Region))
		}

		mqlDomain, err := CreateResource(o.MqlRuntime, "oci.identity.domain", map[string]*llx.RawData{
			"id":              llx.StringDataPtr(d.Id),
			"name":            llx.StringDataPtr(d.DisplayName),
			"description":     llx.StringDataPtr(d.Description),
			"type":            llx.StringData(string(d.Type)),
			"licenseType":     llx.StringDataPtr(d.LicenseType),
			"homeRegion":      llx.StringDataPtr(d.HomeRegion),
			"replicaRegions":  llx.ArrayData(stringsToAny(replicaRegions), types.String),
			"isHiddenOnLogin": llx.BoolData(boolValue(d.IsHiddenOnLogin)),
			"state":           llx.StringData(string(d.LifecycleState)),
			"created":         sdkTimeData(d.TimeCreated),
			"freeformTags":    llx.MapData(strMapToAny(d.FreeformTags), types.String),
			"definedTags":     llx.MapData(definedTagsToAny(d.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlDomainTyped := mqlDomain.(*mqlOciIdentityDomain)
		mqlDomainTyped.cacheCompartmentID = stringValue(d.CompartmentId)
		mqlDomainTyped.cacheURL = stringValue(d.Url)
		res = append(res, mqlDomainTyped)
	}

	return res, nil
}

type mqlOciIdentityDomainInternal struct {
	cacheCompartmentID string
	// The domain's own SCIM endpoint. Every sub-collection is served from
	// here rather than from a regional endpoint.
	cacheURL string

	// Every sub-collection accessor needs a client for this domain, so it is
	// built once rather than per accessor.
	//
	// An atomic.Pointer rather than a plain one, for the same reason the
	// detail flags elsewhere are atomic.Bool: domainClient reads it before
	// taking the lock, and an unsynchronized pointer read racing the write
	// inside the lock is a data race.
	clientLock   sync.Mutex
	cachedClient atomic.Pointer[identitydomains.IdentityDomainsClient]

	// The domain's keep-me-signed-in settings, read once and shared by the six
	// fields that report parts of them.
	kmsi ociRetryLazy[*identitydomains.KmsiSetting]

	// The domain's settings record, read once and shared by the fields that
	// report parts of it.
	settings ociRetryLazy[*identitydomains.Setting]
}

func (o *mqlOciIdentityDomain) id() (string, error) {
	return "oci.identity.domain/" + o.Id.Data, nil
}

func (o *mqlOciIdentityDomain) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciIdentityDomain) domainClient() (*identitydomains.IdentityDomainsClient, error) {
	// Fast path: five sub-collection accessors share this client, so after the
	// first the rest should not queue on the mutex to read a cached pointer.
	if client := o.cachedClient.Load(); client != nil {
		return client, nil
	}

	o.clientLock.Lock()
	defer o.clientLock.Unlock()
	if client := o.cachedClient.Load(); client != nil {
		return client, nil
	}

	if o.cacheURL == "" {
		return nil, errors.New("identity domain has no endpoint url: " + o.Id.Data)
	}
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	client, err := conn.IdentityDomainsClient(o.cacheURL)
	if err != nil {
		return nil, err
	}

	o.cachedClient.Store(client)
	return client, nil
}

func (o *mqlOciIdentityDomain) users() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	users, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.User, *int, error) {
		response, err := client.ListUsers(ctx, identitydomains.ListUsersRequest{
			StartIndex:    common.Int(startIndex),
			Count:         common.Int(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "users")
		}
		return response.Users.Resources, response.Users.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(users))
	for i := range users {
		user := users[i]

		primaryEmail, primaryVerified := ociPrimaryEmail(user.Emails)
		emails, err := convert.JsonToDictSlice(user.Emails)
		if err != nil {
			return nil, err
		}
		groups, err := convert.JsonToDictSlice(user.Groups)
		if err != nil {
			return nil, err
		}

		var (
			mfaStatus, preferredFactor               string
			mfaEnabledOn                             *time.Time
			isLocked                                 bool
			loginAttempts                            int64
			lastSuccessful, prevSuccessful, lastFail *time.Time
			isFederated                              bool
		)

		if mfa := user.UrnIetfParamsScimSchemasOracleIdcsExtensionMfaUser; mfa != nil {
			mfaStatus = string(mfa.MfaStatus)
			preferredFactor = string(mfa.PreferredAuthenticationFactor)
			mfaEnabledOn = ociScimTime(mfa.MfaEnabledOn)
		}

		if state := user.UrnIetfParamsScimSchemasOracleIdcsExtensionUserStateUser; state != nil {
			loginAttempts = int64(intValue(state.LoginAttempts))
			lastSuccessful = ociScimTime(state.LastSuccessfulLoginDate)
			prevSuccessful = ociScimTime(state.PreviousSuccessfulLoginDate)
			lastFail = ociScimTime(state.LastFailedLoginDate)
			if state.Locked != nil {
				isLocked = boolValue(state.Locked.On)
			}
		}

		if ext := user.UrnIetfParamsScimSchemasOracleIdcsExtensionUserUser; ext != nil {
			isFederated = boolValue(ext.IsFederatedUser)
		}

		capabilities := map[string]any{}
		if caps := user.UrnIetfParamsScimSchemasOracleIdcsExtensionCapabilitiesUser; caps != nil {
			capabilities["canUseApiKeys"] = boolValue(caps.CanUseApiKeys)
			capabilities["canUseAuthTokens"] = boolValue(caps.CanUseAuthTokens)
			capabilities["canUseConsolePassword"] = boolValue(caps.CanUseConsolePassword)
			capabilities["canUseCustomerSecretKeys"] = boolValue(caps.CanUseCustomerSecretKeys)
			capabilities["canUseSmtpCredentials"] = boolValue(caps.CanUseSmtpCredentials)
			capabilities["canUseDbCredentials"] = boolValue(caps.CanUseDbCredentials)
			capabilities["canUseConsole"] = boolValue(caps.CanUseConsole)
		}

		mqlUser, err := CreateResource(o.MqlRuntime, "oci.identity.domain.user", map[string]*llx.RawData{
			"__id":                          llx.StringData(o.Id.Data + "/user/" + stringValue(user.Id)),
			"id":                            llx.StringDataPtr(user.Id),
			"ocid":                          llx.StringDataPtr(user.Ocid),
			"userName":                      llx.StringDataPtr(user.UserName),
			"displayName":                   llx.StringDataPtr(user.DisplayName),
			"description":                   llx.StringDataPtr(user.Description),
			"active":                        llx.BoolData(boolValue(user.Active)),
			"userType":                      llx.StringData(string(user.UserType)),
			"primaryEmail":                  llx.StringData(primaryEmail),
			"primaryEmailVerified":          llx.BoolData(primaryVerified),
			"emails":                        llx.ArrayData(emails, types.Dict),
			"isFederated":                   llx.BoolData(isFederated),
			"mfaStatus":                     llx.StringData(mfaStatus),
			"preferredAuthenticationFactor": llx.StringData(preferredFactor),
			"mfaEnabledOn":                  llx.TimeDataPtr(mfaEnabledOn),
			"isLocked":                      llx.BoolData(isLocked),
			"loginAttempts":                 llx.IntData(loginAttempts),
			"lastSuccessfulLogin":           llx.TimeDataPtr(lastSuccessful),
			"previousSuccessfulLogin":       llx.TimeDataPtr(prevSuccessful),
			"lastFailedLogin":               llx.TimeDataPtr(lastFail),
			"capabilities":                  llx.MapData(capabilities, types.Bool),
			"groups":                        llx.ArrayData(groups, types.Dict),
			"created":                       llx.TimeDataPtr(ociScimCreatedAt(user.Meta)),
		})
		if err != nil {
			return nil, err
		}
		mqlUser.(*mqlOciIdentityDomainUser).cacheDomain = o
		mqlUser.(*mqlOciIdentityDomainUser).cacheGroups = user.Groups
		res = append(res, mqlUser)
	}

	return res, nil
}

type mqlOciIdentityDomainUserInternal struct {
	cacheDomain *mqlOciIdentityDomain
	cacheGroups []identitydomains.UserGroups
}

// groupMemberships builds one resource per group the user belongs to.
func (o *mqlOciIdentityDomainUser) groupMemberships() ([]any, error) {
	res := make([]any, 0, len(o.cacheGroups))
	for i := range o.cacheGroups {
		g := o.cacheGroups[i]

		mqlMembership, err := CreateResource(o.MqlRuntime, "oci.identity.domain.user.groupMembership", map[string]*llx.RawData{
			"__id":           llx.StringData(o.__id + "/groupMembership/" + stringValue(g.Value)),
			"membershipOcid": llx.StringDataPtr(g.MembershipOcid),
			"groupId":        llx.StringDataPtr(g.Value),
			"displayName":    llx.StringDataPtr(g.Display),
			"type":           llx.StringData(string(g.Type)),
			"dateAdded":      llx.StringDataPtr(g.DateAdded),
			"externalId":     llx.StringDataPtr(g.ExternalId),
		})
		if err != nil {
			return nil, err
		}
		membership := mqlMembership.(*mqlOciIdentityDomainUserGroupMembership)
		membership.cacheDomain = o.cacheDomain
		membership.cacheGroupOcid = stringValue(g.Ocid)
		res = append(res, membership)
	}
	return res, nil
}

type mqlOciIdentityDomainUserGroupMembershipInternal struct {
	cacheDomain    *mqlOciIdentityDomain
	cacheGroupOcid string
}

// group resolves the membership against the domain's already fetched group
// list. NewResource would re-run the group lookup per membership, since init
// runs before the runtime cache is consulted.
func (o *mqlOciIdentityDomainUserGroupMembership) group() (*mqlOciIdentityDomainGroup, error) {
	if o.cacheDomain == nil {
		o.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	groups := o.cacheDomain.GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}

	if g := ociGroupFromList(groups.Data, o.cacheGroupOcid, o.GroupId.Data); g != nil {
		return g, nil
	}

	// A group the caller cannot read leaves the membership in place with
	// nothing behind it, which is the reading the schema documents.
	o.Group.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ociGroupFromList picks a membership's group out of the domain's group list.
//
// The membership carries both the group's OCID and its SCIM id, and which of
// them is populated varies: OCIDs were added to memberships later, so a domain
// predating that returns only the SCIM id. Matching on either is what keeps
// those domains resolvable. An empty ocid must never match a group that
// reports no OCID, or every membership on such a domain would resolve to
// whichever group came back first.
func ociGroupFromList(groups []any, ocid, groupID string) *mqlOciIdentityDomainGroup {
	// The OCID is scanned across the whole list before the SCIM id is tried, so
	// the stronger key decides even when a weaker match sits earlier in the
	// list.
	if ocid != "" {
		for _, raw := range groups {
			if g, ok := raw.(*mqlOciIdentityDomainGroup); ok && g.Ocid.Data == ocid {
				return g
			}
		}
	}
	if groupID != "" {
		for _, raw := range groups {
			if g, ok := raw.(*mqlOciIdentityDomainGroup); ok && g.Id.Data == groupID {
				return g
			}
		}
	}
	return nil
}

func (o *mqlOciIdentityDomain) groups() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	groups, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.Group, *int, error) {
		response, err := client.ListGroups(ctx, identitydomains.ListGroupsRequest{
			StartIndex:    common.Int(startIndex),
			Count:         common.Int(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "groups")
		}
		return response.Groups.Resources, response.Groups.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(groups))
	for i := range groups {
		group := groups[i]

		isRequestable := false
		if ext := group.UrnIetfParamsScimSchemasOracleIdcsExtensionRequestableGroup; ext != nil {
			isRequestable = boolValue(ext.Requestable)
		}

		mqlGroup, err := CreateResource(o.MqlRuntime, "oci.identity.domain.group", map[string]*llx.RawData{
			"__id":          llx.StringData(o.Id.Data + "/group/" + stringValue(group.Id)),
			"id":            llx.StringDataPtr(group.Id),
			"ocid":          llx.StringDataPtr(group.Ocid),
			"displayName":   llx.StringDataPtr(group.DisplayName),
			"description":   llx.StringData(ociGroupDescription(group)),
			"memberCount":   llx.IntData(int64(len(group.Members))),
			"isRequestable": llx.BoolData(isRequestable),
			"created":       llx.TimeDataPtr(ociScimCreatedAt(group.Meta)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}

	return res, nil
}

func (o *mqlOciIdentityDomain) passwordPolicies() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policies, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.PasswordPolicy, *int, error) {
		response, err := client.ListPasswordPolicies(ctx, identitydomains.ListPasswordPoliciesRequest{
			StartIndex:    common.Int(startIndex),
			Count:         common.Int(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "password policies")
		}
		return response.PasswordPolicies.Resources, response.PasswordPolicies.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policies))
	for i := range policies {
		p := policies[i]

		mqlPolicy, err := CreateResource(o.MqlRuntime, "oci.identity.domain.passwordPolicy", map[string]*llx.RawData{
			"__id":                     llx.StringData(o.Id.Data + "/passwordPolicy/" + stringValue(p.Id)),
			"id":                       llx.StringDataPtr(p.Id),
			"ocid":                     llx.StringDataPtr(p.Ocid),
			"name":                     llx.StringDataPtr(p.Name),
			"description":              llx.StringDataPtr(p.Description),
			"minLength":                llx.IntDataDefault(p.MinLength, 0),
			"maxLength":                llx.IntDataDefault(p.MaxLength, 0),
			"minAlphas":                llx.IntDataDefault(p.MinAlphas, 0),
			"minNumerals":              llx.IntDataDefault(p.MinNumerals, 0),
			"minAlphaNumerals":         llx.IntDataDefault(p.MinAlphaNumerals, 0),
			"minSpecialChars":          llx.IntDataDefault(p.MinSpecialChars, 0),
			"maxSpecialChars":          llx.IntDataDefault(p.MaxSpecialChars, 0),
			"minLowerCase":             llx.IntDataDefault(p.MinLowerCase, 0),
			"minUpperCase":             llx.IntDataDefault(p.MinUpperCase, 0),
			"minUniqueChars":           llx.IntDataDefault(p.MinUniqueChars, 0),
			"maxRepeatedChars":         llx.IntDataDefault(p.MaxRepeatedChars, 0),
			"passwordExpiresAfter":     llx.IntDataDefault(p.PasswordExpiresAfter, 0),
			"passwordExpireWarning":    llx.IntDataDefault(p.PasswordExpireWarning, 0),
			"minPasswordAge":           llx.IntDataDefault(p.MinPasswordAge, 0),
			"numPasswordsInHistory":    llx.IntDataDefault(p.NumPasswordsInHistory, 0),
			"maxIncorrectAttempts":     llx.IntDataDefault(p.MaxIncorrectAttempts, 0),
			"lockoutDuration":          llx.IntDataDefault(p.LockoutDuration, 0),
			"dictionaryWordDisallowed": llx.BoolData(boolValue(p.DictionaryWordDisallowed)),
			"userNameDisallowed":       llx.BoolData(boolValue(p.UserNameDisallowed)),
			"firstNameDisallowed":      llx.BoolData(boolValue(p.FirstNameDisallowed)),
			"lastNameDisallowed":       llx.BoolData(boolValue(p.LastNameDisallowed)),
			"startsWithAlphabet":       llx.BoolData(boolValue(p.StartsWithAlphabet)),
			"disallowedSubstrings":     llx.ArrayData(stringsToAny(p.DisallowedSubstrings), types.String),

			"passwordStrength": llx.StringData(string(p.PasswordStrength)),
			"requiredChars":    llx.StringDataPtr(p.RequiredChars),
			"allowedChars":     llx.StringDataPtr(p.AllowedChars),
			"disallowedChars":  llx.StringDataPtr(p.DisallowedChars),
			// distinctCharacters and priority stay null when IDCS does not
			// return them. Defaulting to 0 the way the older fields above do
			// would assert two things that are not known to be true: that a
			// single-character edit is an acceptable password change, and that
			// this policy outranks every other one.
			"distinctCharacters":            llx.IntDataPtr(p.DistinctCharacters),
			"forcePasswordReset":            llx.BoolData(boolValue(p.ForcePasswordReset)),
			"disallowedUserAttributeValues": llx.ArrayData(stringsToAny(p.DisallowedUserAttributeValues), types.String),
			"dictionaryLocation":            llx.StringDataPtr(p.DictionaryLocation),
			"priority":                      llx.IntDataPtr(p.Priority),
		})
		if err != nil {
			return nil, err
		}
		mqlPolicyRes := mqlPolicy.(*mqlOciIdentityDomainPasswordPolicy)
		mqlPolicyRes.cacheDomain = o
		for _, g := range p.Groups {
			if g.Value != nil {
				mqlPolicyRes.cacheGroupIDs = append(mqlPolicyRes.cacheGroupIDs, *g.Value)
			}
		}
		res = append(res, mqlPolicyRes)
	}

	return res, nil
}

type mqlOciIdentityDomainPasswordPolicyInternal struct {
	cacheDomain   *mqlOciIdentityDomain
	cacheGroupIDs []string
}

// groups resolves the policy's group references against the domain's already
// fetched group list. Resolving each one through NewResource would re-run the
// group init per reference, since init runs before the runtime cache is
// consulted.
func (o *mqlOciIdentityDomainPasswordPolicy) groups() ([]any, error) {
	if len(o.cacheGroupIDs) == 0 || o.cacheDomain == nil {
		return []any{}, nil
	}

	groups := o.cacheDomain.GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}

	byID := make(map[string]any, len(groups.Data))
	for _, raw := range groups.Data {
		g, ok := raw.(*mqlOciIdentityDomainGroup)
		if !ok {
			continue
		}
		byID[g.Id.Data] = g
	}

	res := make([]any, 0, len(o.cacheGroupIDs))
	for _, id := range o.cacheGroupIDs {
		if g, ok := byID[id]; ok {
			res = append(res, g)
			continue
		}
		// A group the caller cannot read is skipped rather than failing the
		// whole list, which would hide the groups that did resolve.
		log.Debug().Str("group", id).Msg("skipping unresolvable oci password policy group")
	}
	return res, nil
}

func (o *mqlOciIdentityDomain) authenticationFactorSettings() (*mqlOciIdentityDomainAuthenticationFactorSettings, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	response, err := client.ListAuthenticationFactorSettings(context.Background(),
		identitydomains.ListAuthenticationFactorSettingsRequest{})
	if err != nil {
		return nil, ociScimError(err, o.Name.Data, "authentication factor settings")
	}

	// The service models this as a collection, but a domain has exactly one
	// settings resource. An empty collection means the domain returned no
	// multi-factor configuration at all, which is a null answer rather than a
	// domain with every factor disabled - reporting the latter would assert
	// something the API never said.
	if len(response.AuthenticationFactorSettings.Resources) == 0 {
		o.AuthenticationFactorSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	s := response.AuthenticationFactorSettings.Resources[0]

	res, err := CreateResource(o.MqlRuntime, "oci.identity.domain.authenticationFactorSettings", map[string]*llx.RawData{
		"__id":                     llx.StringData(o.Id.Data + "/authenticationFactorSettings"),
		"id":                       llx.StringDataPtr(s.Id),
		"smsEnabled":               llx.BoolData(boolValue(s.SmsEnabled)),
		"emailEnabled":             llx.BoolData(boolValue(s.EmailEnabled)),
		"totpEnabled":              llx.BoolData(boolValue(s.TotpEnabled)),
		"pushEnabled":              llx.BoolData(boolValue(s.PushEnabled)),
		"phoneCallEnabled":         llx.BoolData(boolValue(s.PhoneCallEnabled)),
		"fidoAuthenticatorEnabled": llx.BoolData(boolValue(s.FidoAuthenticatorEnabled)),
		"yubicoOtpEnabled":         llx.BoolData(boolValue(s.YubicoOtpEnabled)),
		"securityQuestionsEnabled": llx.BoolData(boolValue(s.SecurityQuestionsEnabled)),
		"bypassCodeEnabled":        llx.BoolData(boolValue(s.BypassCodeEnabled)),
		"mfaEnrollmentType":        llx.StringDataPtr(s.MfaEnrollmentType),
		"mfaEnabledCategory":       llx.StringDataPtr(s.MfaEnabledCategory),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciIdentityDomainAuthenticationFactorSettings), nil
}

func (o *mqlOciIdentityDomain) apps() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	apps, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.App, *int, error) {
		response, err := client.ListApps(ctx, identitydomains.ListAppsRequest{
			StartIndex:    common.Int(startIndex),
			Count:         common.Int(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "apps")
		}
		return response.Apps.Resources, response.Apps.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(apps))
	for i := range apps {
		app := apps[i]

		mqlApp, err := CreateResource(o.MqlRuntime, "oci.identity.domain.app", map[string]*llx.RawData{
			"__id":            llx.StringData(o.Id.Data + "/app/" + stringValue(app.Id)),
			"id":              llx.StringDataPtr(app.Id),
			"name":            llx.StringDataPtr(app.Name),
			"displayName":     llx.StringDataPtr(app.DisplayName),
			"description":     llx.StringDataPtr(app.Description),
			"active":          llx.BoolData(boolValue(app.Active)),
			"isOAuthClient":   llx.BoolData(boolValue(app.IsOAuthClient)),
			"isOAuthResource": llx.BoolData(boolValue(app.IsOAuthResource)),
			"clientType":      llx.StringData(string(app.ClientType)),
			"allowedGrants":   llx.ArrayData(stringsToAny(app.AllowedGrants), types.String),
			"landingPageUrl":  llx.StringDataPtr(app.LandingPageUrl),
			"isWebTierPolicy": llx.BoolData(boolValue(app.IsWebTierPolicy)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlApp)
	}

	return res, nil
}

// ociScimNextIndex advances a SCIM startIndex/count pagination loop.
//
// SCIM indexes are 1-based and the service reports the total separately from
// the page, so the loop cannot stop on an absent page token the way the rest of
// OCI does. It returns the next start index and whether another page is due.
//
// A page that comes back empty always terminates the loop: without that guard a
// service reporting a total larger than it will actually return - or a page
// truncated for any reason - would spin forever.
//
// pageSize is passed in rather than read from the package constant so the
// short-page heuristic below stays correct if a caller ever requests a
// different size.
func ociScimNextIndex(startIndex int, returned int, total *int, pageSize int) (int, bool) {
	if returned == 0 {
		return 0, false
	}
	next := startIndex + returned
	if total == nil {
		// No total to compare against: keep going only while pages come back
		// full, since a short page means the collection is exhausted.
		return next, returned >= pageSize
	}
	if next > *total {
		return 0, false
	}
	return next, true
}

// ociPrimaryEmail picks the primary address out of a SCIM emails list, falling
// back to the first entry when none is flagged primary.
func ociPrimaryEmail(emails []identitydomains.UserEmails) (string, bool) {
	if len(emails) == 0 {
		return "", false
	}
	for i := range emails {
		if boolValue(emails[i].Primary) {
			return stringValue(emails[i].Value), boolValue(emails[i].Verified)
		}
	}
	return stringValue(emails[0].Value), boolValue(emails[0].Verified)
}

// ociScimTime parses an RFC3339 timestamp carried as a SCIM string field.
//
// Returns nil for an absent or unparseable value. Nil is the right answer for
// both: an account that has never signed in has no lastSuccessfulLoginDate at
// all, and that is a distinct state from having signed in long ago - which is
// exactly the distinction a stale-account query needs. A malformed timestamp is
// not worth failing the whole listing over.
func ociScimTime(value *string) *time.Time {
	if value == nil || *value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return nil
	}
	return &parsed
}

// ociScimCreatedAt pulls the creation timestamp out of a SCIM meta block.
func ociScimCreatedAt(meta *identitydomains.Meta) *time.Time {
	if meta == nil {
		return nil
	}
	return ociScimTime(meta.Created)
}

// ociGroupDescription reads a group's description, which SCIM carries on an
// extension rather than on the group itself.
func ociGroupDescription(group identitydomains.Group) string {
	if ext := group.UrnIetfParamsScimSchemasOracleIdcsExtensionGroupGroup; ext != nil {
		return stringValue(ext.Description)
	}
	return ""
}

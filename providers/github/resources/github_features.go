// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/github/connection"
)

// The first GitHub Enterprise Server release to carry each feature. The three
// at 3.0 predate every release GitHub still supports; they are listed anyway so
// the table is a complete statement of what gates what, rather than a list of
// the exceptions somebody happened to remember.
//
// ghesFloorPatApproval gates the approvedTokens field. It is not named after
// the field because a constant whose name carries a credential word and whose
// value is a string literal trips the secret scanner, whatever the value is.
const (
	ghesFloorAuditLog          = "3.0"
	ghesFloorSamlSingleSignOn  = "3.0"
	ghesFloorIpAllowList       = "3.0"
	ghesFloorCustomRoles       = "3.13"
	ghesFloorPatApproval       = "3.12"
	ghesFloorAuditLogStreaming = "3.16"
)

// enterprisePlanNames are the plan names that carry the Enterprise feature set
// on GitHub.com. GitHub does not publish the full set of plan names:
// `enterprise` is what a current GitHub Enterprise Cloud account reports, and
// `business` and `business_plus` are what accounts created under that plan's
// earlier names still report. A name outside this set is read as an account
// without the feature set, which is the direction that reports a finding
// rather than hiding one.
var enterprisePlanNames = map[string]bool{
	"enterprise":    true,
	"business":      true,
	"business_plus": true,
}

// githubFeatureAvailability answers, for each feature GitHub gates behind an
// Enterprise account, whether this account carries it. A nil answer means the
// question could not be answered, and the field reads null rather than
// asserting a tier nobody measured.
type githubFeatureAvailability struct {
	AuditLog          *bool
	SamlSingleSignOn  *bool
	IpAllowList       *bool
	CustomRoles       *bool
	ApprovedTokens    *bool
	AuditLogStreaming *bool
}

// githubFeatures decides which Enterprise-gated features an account carries.
//
// A GitHub Enterprise Server installation carries a feature once it runs the
// release that introduced it, so the answer comes from ghesVersion. Everything
// else is GitHub.com, where the answer comes from the plan name and is the same
// for every feature. Either input being unknown yields an all-nil result: an
// installation that withholds its release, and an organization whose plan the
// token may not read, are both cases where guessing would put an unmeasured
// claim into an audit.
func githubFeatures(planName, ghesVersion string, enterpriseServer bool) githubFeatureAvailability {
	if enterpriseServer {
		if ghesVersion == "" {
			return githubFeatureAvailability{}
		}
		atLeast := func(floor string) *bool {
			carries := compareGhesVersions(ghesVersion, floor) >= 0
			return &carries
		}
		return githubFeatureAvailability{
			AuditLog:          atLeast(ghesFloorAuditLog),
			SamlSingleSignOn:  atLeast(ghesFloorSamlSingleSignOn),
			IpAllowList:       atLeast(ghesFloorIpAllowList),
			CustomRoles:       atLeast(ghesFloorCustomRoles),
			ApprovedTokens:    atLeast(ghesFloorPatApproval),
			AuditLogStreaming: atLeast(ghesFloorAuditLogStreaming),
		}
	}

	if planName == "" {
		return githubFeatureAvailability{}
	}

	carries := func() *bool {
		v := enterprisePlanNames[strings.ToLower(planName)]
		return &v
	}
	return githubFeatureAvailability{
		AuditLog:          carries(),
		SamlSingleSignOn:  carries(),
		IpAllowList:       carries(),
		CustomRoles:       carries(),
		ApprovedTokens:    carries(),
		AuditLogStreaming: carries(),
	}
}

// compareGhesVersions orders two GitHub Enterprise Server release strings,
// returning -1 when a sorts before b, 1 when after, and 0 when they are equal.
// Components compare numerically and a missing component counts as zero, so
// "3.16" and "3.16.0" are equal. Parsing stops at the first component that is
// not a number, which is how a pre-release build such as "3.17.0.rc1" compares
// as 3.17.0.
func compareGhesVersions(a, b string) int {
	as := ghesVersionComponents(a)
	bs := ghesVersionComponents(b)

	n := max(len(as), len(bs))

	for i := range n {
		x, y := 0, 0
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func ghesVersionComponents(v string) []int {
	var out []int
	for part := range strings.SplitSeq(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// boolOrNil keeps an unmeasured answer null instead of collapsing it to false.
func boolOrNil(v *bool) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.BoolData(*v)
}

func (g *mqlGithubOrganizationSubscription) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganizationFeatures) id() (string, error) {
	return g.__id, nil
}

// initGithubOrganizationSubscription resolves the resource for a query written
// against its own path, github.organization.subscription, rather than reached
// through the organization. Without it that path builds an empty resource whose
// every field reads null.
func initGithubOrganizationSubscription(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	subscription := org.(*mqlGithubOrganization).GetSubscription()
	if subscription.Error != nil {
		return nil, nil, subscription.Error
	}
	if subscription.Data == nil {
		return nil, nil, errors.New("no plan is available for this organization (GitHub reports a plan only to a token with owner access, and a GitHub Enterprise Server installation reports none)")
	}
	return args, subscription.Data, nil
}

// initGithubOrganizationFeatures resolves the resource for a query written
// against its own path, which is the shape a policy filter takes. Unlike the
// other organization sub-resources this one never resolves to nothing: an
// account whose tier could not be read reports null fields, so a filter skips
// the check rather than failing on an error.
func initGithubOrganizationFeatures(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	features := org.(*mqlGithubOrganization).GetFeatures()
	if features.Error != nil {
		return nil, nil, features.Error
	}
	return args, features.Data, nil
}

func (g *mqlGithubOrganization) subscription() (*mqlGithubOrganizationSubscription, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	orgName := g.Name.Data

	// getOrg memoizes on the same name the organization was built from, so this
	// reads the record already fetched rather than costing another call.
	org, err := getOrg(conn.Context(), g.MqlRuntime, conn, orgName)
	if err != nil {
		return nil, err
	}
	if org == nil || org.Plan == nil {
		// GitHub reports a plan only to a token with owner access on the
		// organization, and a GitHub Enterprise Server installation reports
		// none at all. Neither is a free plan, so neither may read as one.
		g.Subscription.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(g.MqlRuntime, "github.organization.subscription", map[string]*llx.RawData{
		"__id":          llx.StringData("github.organization.subscription/" + orgName),
		"name":          llx.StringDataPtr(org.Plan.Name),
		"space":         llx.IntDataPtr(org.Plan.Space),
		"collaborators": llx.IntDataPtr(org.Plan.Collaborators),
		"privateRepos":  llx.IntDataPtr(org.Plan.PrivateRepos),
		"filledSeats":   llx.IntDataPtr(org.Plan.FilledSeats),
		"seats":         llx.IntDataPtr(org.Plan.Seats),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationSubscription), nil
}

func (g *mqlGithubOrganization) features() (*mqlGithubOrganizationFeatures, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	orgName := g.Name.Data

	enterpriseServer, err := conn.IsEnterpriseServer()
	if err != nil {
		return nil, err
	}
	ghesVersion, err := conn.EnterpriseVersion()
	if err != nil {
		return nil, err
	}

	// A GitHub Enterprise Server installation serves no plan, so asking for one
	// would spend a call to learn nothing.
	planName := ""
	if !enterpriseServer {
		subscription := g.GetSubscription()
		if subscription.Error != nil {
			return nil, subscription.Error
		}
		if subscription.Data != nil {
			name := subscription.Data.GetName()
			if name.Error != nil {
				return nil, name.Error
			}
			planName = name.Data
		}
	}

	available := githubFeatures(planName, ghesVersion, enterpriseServer)
	res, err := CreateResource(g.MqlRuntime, "github.organization.features", map[string]*llx.RawData{
		"__id":              llx.StringData("github.organization.features/" + orgName),
		"auditLog":          boolOrNil(available.AuditLog),
		"samlSingleSignOn":  boolOrNil(available.SamlSingleSignOn),
		"ipAllowList":       boolOrNil(available.IpAllowList),
		"customRoles":       boolOrNil(available.CustomRoles),
		"approvedTokens":    boolOrNil(available.ApprovedTokens),
		"auditLogStreaming": boolOrNil(available.AuditLogStreaming),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationFeatures), nil
}

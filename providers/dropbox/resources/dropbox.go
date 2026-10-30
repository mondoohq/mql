// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team_policies"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/dropbox/connection"
)

func (r *mqlDropbox) id() (string, error) {
	return "dropbox", nil
}

// id returns the team ID as the resource's cache key. There is exactly one
// team per connection, so this is a stable, natural key.
func (r *mqlDropboxTeam) id() (string, error) {
	return "dropbox.team/" + r.Id.Data, nil
}

// conn returns the Dropbox connection backing this runtime.
func (r *mqlDropbox) conn() *connection.DropboxConnection {
	return r.MqlRuntime.Connection.(*connection.DropboxConnection)
}

// initDropboxTeam reads the team-wide identity and sharing configuration
// singleton. There is exactly one team per connection, so it resolves entirely
// from the connection and uses the team ID as its cache key.
func initDropboxTeam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.DropboxConnection)
	client := conn.Client()

	info, err := conn.TeamInfo()
	if err != nil {
		return nil, nil, err
	}

	externalSharingAllowed, publicSharingAllowed := deriveSharingPolicies(info.Policies)

	var uploadRateLimit int64
	features, err := client.FeaturesGetValues(&team.FeaturesGetValuesBatchArg{
		Features: []*team.Feature{{Tag: team.FeatureUploadApiRateLimit}},
	})
	if err != nil {
		// A missing scope or transient failure leaves uploadApiRateLimit at 0,
		// which is indistinguishable from "unlimited"; log so operators can tell
		// the difference when diagnosing a misconfigured token.
		log.Warn().Err(err).Msg("dropbox: could not fetch team upload API rate limit")
	} else {
		for _, v := range features.Values {
			if v.UploadApiRateLimit != nil && v.UploadApiRateLimit.Tag == team.UploadApiRateLimitValueLimit {
				uploadRateLimit = int64(v.UploadApiRateLimit.Limit)
			}
		}
	}

	args["__id"] = llx.StringData(info.TeamId)
	args["id"] = llx.StringData(info.TeamId)
	args["name"] = llx.StringData(info.Name)
	args["numLicensedUsers"] = llx.IntData(int64(info.NumLicensedUsers))
	args["numProvisionedUsers"] = llx.IntData(int64(info.NumProvisionedUsers))
	args["numUsedLicenses"] = llx.IntData(int64(info.NumUsedLicenses))
	args["externalSharingAllowed"] = llx.BoolData(externalSharingAllowed)
	args["publicSharingAllowed"] = llx.BoolData(publicSharingAllowed)
	args["uploadApiRateLimit"] = llx.IntData(uploadRateLimit)

	return args, nil, nil
}

// deriveSharingPolicies maps a team's sharing policy tags to the two booleans
// the team resource exposes. externalSharingAllowed is true when shared
// folders may include members from outside the team; publicSharingAllowed is
// true when team members are permitted to create shared links with a public
// (non-team) audience.
func deriveSharingPolicies(policies *team_policies.TeamMemberPolicies) (externalSharingAllowed, publicSharingAllowed bool) {
	if policies == nil || policies.Sharing == nil {
		return false, false
	}
	sharing := policies.Sharing
	if sharing.SharedFolderMemberPolicy != nil {
		// "team" means only team members may join a shared folder; anything
		// else (anyone, team_and_approved) admits members from outside the team.
		externalSharingAllowed = sharing.SharedFolderMemberPolicy.Tag != "team"
	}
	if sharing.SharedLinkCreatePolicy != nil {
		// "team_only" and "default_no_one" bar members from creating a public
		// link; the other tags (default_public, default_team_only) permit one.
		tag := sharing.SharedLinkCreatePolicy.Tag
		publicSharingAllowed = tag != "team_only" && tag != "default_no_one"
	}
	return externalSharingAllowed, publicSharingAllowed
}

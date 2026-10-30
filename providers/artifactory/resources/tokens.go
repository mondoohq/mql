// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// adminScope is the scope that lifts a token above every permission target.
const adminScope = "applied-permissions/admin"

type tokenListResponse struct {
	Tokens []tokenRecord `json:"tokens"`
}

// tokenRecord is a token as the Access API reports it. Expiry and issue time
// are epoch seconds, and a token that never expires carries no expiry at all.
type tokenRecord struct {
	TokenID     string `json:"token_id"`
	Subject     string `json:"subject"`
	Description string `json:"description"`
	Issuer      string `json:"issuer"`
	Scope       string `json:"scope"`
	Refreshable bool   `json:"refreshable"`
	Expiry      int64  `json:"expiry"`
	IssuedAt    int64  `json:"issued_at"`
}

func (a *mqlArtifactory) accessTokens() ([]any, error) {
	conn := artifactoryConn(a.MqlRuntime)

	var response tokenListResponse
	if err := conn.GetJSON(context.Background(), conn.AccessURL("/api/v1/tokens"), &response); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(response.Tokens))
	for i := range response.Tokens {
		token, err := newArtifactoryAccessToken(a.MqlRuntime, &response.Tokens[i])
		if err != nil {
			return nil, err
		}
		res = append(res, token)
	}
	return res, nil
}

type mqlArtifactoryAccessTokenInternal struct {
	// subject is the full principal string, which the user reference is
	// resolved from.
	subject string
}

func newArtifactoryAccessToken(runtime *plugin.Runtime, rec *tokenRecord) (*mqlArtifactoryAccessToken, error) {
	scopes := splitScope(rec.Scope)

	res, err := CreateResource(runtime, "artifactory.accessToken", map[string]*llx.RawData{
		"id":          llx.StringData(rec.TokenID),
		"subject":     llx.StringData(rec.Subject),
		"description": optionalString(rec.Description),
		"issuer":      llx.StringData(rec.Issuer),
		"scope":       llx.ArrayData(strSliceToAny(scopes), types.String),
		"grantsAdmin": llx.BoolData(grantsAdmin(scopes)),
		"refreshable": llx.BoolData(rec.Refreshable),
		"expiry":      llx.TimeDataPtr(epochTime(rec.Expiry)),
		"expires":     llx.BoolData(rec.Expiry > 0),
		"issuedAt":    llx.TimeDataPtr(epochTime(rec.IssuedAt)),
	})
	if err != nil {
		return nil, err
	}

	token := res.(*mqlArtifactoryAccessToken)
	token.subject = rec.Subject
	return token, nil
}

func (t *mqlArtifactoryAccessToken) id() (string, error) {
	return "artifactory.accessToken/" + t.Id.Data, t.Id.Error
}

// subjectRef resolves the principal the token acts as. The subject is a
// slash-separated path, for example jfrt@01ab2c3d/users/example, so the
// account name is its last segment. A subject that is not a user, such as a
// service subject, reports null.
func (t *mqlArtifactoryAccessToken) subjectRef() (*mqlArtifactoryUser, error) {
	name := subjectUserName(t.subject)
	if name == "" {
		t.SubjectRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	user, err := findUser(t.MqlRuntime, name)
	if err != nil {
		return nil, err
	}
	if user == nil {
		t.SubjectRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return user, nil
}

// subjectUserName pulls the account name out of a token subject. It returns
// the empty string when the subject does not name a user.
func subjectUserName(subject string) string {
	parts := strings.Split(subject, "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "users" {
			return strings.Join(parts[i+1:], "/")
		}
	}
	return ""
}

// splitScope turns the space-separated scope string into its entries. An empty
// scope reports an empty list rather than a list holding one empty entry.
func splitScope(scope string) []string {
	return strings.Fields(scope)
}

func grantsAdmin(scopes []string) bool {
	for _, scope := range scopes {
		if strings.EqualFold(scope, adminScope) {
			return true
		}
	}
	return false
}

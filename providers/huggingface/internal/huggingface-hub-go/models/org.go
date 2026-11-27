// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

// OrgMember is one entry of GET /api/organizations/{name}/members. The
// admin-only fields are pointers so that a field the Hub did not report stays
// apart from a reported false or empty value.
type OrgMember struct {
	ID                     string                   `json:"_id"`
	User                   string                   `json:"user"`
	Fullname               string                   `json:"fullname"`
	Role                   string                   `json:"role"`
	TwoFaEnabled           *bool                    `json:"twoFaEnabled"`
	IsExternalCollaborator *bool                    `json:"isExternalCollaborator"`
	VerifiedEmail          *string                  `json:"verifiedEmail"`
	ResourceGroups         []OrgMemberResourceGroup `json:"resourceGroups"`
}

type OrgMemberResourceGroup struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	AssignedRole string `json:"assignedRole"`
}

// OrgNetworkSecurity is GET /api/organizations/{name}/settings/network-security.
type OrgNetworkSecurity struct {
	EnforceAuth           *bool        `json:"enforceAuth"`
	EnforceIPRestriction  *bool        `json:"enforceIpRestriction"`
	AreCidrRangesApproved *bool        `json:"areCidrRangesApproved"`
	IPRanges              []string     `json:"ipRanges"`
	BlockedContents       []ContentRef `json:"blockedContents"`
	AllowedContents       []ContentRef `json:"allowedContents"`
}

// ContentRef is one content rule: a kind of repository ("*" for every kind)
// and the scope it matches.
type ContentRef struct {
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
}

// OrgMemberToken is one entry of GET /api/organizations/{name}/settings/tokens.
// The list also carries last4, the last characters of the token value; it is
// deliberately not decoded.
type OrgMemberToken struct {
	ID            string                 `json:"_id"`
	DisplayName   *string                `json:"displayName"`
	Role          string                 `json:"role"`
	CreatedAt     string                 `json:"createdAt"`
	LastUsedAt    string                 `json:"lastUsedAt"`
	Owner         OrgTokenOwner          `json:"owner"`
	Authorization *OrgTokenAuthorization `json:"authorization"`
	// FineGrained is absent on read and write tokens.
	FineGrained *OrgTokenFineGrained `json:"fineGrained"`
}

type OrgTokenOwner struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
}

type OrgTokenAuthorization struct {
	Status string `json:"status"`
}

type OrgTokenFineGrained struct {
	Scoped []Scoped `json:"scoped"`
}

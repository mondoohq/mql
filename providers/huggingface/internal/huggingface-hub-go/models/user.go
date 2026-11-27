// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

type User struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Fullname  string `json:"fullname"`
	IsPro     bool   `json:"isPro"`
	AvatarURL string `json:"avatarUrl"`
	Orgs      []Org  `json:"orgs"`
	Auth      Auth   `json:"auth"`
}

type Org struct {
	Type         string `json:"type"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Fullname     string `json:"fullname"`
	Email        string `json:"email,omitempty"`
	CanPay       bool   `json:"canPay,omitempty"`
	PeriodEnd    int64  `json:"periodEnd,omitempty"`
	AvatarURL    string `json:"avatarUrl"`
	RoleInOrg    string `json:"roleInOrg,omitempty"`
	IsEnterprise bool   `json:"isEnterprise"`
	// Plan is absent on an organization without a paid plan.
	Plan string `json:"plan,omitempty"`
	// SecurityRestrictions is nil when the Hub did not report the list, which
	// keeps an unreported list apart from an empty one.
	SecurityRestrictions *[]string `json:"securityRestrictions,omitempty"`
}

type Auth struct {
	Type        string      `json:"type"`
	AccessToken AccessToken `json:"accessToken"`
	// ExpiresAt is absent for a credential that never expires.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type AccessToken struct {
	DisplayName string      `json:"displayName"`
	Role        string      `json:"role"`
	CreatedAt   string      `json:"createdAt"`
	FineGrained FineGrained `json:"fineGrained"`
}

type FineGrained struct {
	CanReadGatedRepos bool     `json:"canReadGatedRepos"`
	Global            []string `json:"global"`
	Scoped            []Scoped `json:"scoped"`
}

type Scoped struct {
	Entity      Entity   `json:"entity"`
	Permissions []string `json:"permissions"`
}

type Entity struct {
	ID   string `json:"_id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

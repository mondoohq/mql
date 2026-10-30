// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

func orgItem(publicId string) datadogV2.UserResponseIncludedItem {
	attrs := datadogV2.NewOrganizationAttributes()
	if publicId != "" {
		attrs.SetPublicId(publicId)
	}
	org := datadogV2.NewOrganization(datadogV2.ORGANIZATIONSTYPE_ORGS)
	org.SetAttributes(*attrs)
	return datadogV2.UserResponseIncludedItem{Organization: org}
}

func roleItem() datadogV2.UserResponseIncludedItem {
	return datadogV2.UserResponseIncludedItem{
		Role: datadogV2.NewRole(datadogV2.ROLESTYPE_ROLES),
	}
}

func TestOrgPublicIdFromUser(t *testing.T) {
	tests := []struct {
		name     string
		included []datadogV2.UserResponseIncludedItem
		want     string
	}{
		{
			name: "organization is the only included item",
			included: []datadogV2.UserResponseIncludedItem{
				orgItem("abc123"),
			},
			want: "abc123",
		},
		{
			// The included array is a union; roles and permissions come back
			// alongside the organization and must not stop the search.
			name: "organization follows other union arms",
			included: []datadogV2.UserResponseIncludedItem{
				roleItem(),
				{Permission: datadogV2.NewPermission(datadogV2.PERMISSIONSTYPE_PERMISSIONS)},
				orgItem("def456"),
			},
			want: "def456",
		},
		{
			name:     "no included items",
			included: nil,
			want:     "",
		},
		{
			name:     "no organization among the included items",
			included: []datadogV2.UserResponseIncludedItem{roleItem()},
			want:     "",
		},
		{
			// A present organization carrying no public ID must not be
			// mistaken for a usable identity.
			name:     "organization without a public id",
			included: []datadogV2.UserResponseIncludedItem{orgItem("")},
			want:     "",
		},
		{
			name: "organization without a public id followed by one with",
			included: []datadogV2.UserResponseIncludedItem{
				orgItem(""),
				orgItem("ghi789"),
			},
			want: "ghi789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := datadogV2.UserResponse{}
			if tt.included != nil {
				resp.SetIncluded(tt.included)
			}
			if got := orgPublicIdFromUser(resp); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestOrgPublicIdFromUser_NilAttributes(t *testing.T) {
	// Organization.Attributes is optional, so an included organization can
	// arrive with no attributes at all. The generated getters guard a nil
	// receiver, so this must return empty rather than panic.
	resp := datadogV2.UserResponse{}
	resp.SetIncluded([]datadogV2.UserResponseIncludedItem{
		{Organization: datadogV2.NewOrganization(datadogV2.ORGANIZATIONSTYPE_ORGS)},
	})

	if got := orgPublicIdFromUser(resp); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestUnstableOperationsAreRecognized(t *testing.T) {
	// SetUnstableOperationEnabled reports false for a name the SDK does not
	// know, and changes nothing. A typo here would leave the operation disabled,
	// so the resource would report an error on every organization instead of
	// data, with nothing in the build to say why.
	cfg := datadog.NewConfiguration()
	for _, op := range unstableOperations {
		if !cfg.SetUnstableOperationEnabled(op, true) {
			t.Errorf("%q is not an unstable operation in this SDK version", op)
			continue
		}
		if !cfg.IsUnstableOperationEnabled(op) {
			t.Errorf("%q was not enabled", op)
		}
	}
}

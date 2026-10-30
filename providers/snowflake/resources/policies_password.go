// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

func (r *mqlSnowflakeAccount) passwordPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	passwordPolicies, err := client.PasswordPolicies.Show(ctx, &sdk.ShowPasswordPolicyRequest{
		In: &sdk.ExtendedIn{
			Account: new(true)},
	})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range passwordPolicies {
		mqlPasswordPolicy, err := newMqlSnowflakePasswordPolicy(r.MqlRuntime, passwordPolicies[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPasswordPolicy)
	}

	return list, nil
}

func newMqlSnowflakePasswordPolicy(runtime *plugin.Runtime, passwordPolicy sdk.PasswordPolicy) (*mqlSnowflakePasswordPolicy, error) {
	r, err := CreateResource(runtime, "snowflake.passwordPolicy", map[string]*llx.RawData{
		"__id":         llx.StringData(passwordPolicy.ID().FullyQualifiedName()),
		"name":         llx.StringData(passwordPolicy.Name),
		"databaseName": llx.StringData(passwordPolicy.DatabaseName),
		"schemaName":   llx.StringData(passwordPolicy.SchemaName),
		"kind":         llx.StringData(passwordPolicy.Kind),
		"comment":      llx.StringData(passwordPolicy.Comment),
		"createdAt":    llx.TimeData(passwordPolicy.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakePasswordPolicy)
	mqlResource.cacheOwner = passwordPolicy.Owner
	return mqlResource, nil
}

// mqlSnowflakePasswordPolicyInternal holds the owning role name that the owner
// reference resolves, and the memoized outcome of the policy's own
// POLICY_REFERENCES lookup.
type mqlSnowflakePasswordPolicyInternal struct {
	cacheOwner string
	refsMemo   policyReferenceMemo
}

func (r *mqlSnowflakePasswordPolicy) gatherPasswordPolicyDetails() error {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	properties, err := client.PasswordPolicies.Describe(ctx, sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data))
	if err != nil {
		return err
	}
	values := passwordPolicyIntProperties(properties)

	r.PasswordMinLength = passwordPolicyIntValue(values, "PASSWORD_MIN_LENGTH")
	r.PasswordMaxLength = passwordPolicyIntValue(values, "PASSWORD_MAX_LENGTH")
	r.PasswordMinUpperCaseChars = passwordPolicyIntValue(values, "PASSWORD_MIN_UPPER_CASE_CHARS")
	r.PasswordMinLowerCaseChars = passwordPolicyIntValue(values, "PASSWORD_MIN_LOWER_CASE_CHARS")
	r.PasswordMinNumericChars = passwordPolicyIntValue(values, "PASSWORD_MIN_NUMERIC_CHARS")
	r.PasswordMinSpecialChars = passwordPolicyIntValue(values, "PASSWORD_MIN_SPECIAL_CHARS")
	r.PasswordMinAgeDays = passwordPolicyIntValue(values, "PASSWORD_MIN_AGE_DAYS")
	r.PasswordMaxAgeDays = passwordPolicyIntValue(values, "PASSWORD_MAX_AGE_DAYS")
	r.PasswordMaxRetries = passwordPolicyIntValue(values, "PASSWORD_MAX_RETRIES")
	r.PasswordLockoutTimeMins = passwordPolicyIntValue(values, "PASSWORD_LOCKOUT_TIME_MINS")
	r.PasswordHistory = passwordPolicyIntValue(values, "PASSWORD_HISTORY")

	return nil
}

// passwordPolicyIntProperties collects the integer-valued rows of DESCRIBE
// PASSWORD POLICY, keyed by property name. A row whose value does not parse as
// an integer (such as NAME, OWNER, or COMMENT) is left out.
func passwordPolicyIntProperties(properties []sdk.PasswordPolicyProperty) map[string]int64 {
	values := make(map[string]int64, len(properties))
	for _, prop := range properties {
		v, err := strconv.ParseInt(strings.TrimSpace(prop.Value), 10, 64)
		if err != nil {
			continue
		}
		values[prop.Property] = v
	}
	return values
}

// passwordPolicyIntValue returns the named property as a set field, or a null
// field when DESCRIBE did not report it, so a missing setting does not read as
// zero.
func passwordPolicyIntValue(values map[string]int64, property string) plugin.TValue[int64] {
	v, ok := values[property]
	if !ok {
		return plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[int64]{Data: v, State: plugin.StateIsSet}
}

func (r *mqlSnowflakePasswordPolicy) passwordMinLength() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMaxLength() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMinUpperCaseChars() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMinLowerCaseChars() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMinNumericChars() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMinSpecialChars() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMinAgeDays() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMaxAgeDays() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordMaxRetries() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordLockoutTimeMins() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) passwordHistory() (int64, error) {
	return 0, r.gatherPasswordPolicyDetails()
}

func (r *mqlSnowflakePasswordPolicy) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

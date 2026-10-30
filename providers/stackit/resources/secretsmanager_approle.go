// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	secretsmanager "github.com/stackitcloud/stackit-sdk-go/services/secretsmanager/v1api"
	"go.mondoo.com/mql/llx"
)

// mqlStackitSecretsManagerApproleInternal caches the owning instance id so the
// back-reference resolves without the schema repeating it as a raw field, and
// so the secret ID listing can address the approle's parent.
type mqlStackitSecretsManagerApproleInternal struct {
	cacheInstanceId string
}

// secretIdTtlUnits maps the duration suffixes the Secrets Manager API
// documents for a secret ID lifetime onto seconds. The API constrains the
// value with the pattern ^[0-9]+[smh]$, so anything outside this set is not a
// duration the service produces, and reads as null rather than as a silently
// wrong number of seconds.
var secretIdTtlUnits = map[byte]int64{
	's': 1,
	'm': 60,
	'h': 3600,
}

// ttlSeconds converts a Secrets Manager duration string ("15m", "1h", "30s")
// into seconds. It returns nil when the value is absent or is not one of the
// documented forms, so a lifetime the service did not report stays null
// instead of collapsing into zero, which the service uses for "never
// expires".
func ttlSeconds(ttl string) *int64 {
	if len(ttl) < 2 {
		return nil
	}
	unit, ok := secretIdTtlUnits[ttl[len(ttl)-1]]
	if !ok {
		return nil
	}
	digits := ttl[:len(ttl)-1]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return nil
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return nil
	}
	secs := n * unit
	return &secs
}

// usesUnlimited reports whether a use count carries the service's unlimited
// sentinel. The API models "this credential may authenticate any number of
// times" as a count of zero, which a query comparing counts cannot tell apart
// from an exhausted credential.
func usesUnlimited(numUses int32) bool {
	return numUses == 0
}

// approles lists the machine identities that hold credentials on the
// instance. The SDK's Approle model carries no secret value; the credential
// lives on the secret ID model, and is deliberately not mapped there either.
func (r *mqlStackitSecretsManagerInstance) approles() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetApproles(bgctx(), c.ProjectID(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	roles, _ := resp.GetApprolesOk()
	out := make([]any, 0, len(roles))
	for i := range roles {
		res, err := newApprole(r, &roles[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// approleArgs maps one Approle record onto MQL field values.
func approleArgs(instanceId string, role *secretsmanager.Approle) map[string]*llx.RawData {
	ttl := role.GetSecretIdTtl()
	numUses := role.GetSecretIdNumUses()
	return map[string]*llx.RawData{
		// the role id is only unique within its instance, so the cache key
		// has to carry the instance it belongs to
		"__id":                  llx.StringData(qualifiedId("stackit.secretsManager.approle", instanceId, role.GetRoleId())),
		"roleId":                llx.StringData(role.GetRoleId()),
		"description":           llx.StringData(role.GetDescription()),
		"write":                 llx.BoolData(role.GetWrite()),
		"secretIdTtl":           llx.StringDataPtr(nonEmpty(ttl)),
		"secretIdTtlSeconds":    llx.IntDataPtr(ttlSeconds(ttl)),
		"secretIdNumUses":       llx.IntData(int64(numUses)),
		"secretIdUsesUnlimited": llx.BoolData(usesUnlimited(numUses)),
	}
}

func newApprole(inst *mqlStackitSecretsManagerInstance, role *secretsmanager.Approle) (*mqlStackitSecretsManagerApprole, error) {
	res, err := CreateResource(inst.MqlRuntime, "stackit.secretsManager.approle", approleArgs(inst.Id.Data, role))
	if err != nil {
		return nil, err
	}
	mqlRole := res.(*mqlStackitSecretsManagerApprole)
	mqlRole.cacheInstanceId = inst.Id.Data
	return mqlRole, nil
}

// secretIds lists the secret ID versions live on the approle. The SDK's
// ApproleSecret carries a SecretId field, which the API returns only when the
// secret is first created and which is the credential itself; it is
// deliberately never mapped into the resource.
func (r *mqlStackitSecretsManagerApprole) secretIds() ([]any, error) {
	if r.cacheInstanceId == "" {
		// only newApprole creates this resource, and it always records the
		// instance. Reporting an empty list here would pass any check written
		// over the secret IDs while having read none of them.
		return nil, fmt.Errorf("stackit.secretsManager.approle %q has no owning instance", r.RoleId.Data)
	}
	c := conn(r.MqlRuntime)
	client, err := c.SecretsManager()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListApproleSecretIds(bgctx(), c.ProjectID(), r.cacheInstanceId, r.RoleId.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	secrets, _ := resp.GetSecretIdsOk()
	out := make([]any, 0, len(secrets))
	for i := range secrets {
		res, err := newApproleSecretId(r, &secrets[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// approleSecretIdArgs maps one ApproleSecret record onto MQL field values. The
// record's SecretId is the credential itself and is never mapped, which
// TestApproleSecretIdArgsNeverCarryCredential pins.
func approleSecretIdArgs(instanceId, roleId string, secret *secretsmanager.ApproleSecret) map[string]*llx.RawData {
	ttl := secret.GetTtl()
	numUses := secret.GetNumUses()
	version := secret.GetVersion()
	return map[string]*llx.RawData{
		// a version number is only unique within its approle, which is itself
		// only unique within its instance
		"__id": llx.StringData(qualifiedId("stackit.secretsManager.approle.secretId",
			instanceId+"/"+roleId, strconv.FormatInt(int64(version), 10))),
		"version":       llx.IntData(int64(version)),
		"description":   llx.StringData(secret.GetDescription()),
		"ttl":           llx.StringDataPtr(nonEmpty(ttl)),
		"ttlSeconds":    llx.IntDataPtr(ttlSeconds(ttl)),
		"numUses":       llx.IntData(int64(numUses)),
		"usesUnlimited": llx.BoolData(usesUnlimited(numUses)),
	}
}

func newApproleSecretId(role *mqlStackitSecretsManagerApprole, secret *secretsmanager.ApproleSecret) (*mqlStackitSecretsManagerApproleSecretId, error) {
	res, err := CreateResource(role.MqlRuntime, "stackit.secretsManager.approle.secretId",
		approleSecretIdArgs(role.cacheInstanceId, role.RoleId.Data, secret))
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecretsManagerApproleSecretId), nil
}

func (r *mqlStackitSecretsManagerApprole) instance() (*mqlStackitSecretsManagerInstance, error) {
	if r.cacheInstanceId == "" {
		return markNull[mqlStackitSecretsManagerInstance](&r.Instance)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.secretsManager.instance", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheInstanceId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecretsManagerInstance), nil
}

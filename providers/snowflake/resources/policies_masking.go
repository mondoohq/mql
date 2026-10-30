// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeMaskingPolicyInternal struct {
	descLock       sync.Mutex
	descLoaded     bool
	descLoadErr    error
	descSignature  []any
	descReturnType string
	descBody       string
	refsLock       sync.Mutex
	refsLoaded     bool
	refsLoadErr    error
	refs           []any
}

func (r *mqlSnowflakeAccount) maskingPolicies() ([]any, error) {
	return listSnowflakeMaskingPolicies(r.MqlRuntime, sdk.ExtendedIn{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) maskingPolicies() ([]any, error) {
	return listSnowflakeMaskingPolicies(r.MqlRuntime, sdk.ExtendedIn{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeMaskingPolicies fetches masking policies within the given scope
// (account-wide or a single database) and maps them to resources.
func listSnowflakeMaskingPolicies(runtime *plugin.Runtime, in sdk.ExtendedIn) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	policies, err := conn.Client().MaskingPolicies.Show(context.Background(), &sdk.ShowMaskingPolicyRequest{In: &in})
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(policies))
	for i := range policies {
		mqlPolicy, err := newMqlSnowflakeMaskingPolicy(runtime, policies[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPolicy)
	}

	return list, nil
}

func newMqlSnowflakeMaskingPolicy(runtime *plugin.Runtime, policy sdk.MaskingPolicy) (*mqlSnowflakeMaskingPolicy, error) {
	r, err := CreateResource(runtime, "snowflake.maskingPolicy", map[string]*llx.RawData{
		"__id":                llx.StringData(policy.ID().FullyQualifiedName()),
		"name":                llx.StringData(policy.Name),
		"databaseName":        llx.StringData(policy.DatabaseName),
		"schemaName":          llx.StringData(policy.SchemaName),
		"kind":                llx.StringData(policy.Kind),
		"owner":               llx.StringData(policy.Owner),
		"ownerRoleType":       llx.StringData(policy.OwnerRoleType),
		"comment":             llx.StringData(policy.Comment),
		"exemptOtherPolicies": llx.BoolData(policy.ExemptOtherPolicies),
		"createdAt":           llx.TimeData(policy.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeMaskingPolicy), nil
}

func (r *mqlSnowflakeMaskingPolicy) gatherDescribe() error {
	if r.descLoaded {
		return r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	details, err := client.MaskingPolicies.Describe(ctx,
		sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data),
	)
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return err
	}

	sig := make([]any, 0, len(details.Signature))
	for _, s := range details.Signature {
		sig = append(sig, s.Name+":"+legacyDataTypeName(s.Type))
	}
	r.descSignature = sig
	r.descReturnType = legacyDataTypeName(details.ReturnType)
	r.descBody = details.Body
	r.descLoaded = true
	return nil
}

func (r *mqlSnowflakeMaskingPolicy) signature() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	return r.descSignature, nil
}

func (r *mqlSnowflakeMaskingPolicy) returnType() (string, error) {
	if err := r.gatherDescribe(); err != nil {
		return "", err
	}
	return r.descReturnType, nil
}

func (r *mqlSnowflakeMaskingPolicy) body() (string, error) {
	if err := r.gatherDescribe(); err != nil {
		return "", err
	}
	return r.descBody, nil
}

func (r *mqlSnowflakeMaskingPolicy) references() ([]any, error) {
	if r.refsLoaded {
		return r.refs, r.refsLoadErr
	}
	r.refsLock.Lock()
	defer r.refsLock.Unlock()
	if r.refsLoaded {
		return r.refs, r.refsLoadErr
	}

	out, err := queryPolicyReferences(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
	if err != nil {
		r.refsLoaded = true
		r.refsLoadErr = err
		return nil, err
	}

	r.refs = out
	r.refsLoaded = true
	return r.refs, nil
}

func newMqlSnowflakePolicyReference(
	runtime *plugin.Runtime,
	policyFqName string,
	pdb, pschema *string, pname, pkind *string,
	refdb, refschema *string, refname, refdomain *string,
	refcol, refargs, tagdb, tagschema, tagname, status *string,
) (*mqlSnowflakePolicyReference, error) {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}

	refEntityName := deref(refname)
	refEntityDomain := deref(refdomain)
	refCol := deref(refcol)

	__id := policyFqName + "|" + refEntityDomain + "|" + refEntityName
	if refCol != "" {
		__id += "|" + refCol
	}

	r, err := CreateResource(runtime, "snowflake.policyReference", map[string]*llx.RawData{
		"__id":              llx.StringData(__id),
		"policyDatabase":    llx.StringData(deref(pdb)),
		"policySchema":      llx.StringData(deref(pschema)),
		"policyName":        llx.StringData(deref(pname)),
		"policyKind":        llx.StringData(deref(pkind)),
		"refDatabaseName":   llx.StringData(deref(refdb)),
		"refSchemaName":     llx.StringData(deref(refschema)),
		"refEntityName":     llx.StringData(refEntityName),
		"refEntityDomain":   llx.StringData(refEntityDomain),
		"refColumnName":     llx.StringData(refCol),
		"refArgColumnNames": llx.StringData(deref(refargs)),
		"tagDatabase":       llx.StringData(deref(tagdb)),
		"tagSchema":         llx.StringData(deref(tagschema)),
		"tagName":           llx.StringData(deref(tagname)),
		"policyStatus":      llx.StringData(deref(status)),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakePolicyReference), nil
}

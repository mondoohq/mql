// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeSequenceInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeAccount) sequences() ([]any, error) {
	return listSnowflakeSequences(r.MqlRuntime, sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) sequences() ([]any, error) {
	return listSnowflakeSequences(r.MqlRuntime, sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeSequences fetches sequences within the given scope (account-wide
// or a single database) and maps them to resources.
func listSnowflakeSequences(runtime *plugin.Runtime, in sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	sequences, err := conn.Client().Sequences.Show(context.Background(),
		sdk.NewShowSequenceRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(sequences))
	for i := range sequences {
		mqlSequence, err := newMqlSnowflakeSequence(runtime, sequences[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlSequence)
	}
	return list, nil
}

func newMqlSnowflakeSequence(runtime *plugin.Runtime, sequence sdk.Sequence) (*mqlSnowflakeSequence, error) {
	r, err := CreateResource(runtime, "snowflake.sequence", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(sequence.DatabaseName, sequence.SchemaName, sequence.Name)),
		"name":          llx.StringData(sequence.Name),
		"databaseName":  llx.StringData(sequence.DatabaseName),
		"schemaName":    llx.StringData(sequence.SchemaName),
		"ownerRoleType": llx.StringData(sequence.OwnerRoleType),
		"nextValue":     llx.IntData(int64(sequence.NextValue)),
		"interval":      llx.IntData(int64(sequence.Interval)),
		"ordered":       llx.BoolData(sequence.Ordered),
		"comment":       llx.StringData(sequence.Comment),
		"createdAt":     parseSnowflakeTime(sequence.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlSequence := r.(*mqlSnowflakeSequence)
	mqlSequence.cacheOwner = sequence.Owner
	return mqlSequence, nil
}

func (r *mqlSnowflakeSequence) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeSequence) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeSequence) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

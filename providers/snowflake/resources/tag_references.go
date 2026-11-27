// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// Tag references: where each tag is set.
//
// SHOW TAGS lists the tags an account defines, not the objects they are set on.
// SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES lists every assignment in the account,
// tables and columns included, in one statement. The per-table alternative,
// INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS, is one statement per table, so
// an account with thousands of tables would pay thousands of statements.
//
// The account view is read once per scan and memoized on the account together
// with its error. The table and tag accessors filter that one list.

// tagReferencesQuery reads every live tag reference of the account. Columns are
// named so the decoder never depends on SELECT * ordering.
const tagReferencesQuery = `SELECT TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_VALUE, DOMAIN,
       OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
WHERE OBJECT_DELETED IS NULL`

// Domains TAG_REFERENCES reports in DOMAIN for objects this provider resolves.
const (
	tagDomainTable    = "TABLE"
	tagDomainColumn   = "COLUMN"
	tagDomainDatabase = "DATABASE"
	tagDomainSchema   = "SCHEMA"
)

// tagReferenceRow is one decoded TAG_REFERENCES row.
type tagReferenceRow struct {
	tagDatabase, tagSchema, tagName, value, domain       string
	objectDatabase, objectSchema, objectName, columnName string
}

// decodeTagReferenceRow decodes one QueryUnsafe row. A NULL TAG_VALUE or
// COLUMN_NAME decodes to "". ok is false for a row without TAG_NAME or DOMAIN,
// which cannot name an assignment.
func decodeTagReferenceRow(row map[string]*any) (tagReferenceRow, bool) {
	r := tagReferenceRow{
		tagDatabase:    unsafeString(row["TAG_DATABASE"]),
		tagSchema:      unsafeString(row["TAG_SCHEMA"]),
		tagName:        unsafeString(row["TAG_NAME"]),
		value:          unsafeString(row["TAG_VALUE"]),
		domain:         strings.ToUpper(strings.TrimSpace(unsafeString(row["DOMAIN"]))),
		objectDatabase: unsafeString(row["OBJECT_DATABASE"]),
		objectSchema:   unsafeString(row["OBJECT_SCHEMA"]),
		objectName:     unsafeString(row["OBJECT_NAME"]),
		columnName:     unsafeString(row["COLUMN_NAME"]),
	}
	if r.tagName == "" || r.domain == "" {
		return tagReferenceRow{}, false
	}
	return r, true
}

// joinNonEmpty joins the non-empty parts with dots.
func joinNonEmpty(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ".")
}

// tagQualifiedName is DATABASE.SCHEMA.TAG as recorded.
func (r tagReferenceRow) tagQualifiedName() string {
	return joinNonEmpty(r.tagDatabase, r.tagSchema, r.tagName)
}

// objectQualifiedName is the object's name qualified by whatever database and
// schema the row records: DB.SCHEMA.TABLE, DB.SCHEMA, DB, or a bare name for an
// object outside a database.
func (r tagReferenceRow) objectQualifiedName() string {
	return joinNonEmpty(r.objectDatabase, r.objectSchema, r.objectName)
}

// tagReferenceID is the cache id: the domain, the fully qualified object name,
// the column, and the fully qualified tag name, joined by "/". Two tags on one
// column differ in the last part, one tag on two columns in the column.
func tagReferenceID(r tagReferenceRow) string {
	return r.domain + "/" + r.objectQualifiedName() + "/" + r.columnName + "/" + r.tagQualifiedName()
}

// isTableDomain reports whether the row's object is a table: a tag set on the
// table itself or on one of its columns.
func (r tagReferenceRow) isTableDomain() bool {
	return r.domain == tagDomainTable || r.domain == tagDomainColumn
}

// objectSchemaName is the schema the object lives in. A DATABASE row has none;
// a SCHEMA row may record the schema only in OBJECT_NAME, since the schema it
// names is the object itself.
func (r tagReferenceRow) objectSchemaName() string {
	switch r.domain {
	case tagDomainDatabase:
		return ""
	case tagDomainSchema:
		if r.objectSchema != "" {
			return r.objectSchema
		}
		return r.objectName
	}
	return r.objectSchema
}

// objectDatabaseName is the database the object lives in. A DATABASE row may
// record the database only in OBJECT_NAME.
func (r tagReferenceRow) objectDatabaseName() string {
	if r.domain == tagDomainDatabase && r.objectDatabase == "" {
		return r.objectName
	}
	return r.objectDatabase
}

// queryRows runs a statement and returns its rows.
type queryRows func(ctx context.Context, statement string) ([]map[string]*any, error)

// tagReferenceMemo holds the account's one TAG_REFERENCES read, value and error.
//
// The failure is memoized with the value: a role that cannot read the account
// usage view on the first accessor cannot read it on the next one either.
type tagReferenceMemo struct {
	once sync.Once
	refs []*mqlSnowflakeTagReference
	err  error

	// query overrides the connection's client; tests set it.
	query queryRows

	tagsOnce   sync.Once
	tagsByName map[string]*mqlSnowflakeTag
	tagsErr    error

	tablesOnce   sync.Once
	tablesByName map[string]*mqlSnowflakeTable
	tablesErr    error
}

type mqlSnowflakeTagReferenceInternal struct {
	row tagReferenceRow
}

// loadTagReferences returns the account's tag references, reading them once.
func (r *mqlSnowflakeAccount) loadTagReferences() ([]*mqlSnowflakeTagReference, error) {
	m := &r.tagReferenceIndex
	m.once.Do(func() {
		query := m.query
		if query == nil {
			conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
			query = conn.Client().QueryUnsafe
		}
		rows, err := query(context.Background(), tagReferencesQuery)
		if err != nil {
			m.err = classifySnowflakeUsageError(err)
			return
		}
		refs := make([]*mqlSnowflakeTagReference, 0, len(rows))
		skipped := 0
		for _, row := range rows {
			decoded, ok := decodeTagReferenceRow(row)
			if !ok {
				skipped++
				continue
			}
			ref, err := newMqlSnowflakeTagReference(r.MqlRuntime, decoded)
			if err != nil {
				m.err = err
				return
			}
			refs = append(refs, ref)
		}
		if skipped > 0 {
			log.Debug().Int("skipped", skipped).
				Msg("snowflake: skipped tag reference rows without a tag name or domain")
		}
		m.refs = refs
	})
	return m.refs, m.err
}

func newMqlSnowflakeTagReference(runtime *plugin.Runtime, row tagReferenceRow) (*mqlSnowflakeTagReference, error) {
	res, err := CreateResource(runtime, "snowflake.tagReference", map[string]*llx.RawData{
		"__id":                llx.StringData(tagReferenceID(row)),
		"tagName":             llx.StringData(row.tagName),
		"tagQualifiedName":    llx.StringData(row.tagQualifiedName()),
		"value":               llx.StringData(row.value),
		"domain":              llx.StringData(row.domain),
		"objectName":          llx.StringData(row.objectName),
		"objectQualifiedName": llx.StringData(row.objectQualifiedName()),
		"columnName":          llx.StringData(row.columnName),
	})
	if err != nil {
		return nil, err
	}
	ref := res.(*mqlSnowflakeTagReference)
	ref.row = row
	return ref, nil
}

func (r *mqlSnowflakeAccount) tagReferences() ([]any, error) {
	refs, err := r.loadTagReferences()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref)
	}
	return out, nil
}

// filterTagReferences returns the account's references the predicate keeps. An
// account-level read error is returned as is, never as an empty list.
func filterTagReferences(runtime *plugin.Runtime, keep func(tagReferenceRow) bool) ([]any, error) {
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	refs, err := account.loadTagReferences()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ref := range refs {
		if keep(ref.row) {
			out = append(out, ref)
		}
	}
	return out, nil
}

// Names compare as stored: Snowflake stores unquoted identifiers folded to
// upper case in both SHOW output and the account usage views, and a quoted
// identifier keeps its case in both, so the stored values are equal.
func (r *mqlSnowflakeTable) tagReferences() ([]any, error) {
	db, schema, name := r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data
	return filterTagReferences(r.MqlRuntime, func(row tagReferenceRow) bool {
		return row.isTableDomain() &&
			row.objectDatabase == db && row.objectSchema == schema && row.objectName == name
	})
}

func (r *mqlSnowflakeTag) references() ([]any, error) {
	db, schema, name := r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data
	return filterTagReferences(r.MqlRuntime, func(row tagReferenceRow) bool {
		return row.tagDatabase == db && row.tagSchema == schema && row.tagName == name
	})
}

// tagIndex maps a tag's schema object id to the account's listed tag.
func (r *mqlSnowflakeAccount) tagIndex() (map[string]*mqlSnowflakeTag, error) {
	m := &r.tagReferenceIndex
	m.tagsOnce.Do(func() {
		tags := r.GetTags()
		if tags.Error != nil {
			m.tagsErr = tags.Error
			return
		}
		m.tagsByName = make(map[string]*mqlSnowflakeTag, len(tags.Data))
		for _, t := range tags.Data {
			tag, ok := t.(*mqlSnowflakeTag)
			if !ok {
				continue
			}
			m.tagsByName[snowflakeSchemaObjectID(tag.DatabaseName.Data, tag.SchemaName.Data, tag.Name.Data)] = tag
		}
	})
	return m.tagsByName, m.tagsErr
}

// tableIndex maps a table's schema object id to the account's listed table.
func (r *mqlSnowflakeAccount) tableIndex() (map[string]*mqlSnowflakeTable, error) {
	m := &r.tagReferenceIndex
	m.tablesOnce.Do(func() {
		tables := r.GetTables()
		if tables.Error != nil {
			m.tablesErr = tables.Error
			return
		}
		m.tablesByName = make(map[string]*mqlSnowflakeTable, len(tables.Data))
		for _, t := range tables.Data {
			table, ok := t.(*mqlSnowflakeTable)
			if !ok {
				continue
			}
			m.tablesByName[snowflakeSchemaObjectID(table.DatabaseName.Data, table.SchemaName.Data, table.Name.Data)] = table
		}
	})
	return m.tablesByName, m.tablesErr
}

func (r *mqlSnowflakeTagReference) tag() (*mqlSnowflakeTag, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	index, err := account.tagIndex()
	if err != nil {
		return nil, err
	}
	tag, ok := index[snowflakeSchemaObjectID(r.row.tagDatabase, r.row.tagSchema, r.row.tagName)]
	if !ok {
		r.Tag.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return tag, nil
}

func (r *mqlSnowflakeTagReference) table() (*mqlSnowflakeTable, error) {
	if !r.row.isTableDomain() {
		r.Table.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	index, err := account.tableIndex()
	if err != nil {
		return nil, err
	}
	table, ok := index[snowflakeSchemaObjectID(r.row.objectDatabase, r.row.objectSchema, r.row.objectName)]
	if !ok {
		r.Table.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return table, nil
}

// The database and schema accessors resolve through the account's memoized
// database and schema listings only, never a per-row SHOW: an account holds
// many more tag references than databases. A name the listing does not hold
// (dropped, not visible to the role) reads null; the qualified name fields keep
// the raw record. A listing that failed returns its error.

func indexedDatabaseRef(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlSnowflakeDatabase]) (*mqlSnowflakeDatabase, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	index, err := account.databaseIndex()
	if err != nil {
		return nil, err
	}
	database, ok := lookupIndexed(index, databaseIndexKey(name))
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlSnowflakeDatabase(runtime, database)
}

func indexedSchemaRef(runtime *plugin.Runtime, databaseName, name string, field *plugin.TValue[*mqlSnowflakeSchema]) (*mqlSnowflakeSchema, error) {
	if databaseName == "" || name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	index, err := account.schemaIndex()
	if err != nil {
		return nil, err
	}
	schema, ok := lookupIndexed(index, schemaIndexKey(databaseName, name))
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlSnowflakeSchema(runtime, schema)
}

func (r *mqlSnowflakeTagReference) tagDatabase() (*mqlSnowflakeDatabase, error) {
	return indexedDatabaseRef(r.MqlRuntime, r.row.tagDatabase, &r.TagDatabase)
}

func (r *mqlSnowflakeTagReference) tagSchema() (*mqlSnowflakeSchema, error) {
	return indexedSchemaRef(r.MqlRuntime, r.row.tagDatabase, r.row.tagSchema, &r.TagSchema)
}

func (r *mqlSnowflakeTagReference) objectDatabase() (*mqlSnowflakeDatabase, error) {
	return indexedDatabaseRef(r.MqlRuntime, r.row.objectDatabaseName(), &r.ObjectDatabase)
}

func (r *mqlSnowflakeTagReference) objectSchema() (*mqlSnowflakeSchema, error) {
	return indexedSchemaRef(r.MqlRuntime, r.row.objectDatabaseName(), r.row.objectSchemaName(), &r.ObjectSchema)
}

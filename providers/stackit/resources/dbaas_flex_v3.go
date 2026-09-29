// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	postgresflexv3 "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v3api"
	sqlserverflexv3 "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v3api"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The v3 APIs of Postgres Flex and SQLServer Flex describe an instance with
// the network access scope (PUBLIC or SNA), the customer-managed encryption
// key, labels, and the deletion flag, none of which the v2 record carries.
// The shipped fields keep reading the v2 record; the fields below read one
// v3 GetInstance per instance, fetched the first time any of them is asked
// for.

// flexV3Fields is the part of a v3 instance record these fields read, taken
// out of the two SDK packages' separate (but identical) types.
type flexV3Fields struct {
	accessScope       *string
	kekKeyID          string
	kekKeyRingID      string
	kekServiceAccount string
	kekVersion        *int64
	labels            map[string]string
	deletable         *bool
	retentionDays     *int64
}

// flexV3Detail memoizes the v3 record of one instance.
type flexV3Detail struct {
	fetched atomic.Bool
	lock    sync.Mutex
	fields  *flexV3Fields
}

// load returns the memoized record, fetching it once. A refused call keeps
// the provider's established behavior (fields read null) until structured
// errors are enabled, and returns the classified refusal after that.
func (d *flexV3Detail) load(fetch func() (*flexV3Fields, error)) (*flexV3Fields, error) {
	if d.fetched.Load() {
		return d.fields, nil
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.fetched.Load() {
		return d.fields, nil
	}
	f, err := fetch()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				d.fetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	d.fields = f
	d.fetched.Store(true)
	return d.fields, nil
}

// parseKekVersion reads the key version the v3 API reports as a string. An
// empty or non-numeric value yields nil.
func parseKekVersion(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// stringPtrValues drops the null values of a label map; STACKIT labels are
// strings, and a label without a value carries nothing to compare.
func stringPtrValues(in map[string]*string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v != nil {
			out[k] = *v
		}
	}
	return out
}

func postgresFlexV3Fields(resp *postgresflexv3.GetInstanceResponse) *flexV3Fields {
	f := &flexV3Fields{labels: stringPtrValues(resp.GetLabels())}
	if n, ok := resp.GetNetworkOk(); ok && n != nil {
		if s, ok := n.GetAccessScopeOk(); ok && s != nil {
			v := string(*s)
			f.accessScope = &v
		}
	}
	if e, ok := resp.GetEncryptionOk(); ok && e != nil {
		f.kekKeyID = e.GetKekKeyId()
		f.kekKeyRingID = e.GetKekKeyRingId()
		f.kekServiceAccount = e.GetServiceAccount()
		f.kekVersion = parseKekVersion(e.GetKekKeyVersion())
	}
	f.deletable = optBool(resp.GetIsDeletableOk())
	if d, ok := resp.GetRetentionDaysOk(); ok && d != nil {
		v := int64(*d)
		f.retentionDays = &v
	}
	return f
}

func sqlServerFlexV3Fields(resp *sqlserverflexv3.GetInstanceResponse) *flexV3Fields {
	f := &flexV3Fields{labels: stringPtrValues(resp.GetLabels())}
	if n, ok := resp.GetNetworkOk(); ok && n != nil {
		if s, ok := n.GetAccessScopeOk(); ok && s != nil {
			v := string(*s)
			f.accessScope = &v
		}
	}
	if e, ok := resp.GetEncryptionOk(); ok && e != nil {
		f.kekKeyID = e.GetKekKeyId()
		f.kekKeyRingID = e.GetKekKeyRingId()
		f.kekServiceAccount = e.GetServiceAccount()
		f.kekVersion = parseKekVersion(e.GetKekKeyVersion())
	}
	f.deletable = optBool(resp.GetIsDeletableOk())
	if d, ok := resp.GetRetentionDaysOk(); ok && d != nil {
		v := int64(*d)
		f.retentionDays = &v
	}
	return f
}

// nullString reports an absent string on the given field as null.
func nullString(field *plugin.TValue[string]) (string, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

// ---- field readers shared by both engines ----

func flexAccessScope(f *flexV3Fields, field *plugin.TValue[string]) (string, error) {
	if f == nil || f.accessScope == nil {
		return nullString(field)
	}
	return *f.accessScope, nil
}

func flexEncryptionKeyVersion(f *flexV3Fields, field *plugin.TValue[int64]) (int64, error) {
	if f == nil || f.kekVersion == nil {
		return nullInt(field)
	}
	return *f.kekVersion, nil
}

func flexDeletable(f *flexV3Fields, field *plugin.TValue[bool]) (bool, error) {
	if f == nil || f.deletable == nil {
		return nullBool(field)
	}
	return *f.deletable, nil
}

func flexLabels(f *flexV3Fields) map[string]any {
	if f == nil {
		return map[string]any{}
	}
	return stringMap(f.labels)
}

// ---- Postgres Flex ----

func (r *mqlStackitPostgresFlexInstance) fetchV3() (*flexV3Fields, error) {
	return r.v3.load(func() (*flexV3Fields, error) {
		c := conn(r.MqlRuntime)
		client, err := c.PostgresFlexV3()
		if err != nil {
			return nil, err
		}
		resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}
		return postgresFlexV3Fields(resp), nil
	})
}

func (r *mqlStackitPostgresFlexInstance) accessScope() (string, error) {
	f, err := r.fetchV3()
	if err != nil {
		return "", err
	}
	return flexAccessScope(f, &r.AccessScope)
}

func (r *mqlStackitPostgresFlexInstance) encryptionKey() (*mqlStackitKmsKey, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitKmsKey](&r.EncryptionKey)
	}
	return kmsKeyInRingRef(r.MqlRuntime, f.kekKeyRingID, f.kekKeyID, &r.EncryptionKey)
}

func (r *mqlStackitPostgresFlexInstance) encryptionKeyRing() (*mqlStackitKmsKeyRing, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitKmsKeyRing](&r.EncryptionKeyRing)
	}
	return kmsKeyRingRef(r.MqlRuntime, f.kekKeyRingID, &r.EncryptionKeyRing)
}

func (r *mqlStackitPostgresFlexInstance) encryptionKeyVersion() (int64, error) {
	f, err := r.fetchV3()
	if err != nil {
		return 0, err
	}
	return flexEncryptionKeyVersion(f, &r.EncryptionKeyVersion)
}

func (r *mqlStackitPostgresFlexInstance) encryptionKeyServiceAccount() (*mqlStackitServiceAccount, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitServiceAccount](&r.EncryptionKeyServiceAccount)
	}
	return serviceAccountRef(r.MqlRuntime, f.kekServiceAccount, &r.EncryptionKeyServiceAccount)
}

func (r *mqlStackitPostgresFlexInstance) labels() (map[string]any, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	return flexLabels(f), nil
}

func (r *mqlStackitPostgresFlexInstance) deletable() (bool, error) {
	f, err := r.fetchV3()
	if err != nil {
		return false, err
	}
	return flexDeletable(f, &r.Deletable)
}

func (r *mqlStackitPostgresFlexInstance) backupRetentionDays() (int64, error) {
	f, err := r.fetchV3()
	if err != nil {
		return 0, err
	}
	if f == nil || f.retentionDays == nil {
		return nullInt(&r.BackupRetentionDays)
	}
	return *f.retentionDays, nil
}

// ---- SQLServer Flex ----

func (r *mqlStackitSqlServerFlexInstance) fetchV3() (*flexV3Fields, error) {
	return r.v3.load(func() (*flexV3Fields, error) {
		c := conn(r.MqlRuntime)
		client, err := c.SqlServerFlexV3()
		if err != nil {
			return nil, err
		}
		// The v3 API takes (projectId, region, instanceId), unlike v2's
		// (projectId, instanceId, region).
		resp, err := client.DefaultAPI.GetInstance(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}
		return sqlServerFlexV3Fields(resp), nil
	})
}

func (r *mqlStackitSqlServerFlexInstance) accessScope() (string, error) {
	f, err := r.fetchV3()
	if err != nil {
		return "", err
	}
	return flexAccessScope(f, &r.AccessScope)
}

func (r *mqlStackitSqlServerFlexInstance) encryptionKey() (*mqlStackitKmsKey, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitKmsKey](&r.EncryptionKey)
	}
	return kmsKeyInRingRef(r.MqlRuntime, f.kekKeyRingID, f.kekKeyID, &r.EncryptionKey)
}

func (r *mqlStackitSqlServerFlexInstance) encryptionKeyRing() (*mqlStackitKmsKeyRing, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitKmsKeyRing](&r.EncryptionKeyRing)
	}
	return kmsKeyRingRef(r.MqlRuntime, f.kekKeyRingID, &r.EncryptionKeyRing)
}

func (r *mqlStackitSqlServerFlexInstance) encryptionKeyVersion() (int64, error) {
	f, err := r.fetchV3()
	if err != nil {
		return 0, err
	}
	return flexEncryptionKeyVersion(f, &r.EncryptionKeyVersion)
}

func (r *mqlStackitSqlServerFlexInstance) encryptionKeyServiceAccount() (*mqlStackitServiceAccount, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return markNull[mqlStackitServiceAccount](&r.EncryptionKeyServiceAccount)
	}
	return serviceAccountRef(r.MqlRuntime, f.kekServiceAccount, &r.EncryptionKeyServiceAccount)
}

func (r *mqlStackitSqlServerFlexInstance) labels() (map[string]any, error) {
	f, err := r.fetchV3()
	if err != nil {
		return nil, err
	}
	return flexLabels(f), nil
}

func (r *mqlStackitSqlServerFlexInstance) deletable() (bool, error) {
	f, err := r.fetchV3()
	if err != nil {
		return false, err
	}
	return flexDeletable(f, &r.Deletable)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stackitcloud/stackit-sdk-go/core/oapierror"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func bgctx() context.Context { return context.Background() }

// timeOrNil turns a (time, ok) result from the SDK's GetXxxOk methods into the
// *time.Time form that llx.TimeDataPtr wants. A nil or zero time reads as unset.
//
// The STACKIT service packages disagree on whether an optional timestamp comes
// back as a value or a pointer (sfs returns time.Time, iaas and ske return
// *time.Time), so accept both rather than making every caller adapt.
// strOrNil turns a (value, ok) getter pair into a pointer, so a field the API
// left out stays null instead of collapsing into an empty string, which a
// query comparing against a version or a name cannot tell apart from a real
// empty value. Callers pass a generated GetXOk() result straight through; the
// STACKIT SDK modules return the value itself in some services and a pointer
// to it in others, so both forms are accepted.
func strOrNil[T string | *string](v T, ok bool) *string {
	if !ok {
		return nil
	}
	switch s := any(v).(type) {
	case string:
		return &s
	case *string:
		return s
	}
	return nil
}

func timeOrNil[T time.Time | *time.Time](t T, ok bool) *time.Time {
	if !ok {
		return nil
	}
	switch v := any(t).(type) {
	case time.Time:
		if v.IsZero() {
			return nil
		}
		return &v
	case *time.Time:
		if v == nil || v.IsZero() {
			return nil
		}
		return v
	}
	return nil
}

// rfc3339OrNil formats a (time, ok) pair from the SDK's GetXxxOk methods as an
// RFC3339 string for embedding as a `dict` value, or nil when unset or zero.
// A `dict` value must be a dict-native scalar (string/number/bool), so a
// *time.Time cannot be stored directly; use llx.TimeDataPtr for typed `time`
// fields and this helper only for timestamps that live inside a dict.
func rfc3339OrNil[T time.Time | *time.Time](t T, ok bool) any {
	tp := timeOrNil(t, ok)
	if tp == nil {
		return nil
	}
	return tp.Format(time.RFC3339)
}

// nonEmpty keeps an empty string out of a field the service normally
// populates, so "the API told us nothing" reads as null rather than as a real
// empty setting. Use it where the SDK models a value as a plain string, which
// leaves no other way to tell an absent value apart from a blank one.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// parseRFC3339 turns an RFC3339 timestamp string into the *time.Time form
// llx.TimeDataPtr wants, or nil if the string is empty or malformed. Several
// STACKIT services return timestamps as strings rather than time.Time.
func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// parseKeyBitSize extracts the numeric key length from STACKIT's human-readable
// key-strength string (for example "RSA 2048" -> 2048). It returns nil for
// elliptic-curve keys, whose strength is expressed as a curve name rather than
// a bit count (for example "ECDSA P-256" or "Ed25519"); only a whitespace-
// delimited all-digit token counts, so the "256" in "P-256" is not mistaken
// for a bit size.
func parseKeyBitSize(s string) *int64 {
	for _, tok := range strings.Fields(s) {
		if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
			return &n
		}
	}
	return nil
}

// strSlice converts a []string into the any-typed slice MQL expects.
func strSlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// stringMap converts a map[string]string into the any-valued form MQL expects
// for `map[string]string` fields.
func stringMap(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// stringPtrMap converts a map[string]*string into the any-valued form MQL
// expects. A nil value stays nil so it reads as null rather than as an empty
// string: the API distinguishes a parameter set to "" from one it did not send.
func stringPtrMap(in map[string]*string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = *v
	}
	return out
}

// strSliceData wraps a []string for assignment to a `[]string` field.
func strSliceData(in []string) *llx.RawData {
	return llx.ArrayData(strSlice(in), types.String)
}

// stringMapData wraps a map[string]string for a `map[string]string` field.
func stringMapData(in map[string]string) *llx.RawData {
	return llx.MapData(stringMap(in), types.String)
}

// labelData wraps a STACKIT label map (string→string OR string→interface{},
// depending on which SDK module emitted it) for a `map[string]string` field.
// STACKIT only stores string values in labels even when the type is broader.
func labelData(in any) *llx.RawData {
	out := map[string]any{}
	switch m := in.(type) {
	case map[string]string:
		for k, v := range m {
			out[k] = v
		}
	case map[string]interface{}:
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return llx.MapData(out, types.String)
}

// metadataData is the same as labelData; kept distinct so callers read clearly.
func metadataData(in any) *llx.RawData { return labelData(in) }

// ptrStr derefs a nullable string returned by the SDK's getter methods. Accepts
// the plain-string form too, since the service packages differ on which they
// return for an optional field.
func ptrStr[T string | *string](p T) string {
	switch v := any(p).(type) {
	case string:
		return v
	case *string:
		if v == nil {
			return ""
		}
		return *v
	}
	return ""
}

// derefInt64 returns the value behind a *int64, or 0 when nil.
func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ptrEnumStr renders a pointer-to-string-enum as its string value, or "" when
// the field is unset. The versioned service packages hand back a pointer for
// optional enums where the root packages returned the bare enum.
func ptrEnumStr[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

// toDict marshals any SDK struct (or other value) into the JSON-equivalent
// map/slice form that MQL `dict` fields accept. The cheap way to avoid
// hand-rolling getter conversions for every nested SDK object — at the cost
// of one allocation per call. Returns nil for nil inputs or marshal errors.
func toDict(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// dictAny renders any value into MQL-compatible dict form. Maps/slices are
// recursed; nil → nil; scalars pass through.
func dictAny(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]interface{}:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = dictAny(val)
		}
		return out
	case []interface{}:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = dictAny(val)
		}
		return out
	default:
		return v
	}
}

// isAccessDenied returns true for 401/403 — the standard "permission
// missing for this scope" fallback so a single denied call doesn't fail the
// whole query. 404 is intentionally excluded: a "not found" can mean a wrong
// project/instance ID and should surface as an error rather than be silently
// swallowed as an empty result.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var oerr *oapierror.GenericOpenAPIError
	if errors.As(err, &oerr) {
		switch oerr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") ||
		strings.Contains(msg, "status 403")
}

// isNotFound returns true for HTTP 404. Use this for optional sub-resources
// where "not configured" is a legitimate state distinct from access-denied.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var oerr *oapierror.GenericOpenAPIError
	if errors.As(err, &oerr) {
		return oerr.StatusCode == http.StatusNotFound
	}
	return strings.Contains(err.Error(), "status 404")
}

// markNull marks a typed-resource pointer field as set+null and returns nil.
// Used by typed-ref methods when the source identifier is empty.
func markNull[T any](field *plugin.TValue[*T]) (*T, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// qualifiedId builds the cache key for a resource whose own id is only unique
// within its parent, such as a database user inside an instance or a wrapping
// key inside a key ring. Pass the result as the "__id" argument to
// CreateResource: an id() method cannot do this job, because it runs inside
// CreateResource, before the parent can be recorded on the returned resource,
// and would silently produce the same key for every parent.
func qualifiedId(resource, parent, id string) string {
	return resource + "/" + parent + "/" + id
}

// idArg pulls a single string arg out of an init args map.
func idArg(args map[string]*llx.RawData, key string) (string, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.Value.(string)
	return s, ok && s != ""
}

// makeNamespace creates the bare namespace resource (no fields, just child
// collection getters).
func makeNamespace(runtime *plugin.Runtime, name string) (plugin.Resource, error) {
	return CreateResource(runtime, name, map[string]*llx.RawData{})
}

// refByKey resolves a reference to another resource through that resource's
// init, keyed by one string argument (key: value). An empty value marks the
// field null. So does a 404 from the lookup: the referencing record still
// names an object the service no longer has (a backup whose volume was
// deleted, a volume whose source image was retired, a server whose key pair
// belongs to another user), and that is an absence, not a failure. Any other
// error, a refusal included, is returned as is.
func refByKey[T any](runtime *plugin.Runtime, resource, key, value string, field *plugin.TValue[*T]) (*T, error) {
	if value == "" {
		return markNull(field)
	}
	res, err := NewResource(runtime, resource, map[string]*llx.RawData{
		key: llx.StringData(value),
	})
	if err != nil {
		if isNotFound(err) {
			return markNull(field)
		}
		return nil, err
	}
	typed, ok := any(res).(*T)
	if !ok {
		return nil, fmt.Errorf("stackit: unexpected type %T for %s", res, resource)
	}
	return typed, nil
}

// refsByID resolves a list of references by id through the target
// resource's init. See refsByKey.
func refsByID(runtime *plugin.Runtime, resource string, ids []string) ([]any, error) {
	return refsByKey(runtime, resource, "id", ids)
}

// refsByKey resolves a list of references through the target resource's
// init, each keyed by one string argument. Empty values are skipped, and so
// are values the service answers 404 for, so one deleted object does not
// fail the whole list. Any other error, a refusal included, is returned as
// is.
func refsByKey(runtime *plugin.Runtime, resource, key string, values []string) ([]any, error) {
	out := make([]any, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		res, err := NewResource(runtime, resource, map[string]*llx.RawData{
			key: llx.StringData(v),
		})
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// serverRef resolves a stackit.server by its UUID, marking the given field
// null when the ID is empty or the server no longer exists. Shared by the
// server-scoped sub-resources (backups, schedules, updates) that carry a
// back-reference to their server.
func serverRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitServer]) (*mqlStackitServer, error) {
	return refByKey(runtime, "stackit.server", "id", id, field)
}

// volumeRef resolves a single stackit.volume by its UUID, marking the given
// field null when the ID is empty or the volume no longer exists.
func volumeRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitVolume]) (*mqlStackitVolume, error) {
	return refByKey(runtime, "stackit.volume", "id", id, field)
}

// kmsKeyRef resolves a Key Management Service key by its bare UUID, marking the
// given field null when the ID is empty or the project holds no such key.
//
// The lookup goes through the project-wide key index on the stackit.kms
// singleton rather than NewResource: stackit.kms.key has no init, and its cache
// key is qualified by the key ring, so a bare UUID cannot address one. Reading
// a denied key ring already degrades to an empty listing upstream, which lands
// here as a null reference rather than an error.
func kmsKeyRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitKmsKey]) (*mqlStackitKmsKey, error) {
	if id == "" {
		return markNull[mqlStackitKmsKey](field)
	}
	k, err := kmsResource(runtime)
	if err != nil {
		return nil, err
	}
	idx, err := k.keyIndexByID()
	if err != nil {
		return nil, err
	}
	key, ok := idx[id]
	if !ok || key == nil {
		return markNull[mqlStackitKmsKey](field)
	}
	return key, nil
}

// optBool passes an SDK GetXxxOk() bool pair through as a pointer that is nil
// when the API omitted the field, so the MQL field reads null rather than a
// false the API never sent.
func optBool(v *bool, ok bool) *bool {
	if !ok {
		return nil
	}
	return v
}

// kmsKeyRingRef resolves a key ring by UUID, marking the field null when the
// id is empty or the ring is not readable from this project (a ring that lives
// in another project answers 404 to GetKeyRing).
func kmsKeyRingRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitKmsKeyRing]) (*mqlStackitKmsKeyRing, error) {
	if id == "" {
		return markNull[mqlStackitKmsKeyRing](field)
	}
	res, err := NewResource(runtime, "stackit.kms.keyRing", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if isNotFound(err) || isAccessDenied(err) {
			return markNull[mqlStackitKmsKeyRing](field)
		}
		return nil, err
	}
	return res.(*mqlStackitKmsKeyRing), nil
}

// kmsKeyInRingRef resolves a key by UUID through the ring that holds it, which
// costs one ring's key list rather than the walk over every ring that
// kmsKeyRef performs. It falls back to that walk when the ring is unknown, and
// marks the field null when the key id is empty or the ring's list does not
// carry the key.
func kmsKeyInRingRef(runtime *plugin.Runtime, ringID, keyID string, field *plugin.TValue[*mqlStackitKmsKey]) (*mqlStackitKmsKey, error) {
	if keyID == "" {
		return markNull[mqlStackitKmsKey](field)
	}
	if ringID == "" {
		return kmsKeyRef(runtime, keyID, field)
	}
	var ringField plugin.TValue[*mqlStackitKmsKeyRing]
	ring, err := kmsKeyRingRef(runtime, ringID, &ringField)
	if err != nil {
		return nil, err
	}
	if ring == nil {
		return markNull[mqlStackitKmsKey](field)
	}
	keys := ring.GetKeys()
	if keys.Error != nil {
		return nil, keys.Error
	}
	key, ok := indexKmsKeysByID(keys.Data)[keyID]
	if !ok || key == nil {
		return markNull[mqlStackitKmsKey](field)
	}
	return key, nil
}

// serviceAccountRef resolves a service account by email against the project's
// service-account list, marking the field null when the email is empty or the
// account is not one of this project's. A key-encryption key held in another
// project is used through a service account of that project, which this
// connection cannot list.
func serviceAccountRef(runtime *plugin.Runtime, email string, field *plugin.TValue[*mqlStackitServiceAccount]) (*mqlStackitServiceAccount, error) {
	if email == "" {
		return markNull[mqlStackitServiceAccount](field)
	}
	root, err := CreateResource(runtime, "stackit", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	accounts := root.(*mqlStackit).GetServiceAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}
	for _, a := range accounts.Data {
		sa, ok := a.(*mqlStackitServiceAccount)
		if ok && sa.Email.Data == email {
			return sa, nil
		}
	}
	return markNull[mqlStackitServiceAccount](field)
}

// iamRoleRef resolves a project role by name, marking the given field null when
// the name is empty or the role catalog does not define it.
//
// The lookup goes through the role index on the stackit.iam singleton rather
// than NewResource: stackit.iam.role has no init and roles are only ever
// produced by listing the catalog.
func iamRoleRef(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlStackitIamRole]) (*mqlStackitIamRole, error) {
	if name == "" {
		return markNull[mqlStackitIamRole](field)
	}
	i, err := iamResource(runtime)
	if err != nil {
		return nil, err
	}
	idx, err := i.roleIndexByName()
	if err != nil {
		return nil, err
	}
	role, ok := idx[name]
	if !ok || role == nil {
		return markNull[mqlStackitIamRole](field)
	}
	return role, nil
}

// volumeRefs resolves a list of stackit.volume resources from their UUIDs,
// skipping empty IDs and volumes that no longer exist.
func volumeRefs(runtime *plugin.Runtime, ids []string) ([]any, error) {
	return refsByID(runtime, "stackit.volume", ids)
}

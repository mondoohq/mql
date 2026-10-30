// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"go.mondoo.com/mql/types"
)

// AnonymousUser is the principal an unauthenticated caller acts as. A
// permission target naming it grants to everyone who can reach the instance,
// which is why several fields of this provider single it out.
const AnonymousUser = "anonymous"

// deploy actions let a principal put artifacts into a repository or change who
// else can. Read is deliberately not one of them.
var deployActions = map[string]bool{
	"write":  true,
	"deploy": true,
	"delete": true,
	"manage": true,
}

func (a *mqlArtifactory) id() (string, error) {
	return "artifactory", nil
}

// --- shared helpers -------------------------------------------------------

// artifactoryConn returns the connection backing the runtime.
func artifactoryConn(runtime *plugin.Runtime) *connection.ArtifactoryConnection {
	return runtime.Connection.(*connection.ArtifactoryConnection)
}

// getArtifactory returns the root resource. Cross-resource accessors go
// through it so that its cached lists are reused rather than refetched.
func getArtifactory(runtime *plugin.Runtime) (*mqlArtifactory, error) {
	res, err := CreateResource(runtime, "artifactory", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlArtifactory), nil
}

// optionalString reports a value the instance leaves unset as null rather than
// as an empty string, so a schema that promises null keeps that promise. An
// empty string and an absent value are the same thing in these responses, so
// the empty case is the absent one.
func optionalString(v string) *llx.RawData {
	if v == "" {
		return llx.NilData
	}
	return llx.StringData(v)
}

// nullableString does the same for a computed accessor, where the value is
// reported by setting the field null rather than by passing raw data.
func nullableString(v string, field *plugin.TValue[string]) (string, error) {
	if v == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return v, nil
}

// strSliceToAny widens a string slice for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// epochTime converts an epoch-seconds timestamp into a time value. Zero and
// negative values mean the instance did not report one, and stay null rather
// than becoming 1 January 1970.
func epochTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	return &t
}

// millisTime converts an epoch-milliseconds timestamp into a time value. The
// Access API reports account timestamps in milliseconds.
func millisTime(millis int64) *time.Time {
	if millis <= 0 {
		return nil
	}
	t := time.UnixMilli(millis).UTC()
	return &t
}

// isoTime decodes a timestamp the instance reports as a string, which is
// absent on a record that never reached the state it describes.
type isoTime struct {
	t *time.Time
}

func (i *isoTime) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	// A few endpoints report the same field as epoch milliseconds rather than
	// as a string, so the numeric shape is decoded before the string one.
	if s[0] != '"' {
		var millis int64
		if err := json.Unmarshal(b, &millis); err != nil {
			return err
		}
		i.t = millisTime(millis)
		return nil
	}

	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if str == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339, str); err == nil {
		i.t = &parsed
		return nil
	}
	// Artifactory writes an offset without a colon, for example
	// 2026-01-02T03:04:05.000+0000, which RFC 3339 does not cover.
	if parsed, err := time.Parse("2006-01-02T15:04:05.000-0700", str); err == nil {
		i.t = &parsed
		return nil
	}
	// A timestamp whose shape changed is reported as null rather than failing
	// the whole resource, and logged so the change is visible instead of
	// looking like a record that never reached the state the field describes.
	log.Warn().Str("value", str).Msg("artifactory> could not parse timestamp; reporting it as null")
	return nil
}

// Time returns the decoded time value, or nil when the source was absent.
func (i isoTime) Time() *time.Time {
	return i.t
}

// containsDeployAction reports whether any action lets a principal publish.
func containsDeployAction(actions []string) bool {
	for _, action := range actions {
		if deployActions[strings.ToLower(action)] {
			return true
		}
	}
	return false
}

// containsAction reports whether the actions contain want, ignoring case.
func containsAction(actions []string, want string) bool {
	for _, action := range actions {
		if strings.EqualFold(action, want) {
			return true
		}
	}
	return false
}

// --- root resource --------------------------------------------------------

func (a *mqlArtifactory) system() (*mqlArtifactorySystemInfo, error) {
	conn := artifactoryConn(a.MqlRuntime)
	info := FetchSystemInfo(context.Background(), conn)

	serviceID := info.ServiceID
	if serviceID == "" {
		serviceID = conn.Host()
	}

	res, err := CreateResource(a.MqlRuntime, "artifactory.systemInfo", map[string]*llx.RawData{
		"serviceId": llx.StringData(serviceID),
		"version":   llx.StringData(info.Version),
		"revision":  llx.StringData(info.Revision),
		"addons":    llx.ArrayData(strSliceToAny(info.Addons), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlArtifactorySystemInfo), nil
}

func (s *mqlArtifactorySystemInfo) id() (string, error) {
	return "artifactory.systemInfo/" + s.ServiceId.Data, s.ServiceId.Error
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vllm/connection"
)

// nullBool marks a boolean field as resolved-and-null. A posture field that
// was never observed must not read as false: MQL evaluates `null && null` to
// true, but a false would be reported to the user as an observation the probe
// never made.
func nullBool(field *plugin.TValue[bool]) (bool, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func boolField(field *plugin.TValue[bool], value *bool) (bool, error) {
	if value == nil {
		return nullBool(field)
	}
	return *value, nil
}

func stringField(field *plugin.TValue[string], value *string) (string, error) {
	if value == nil || *value == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *value, nil
}

func intField(field *plugin.TValue[int64], value *int64) (int64, error) {
	if value == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *value, nil
}

// stringListField renders a list of names. A nil slice means the server was
// never read, so the field resolves to null; an empty slice means the server
// was read and reported nothing, which is a different answer.
func stringListField(field *plugin.TValue[[]any], values []string) ([]any, error) {
	if values == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	out := make([]any, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out, nil
}

// stringMapField renders a name/value set. A nil map means the server was never
// read, so the field resolves to null; an empty map means the server was read
// and carried nothing, which is a different answer.
func stringMapField(field *plugin.TValue[map[string]any], values map[string]string) (map[string]any, error) {
	if values == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out, nil
}

func dictField(field *plugin.TValue[any], value map[string]any) (any, error) {
	if value == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return value, nil
}

func (r *mqlVllm) serverInfo() (*mqlVllmServerInfo, error) {
	res, err := CreateResource(r.MqlRuntime, "vllm.serverInfo", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlVllmServerInfo), nil
}

func (r *mqlVllm) tokenizerInfo() (*mqlVllmTokenizerInfo, error) {
	res, err := CreateResource(r.MqlRuntime, "vllm.tokenizerInfo", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlVllmTokenizerInfo), nil
}

func (s *mqlVllmServerInfo) id() (string, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL() + "/server_info", nil
}

// info returns the decoded engine configuration, or nil when the route did not
// answer with one. A transport or status failure is reported as "no
// configuration" rather than as a query error, so one closed route does not
// fail every other field on the asset.
func (s *mqlVllmServerInfo) info() *connection.ServerInfo {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return nil
	}
	info, err := conn.ServerInfo(context.Background())
	if err != nil {
		return nil
	}
	return info
}

func (s *mqlVllmServerInfo) exposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(s.MqlRuntime, http.MethodGet, "/server_info")
	if err != nil {
		return false, err
	}
	if !known {
		return nullBool(&s.Exposed)
	}
	return accessible, nil
}

func (s *mqlVllmServerInfo) configReadable() (bool, error) {
	info := s.info()
	if info == nil {
		// The route did not answer at all, so nothing was readable. This is an
		// observation, not an unknown, and it is reported as a definite false.
		return false, nil
	}
	return info.Structured, nil
}

func (s *mqlVllmServerInfo) trustRemoteCode() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.TrustRemoteCode)
	}
	return boolField(&s.TrustRemoteCode, info.TrustRemoteCode)
}

func (s *mqlVllmServerInfo) model() (string, error) {
	info := s.info()
	if info == nil {
		return stringField(&s.Model, nil)
	}
	return stringField(&s.Model, info.Model)
}

func (s *mqlVllmServerInfo) tokenizer() (string, error) {
	info := s.info()
	if info == nil {
		return stringField(&s.Tokenizer, nil)
	}
	return stringField(&s.Tokenizer, info.Tokenizer)
}

func (s *mqlVllmServerInfo) tokenizerMode() (string, error) {
	info := s.info()
	if info == nil {
		return stringField(&s.TokenizerMode, nil)
	}
	return stringField(&s.TokenizerMode, info.TokenizerMode)
}

func (s *mqlVllmServerInfo) servedModelNames() ([]any, error) {
	info := s.info()
	if info == nil {
		return stringListField(&s.ServedModelNames, nil)
	}
	return stringListField(&s.ServedModelNames, info.ServedModelNames)
}

func (s *mqlVllmServerInfo) maxModelLen() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.MaxModelLen, nil)
	}
	return intField(&s.MaxModelLen, info.MaxModelLen)
}

func (s *mqlVllmServerInfo) quantization() (string, error) {
	info := s.info()
	if info == nil {
		return stringField(&s.Quantization, nil)
	}
	return stringField(&s.Quantization, info.Quantization)
}

func (s *mqlVllmServerInfo) enforceEager() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.EnforceEager)
	}
	return boolField(&s.EnforceEager, info.EnforceEager)
}

func (s *mqlVllmServerInfo) enablePrefixCaching() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.EnablePrefixCaching)
	}
	return boolField(&s.EnablePrefixCaching, info.EnablePrefixCaching)
}

func (s *mqlVllmServerInfo) loraEnabled() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.LoraEnabled)
	}
	return boolField(&s.LoraEnabled, info.LoraEnabled)
}

func (s *mqlVllmServerInfo) maxLoras() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.MaxLoras, nil)
	}
	return intField(&s.MaxLoras, info.MaxLoras)
}

func (s *mqlVllmServerInfo) maxLoraRank() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.MaxLoraRank, nil)
	}
	return intField(&s.MaxLoraRank, info.MaxLoraRank)
}

func (s *mqlVllmServerInfo) loraConfig() (any, error) {
	info := s.info()
	if info == nil {
		return dictField(&s.LoraConfig, nil)
	}
	return dictField(&s.LoraConfig, info.LoraConfig)
}

func (s *mqlVllmServerInfo) tensorParallelSize() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.TensorParallelSize, nil)
	}
	return intField(&s.TensorParallelSize, info.TensorParallelSize)
}

func (s *mqlVllmServerInfo) pipelineParallelSize() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.PipelineParallelSize, nil)
	}
	return intField(&s.PipelineParallelSize, info.PipelineParallelSize)
}

func (s *mqlVllmServerInfo) dataParallelSize() (int64, error) {
	info := s.info()
	if info == nil {
		return intField(&s.DataParallelSize, nil)
	}
	return intField(&s.DataParallelSize, info.DataParallelSize)
}

func (s *mqlVllmServerInfo) parallelConfig() (any, error) {
	info := s.info()
	if info == nil {
		return dictField(&s.ParallelConfig, nil)
	}
	return dictField(&s.ParallelConfig, info.ParallelConfig)
}

func (s *mqlVllmServerInfo) otlpTracesEndpoint() (string, error) {
	info := s.info()
	if info == nil {
		return stringField(&s.OtlpTracesEndpoint, nil)
	}
	return stringField(&s.OtlpTracesEndpoint, info.OtlpTracesEndpoint)
}

func (s *mqlVllmServerInfo) collectDetailedTraces() ([]any, error) {
	info := s.info()
	if info == nil {
		return stringListField(&s.CollectDetailedTraces, nil)
	}
	return stringListField(&s.CollectDetailedTraces, info.CollectDetailedTraces)
}

func (s *mqlVllmServerInfo) loggingIterationDetailsEnabled() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.LoggingIterationDetailsEnabled)
	}
	return boolField(&s.LoggingIterationDetailsEnabled, info.LoggingIterationDetails)
}

func (s *mqlVllmServerInfo) allowRuntimeLoraUpdating() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.AllowRuntimeLoraUpdating)
	}
	return boolField(&s.AllowRuntimeLoraUpdating, info.AllowRuntimeLoraUpdating)
}

func (s *mqlVllmServerInfo) serverDevMode() (bool, error) {
	info := s.info()
	if info == nil {
		return nullBool(&s.ServerDevMode)
	}
	return boolField(&s.ServerDevMode, info.ServerDevMode)
}

func (t *mqlVllmTokenizerInfo) id() (string, error) {
	conn, err := vllmConnection(t.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL() + "/tokenizer_info", nil
}

func (t *mqlVllmTokenizerInfo) info() *connection.TokenizerInfo {
	conn, err := vllmConnection(t.MqlRuntime)
	if err != nil {
		return nil
	}
	info, err := conn.TokenizerInfo(context.Background())
	if err != nil {
		return nil
	}
	return info
}

func (t *mqlVllmTokenizerInfo) exposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(t.MqlRuntime, http.MethodGet, "/tokenizer_info")
	if err != nil {
		return false, err
	}
	if !known {
		return nullBool(&t.Exposed)
	}
	return accessible, nil
}

func (t *mqlVllmTokenizerInfo) tokenizerClass() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.TokenizerClass, nil)
	}
	return stringField(&t.TokenizerClass, info.TokenizerClass)
}

func (t *mqlVllmTokenizerInfo) chatTemplateConfigured() (bool, error) {
	info := t.info()
	if info == nil {
		return nullBool(&t.ChatTemplateConfigured)
	}
	configured := info.ChatTemplate != nil && *info.ChatTemplate != ""
	return configured, nil
}

func (t *mqlVllmTokenizerInfo) chatTemplate() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.ChatTemplate, nil)
	}
	return stringField(&t.ChatTemplate, info.ChatTemplate)
}

func (t *mqlVllmTokenizerInfo) chatTemplateSha256() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.ChatTemplateSha256, nil)
	}
	return stringField(&t.ChatTemplateSha256, info.ChatTemplateSHA256)
}

func (t *mqlVllmTokenizerInfo) maxLength() (int64, error) {
	info := t.info()
	if info == nil {
		return intField(&t.MaxLength, nil)
	}
	return intField(&t.MaxLength, info.ModelMaxLength)
}

func (t *mqlVllmTokenizerInfo) addBosToken() (bool, error) {
	info := t.info()
	if info == nil {
		return nullBool(&t.AddBosToken)
	}
	return boolField(&t.AddBosToken, info.AddBosToken)
}

func (t *mqlVllmTokenizerInfo) addEosToken() (bool, error) {
	info := t.info()
	if info == nil {
		return nullBool(&t.AddEosToken)
	}
	return boolField(&t.AddEosToken, info.AddEosToken)
}

func (t *mqlVllmTokenizerInfo) bosToken() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.BosToken, nil)
	}
	return stringField(&t.BosToken, info.BosToken)
}

func (t *mqlVllmTokenizerInfo) eosToken() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.EosToken, nil)
	}
	return stringField(&t.EosToken, info.EosToken)
}

func (t *mqlVllmTokenizerInfo) padToken() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.PadToken, nil)
	}
	return stringField(&t.PadToken, info.PadToken)
}

func (t *mqlVllmTokenizerInfo) unkToken() (string, error) {
	info := t.info()
	if info == nil {
		return stringField(&t.UnkToken, nil)
	}
	return stringField(&t.UnkToken, info.UnkToken)
}

func (t *mqlVllmTokenizerInfo) cleanUpTokenizationSpaces() (bool, error) {
	info := t.info()
	if info == nil {
		return nullBool(&t.CleanUpTokenizationSpaces)
	}
	return boolField(&t.CleanUpTokenizationSpaces, info.CleanUpTokenizationSpec)
}

// modelPermissionResources renders the permission array a vLLM server
// advertises for one model. An empty array is a real answer, so it renders as
// an empty list rather than as null.
func modelPermissionResources(runtime *plugin.Runtime, modelID string, permissions []connection.ModelPermission) ([]any, error) {
	conn, err := vllmConnection(runtime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(permissions))
	for i, perm := range permissions {
		id := perm.ID
		if id == "" {
			// The server left the permission unidentified, so key the row on
			// its position in the array to keep the cache entries distinct.
			id = "permission-" + strconv.Itoa(i)
		}
		mqlPerm, err := CreateResource(runtime, "vllm.model.permission", map[string]*llx.RawData{
			"__id":               llx.StringData(conn.BaseURL() + "/model/" + modelID + "/permission/" + id),
			"id":                 llx.StringData(id),
			"allowSampling":      llx.BoolDataPtr(perm.AllowSampling),
			"allowLogprobs":      llx.BoolDataPtr(perm.AllowLogprobs),
			"allowFineTuning":    llx.BoolDataPtr(perm.AllowFineTuning),
			"allowCreateEngine":  llx.BoolDataPtr(perm.AllowCreateEngine),
			"allowSearchIndices": llx.BoolDataPtr(perm.AllowSearchIndices),
			"allowView":          llx.BoolDataPtr(perm.AllowView),
			"organization":       llx.StringDataPtr(perm.Organization),
			"group":              llx.StringDataPtr(perm.Group),
			"isBlocking":         llx.BoolDataPtr(perm.IsBlocking),
			"created":            llx.TimeDataPtr(modelCreatedTime(perm.Created)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPerm)
	}
	return res, nil
}

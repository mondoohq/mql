// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"regexp"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mistral/connection"
	"go.mondoo.com/mql/providers/mistral/internal/mistralai"
	"go.mondoo.com/mql/types"
)

func mistralConn(runtime *plugin.Runtime) *connection.MistralConnection {
	return runtime.Connection.(*connection.MistralConnection)
}

// floatDataPtr maps a *float64 to MQL data, preserving null for an unset value.
// llx ships IntDataPtr/BoolDataPtr/StringDataPtr but no float equivalent.
func floatDataPtr(f *float64) *llx.RawData {
	if f == nil {
		return llx.NilData
	}
	return llx.FloatData(*f)
}

// mqlMistralModelInternal carries the raw id of the model Mistral names as a
// deprecated model's successor. It stays off the schema so the value reaches
// users as a mistral.model rather than as a bare identifier string.
type mqlMistralModelInternal struct {
	replacementModelID string
}

func (r *mqlMistral) id() (string, error) {
	return "mistral", nil
}

func (r *mqlMistral) ownedBy() (string, error) {
	conn := mistralConn(r.MqlRuntime)
	workspace := conn.Workspace()
	if workspace != "" {
		return workspace, nil
	}
	return "mistralai", nil
}

func (r *mqlMistral) models() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.ListModels(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, m := range resp.Data {
		mqlModel, err := newMqlModel(r.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModel)
	}

	return res, nil
}

// newMqlModel maps one API model record onto a mistral.model resource. It is
// shared by the model listing and by the replacementModel accessor, which has
// to build a model that the listing did not report.
func newMqlModel(runtime *plugin.Runtime, m mistralai.Model) (*mqlMistralModel, error) {
	var created *time.Time
	if m.Created > 0 {
		t := time.Unix(m.Created, 0)
		created = &t
	}

	var deprecation *time.Time
	if m.Deprecation != nil && *m.Deprecation != "" {
		if t, err := time.Parse(time.RFC3339, *m.Deprecation); err == nil {
			deprecation = &t
		}
	}

	var defaultTemp float64
	if m.DefaultModelTemperature != nil {
		defaultTemp = *m.DefaultModelTemperature
	}

	name := ""
	if m.Name != nil {
		name = *m.Name
	}
	description := ""
	if m.Description != nil {
		description = *m.Description
	}

	aliases := make([]interface{}, 0, len(m.Aliases))
	for _, a := range m.Aliases {
		aliases = append(aliases, a)
	}

	mqlModel, err := CreateResource(runtime, "mistral.model", map[string]*llx.RawData{
		"__id":                         llx.StringData(m.ID),
		"id":                           llx.StringData(m.ID),
		"type":                         llx.StringData(m.Type),
		"ownedBy":                      llx.StringData(m.OwnedBy),
		"name":                         llx.StringData(name),
		"description":                  llx.StringData(description),
		"maxContextLength":             llx.IntData(m.MaxContextLength),
		"created":                      llx.TimeDataPtr(created),
		"aliases":                      llx.ArrayData(aliases, types.String),
		"deprecation":                  llx.TimeDataPtr(deprecation),
		"defaultModelTemperature":      llx.FloatData(defaultTemp),
		"capabilityChat":               llx.BoolData(m.Capabilities.CompletionChat),
		"capabilityFunctionCalling":    llx.BoolData(m.Capabilities.FunctionCalling),
		"capabilityFim":                llx.BoolData(m.Capabilities.CompletionFim),
		"capabilityFineTuning":         llx.BoolData(m.Capabilities.FineTuning),
		"capabilityVision":             llx.BoolData(m.Capabilities.Vision),
		"capabilityOcr":                llx.BoolData(m.Capabilities.OCR),
		"capabilityClassification":     llx.BoolData(m.Capabilities.Classification),
		"capabilityModeration":         llx.BoolData(m.Capabilities.Moderation),
		"capabilityAudio":              llx.BoolData(m.Capabilities.Audio),
		"capabilityAudioTranscription": llx.BoolData(m.Capabilities.AudioTranscription),
		"job":                          llx.StringData(m.Job),
		"root":                         llx.StringData(m.Root),
		"archived":                     llx.BoolData(m.Archived),
	})
	if err != nil {
		return nil, err
	}

	model := mqlModel.(*mqlMistralModel)
	if m.DeprecationReplacementModel != nil {
		model.replacementModelID = *m.DeprecationReplacementModel
	}
	return model, nil
}

func (r *mqlMistral) connectors() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	connectors, err := client.ListConnectors(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(connectors))
	for _, c := range connectors {
		authMethods := make([]interface{}, 0, len(c.SupportedAuthMethods))
		for _, name := range c.AuthMethodNames() {
			authMethods = append(authMethods, name)
		}

		mqlConnector, err := CreateResource(r.MqlRuntime, "mistral.connector", map[string]*llx.RawData{
			"__id":                 llx.StringData(c.ID),
			"id":                   llx.StringData(c.ID),
			"name":                 llx.StringData(c.Name),
			"description":          llx.StringData(c.Description),
			"server":               llx.StringDataPtr(c.Server),
			"protocol":             llx.StringData(c.Protocol),
			"visibility":           llx.StringData(c.Visibility),
			"ownerType":            llx.StringData(c.OwnerType),
			"supportedAuthMethods": llx.ArrayData(authMethods, types.String),
			"privateToolExecution": llx.BoolData(c.PrivateToolExecution),
			"createdAt":            llx.TimeDataPtr(c.CreatedAt),
			"modifiedAt":           llx.TimeDataPtr(c.ModifiedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConnector)
	}

	return res, nil
}

func (r *mqlMistral) libraries() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	libraries, err := client.ListLibraries(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(libraries))
	for _, l := range libraries {
		mqlLibrary, err := CreateResource(r.MqlRuntime, "mistral.library", map[string]*llx.RawData{
			"__id":        llx.StringData(l.ID),
			"id":          llx.StringData(l.ID),
			"name":        llx.StringData(l.Name),
			"description": llx.StringDataPtr(l.Description),
			"nbDocuments": llx.IntData(l.NbDocuments),
			"totalSize":   llx.IntData(l.TotalSize),
			"ownerType":   llx.StringData(l.OwnerType),
			"ownerId":     llx.StringDataPtr(l.OwnerID),
			"createdAt":   llx.TimeDataPtr(l.CreatedAt),
			"updatedAt":   llx.TimeDataPtr(l.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLibrary)
	}

	return res, nil
}

func (r *mqlMistral) fineTuningJobs() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	jobs, err := client.ListFineTuningJobs(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(jobs))
	for _, j := range jobs {
		createdAt := timeFromUnix(j.CreatedAt)
		modifiedAt := timeFromUnix(j.ModifiedAt)

		fineTunedModel := ""
		if j.FineTunedModel != nil {
			fineTunedModel = *j.FineTunedModel
		}
		suffix := ""
		if j.Suffix != nil {
			suffix = *j.Suffix
		}

		trainingFiles := make([]interface{}, 0, len(j.TrainingFiles))
		for _, f := range j.TrainingFiles {
			trainingFiles = append(trainingFiles, f)
		}
		validationFiles := make([]interface{}, 0, len(j.ValidationFiles))
		for _, f := range j.ValidationFiles {
			validationFiles = append(validationFiles, f)
		}

		var expectedDuration *int64
		var cost *float64
		costCurrency := ""
		if j.Metadata != nil {
			expectedDuration = j.Metadata.ExpectedDurationSeconds
			cost = j.Metadata.Cost
			if j.Metadata.CostCurrency != nil {
				costCurrency = *j.Metadata.CostCurrency
			}
		}

		integrations := make([]interface{}, 0, len(j.Integrations))
		for _, in := range j.Integrations {
			mqlIntegration, err := CreateResource(r.MqlRuntime, "mistral.fineTuningJob.integration", map[string]*llx.RawData{
				"__id":    llx.StringData(integrationID(j.ID, in)),
				"type":    llx.StringData(in.Type),
				"project": llx.StringData(in.Project),
				"name":    llx.StringDataPtr(in.Name),
				"runName": llx.StringDataPtr(in.RunName),
				"url":     llx.StringDataPtr(in.URL),
			})
			if err != nil {
				return nil, err
			}
			integrations = append(integrations, mqlIntegration)
		}

		mqlJob, err := CreateResource(r.MqlRuntime, "mistral.fineTuningJob", map[string]*llx.RawData{
			"__id":                    llx.StringData(j.ID),
			"id":                      llx.StringData(j.ID),
			"status":                  llx.StringData(j.Status),
			"model":                   llx.StringData(j.Model),
			"fineTunedModel":          llx.StringData(fineTunedModel),
			"suffix":                  llx.StringData(suffix),
			"autoStart":               llx.BoolData(j.AutoStart),
			"trainingFiles":           llx.ArrayData(trainingFiles, types.String),
			"validationFiles":         llx.ArrayData(validationFiles, types.String),
			"trainedTokens":           llx.IntDataPtr(j.TrainedTokens),
			"createdAt":               llx.TimeDataPtr(createdAt),
			"modifiedAt":              llx.TimeDataPtr(modifiedAt),
			"jobType":                 llx.StringData(j.JobType),
			"trainingSteps":           llx.IntDataPtr(j.Hyperparameters.TrainingSteps),
			"learningRate":            llx.FloatData(j.Hyperparameters.LearningRate),
			"epochs":                  floatDataPtr(j.Hyperparameters.Epochs),
			"expectedDurationSeconds": llx.IntDataPtr(expectedDuration),
			"cost":                    floatDataPtr(cost),
			"costCurrency":            llx.StringData(costCurrency),
			"integrations":            llx.ArrayData(integrations, types.Resource("mistral.fineTuningJob.integration")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJob)
	}

	return res, nil
}

func (r *mqlMistral) files() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	files, err := client.ListFiles(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(files))
	for _, f := range files {
		createdAt := timeFromUnix(f.CreatedAt)

		mimeType := ""
		if f.MimeType != nil {
			mimeType = *f.MimeType
		}

		mqlFile, err := CreateResource(r.MqlRuntime, "mistral.file", map[string]*llx.RawData{
			"__id":       llx.StringData(f.ID),
			"id":         llx.StringData(f.ID),
			"filename":   llx.StringData(f.Filename),
			"purpose":    llx.StringData(f.Purpose),
			"bytes":      llx.IntData(f.Bytes),
			"createdAt":  llx.TimeDataPtr(createdAt),
			"sampleType": llx.StringData(f.SampleType),
			"source":     llx.StringData(f.Source),
			"numLines":   llx.IntDataPtr(f.NumLines),
			"mimeType":   llx.StringData(mimeType),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}

	return res, nil
}

func (r *mqlMistral) batchJobs() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	batches, err := client.ListBatchJobs(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(batches))
	for _, b := range batches {
		createdAt := timeFromUnix(b.CreatedAt)
		startedAt := timeFromUnixPtr(b.StartedAt)
		completedAt := timeFromUnixPtr(b.CompletedAt)

		model := ""
		if b.Model != nil {
			model = *b.Model
		}
		outputFile := ""
		if b.OutputFile != nil {
			outputFile = *b.OutputFile
		}
		errorFile := ""
		if b.ErrorFile != nil {
			errorFile = *b.ErrorFile
		}

		inputFiles := make([]interface{}, 0, len(b.InputFiles))
		for _, f := range b.InputFiles {
			inputFiles = append(inputFiles, f)
		}

		batchErrors := make([]interface{}, 0, len(b.Errors))
		for _, e := range b.Errors {
			mqlErr, err := CreateResource(r.MqlRuntime, "mistral.batchJob.error", map[string]*llx.RawData{
				"__id":    llx.StringData(b.ID + "/" + e.Message),
				"message": llx.StringData(e.Message),
				"count":   llx.IntData(int64(e.Count)),
			})
			if err != nil {
				return nil, err
			}
			batchErrors = append(batchErrors, mqlErr)
		}

		metadata := make(map[string]interface{}, len(b.Metadata))
		for k, v := range b.Metadata {
			metadata[k] = v
		}

		mqlBatch, err := CreateResource(r.MqlRuntime, "mistral.batchJob", map[string]*llx.RawData{
			"__id":              llx.StringData(b.ID),
			"id":                llx.StringData(b.ID),
			"status":            llx.StringData(b.Status),
			"endpoint":          llx.StringData(b.Endpoint),
			"model":             llx.StringData(model),
			"inputFiles":        llx.ArrayData(inputFiles, types.String),
			"outputFile":        llx.StringData(outputFile),
			"errorFile":         llx.StringData(errorFile),
			"totalRequests":     llx.IntData(b.TotalRequests),
			"completedRequests": llx.IntData(b.CompletedRequests),
			"succeededRequests": llx.IntData(b.SucceededRequests),
			"failedRequests":    llx.IntData(b.FailedRequests),
			"createdAt":         llx.TimeDataPtr(createdAt),
			"startedAt":         llx.TimeDataPtr(startedAt),
			"completedAt":       llx.TimeDataPtr(completedAt),
			"errors":            llx.ArrayData(batchErrors, types.Resource("mistral.batchJob.error")),
			"metadata":          llx.MapData(metadata, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBatch)
	}

	return res, nil
}

func (r *mqlMistralModel) id() (string, error) {
	return r.Id.Data, nil
}

var (
	mistralParamSizeRe = regexp.MustCompile(`[\-_](\d+(?:\.\d+)?(?:[xX]\d+)?[bBmM])[\-_]?`)
)

// mistralFamilies is ordered most-specific first so that e.g. "codestral"
// matches before the shorter "mistral" suffix it shares.
var mistralFamilies = []struct {
	substring string
	family    string
}{
	{"codestral", "Codestral"},
	{"devstral", "Devstral"},
	{"leanstral", "Leanstral"},
	{"magistral", "Magistral"},
	{"mathstral", "Mathstral"},
	{"ministral", "Ministral"},
	{"mixtral", "Mixtral"},
	{"pixtral", "Pixtral"},
	{"nemo", "Nemo"},
	{"embed", "Embed"},
	{"moderation", "Moderation"},
	{"mistral", "Mistral"},
}

// matchFamily maps a model identifier to its architecture family by substring.
// This is a best-effort heuristic: a fine-tuned model whose user-chosen suffix
// happens to contain a family token (e.g. "my-embed-tuner" rooted on
// mistral-large) can be misclassified. The order of mistralFamilies resolves
// the ambiguous base-model cases most-specific first.
func matchFamily(id string) string {
	lower := strings.ToLower(id)
	for _, f := range mistralFamilies {
		if strings.Contains(lower, f.substring) {
			return f.family
		}
	}
	return ""
}

// familyFromNames resolves a family from the model id, falling back to the root
// base model id for fine-tuned models.
func familyFromNames(id, root string) string {
	if f := matchFamily(id); f != "" {
		return f
	}
	if root != "" {
		if f := matchFamily(root); f != "" {
			return f
		}
	}
	return ""
}

// parseParameterSize extracts a normalized parameter count (e.g. "7B",
// "8x22B") from the model id, falling back to the root base model id for
// fine-tuned models. Returns "" when no size token is present.
func parseParameterSize(id, root string) string {
	m := mistralParamSizeRe.FindStringSubmatch(id)
	if m == nil && root != "" {
		m = mistralParamSizeRe.FindStringSubmatch(root)
	}
	if m == nil {
		return ""
	}
	size := m[1]
	last := size[len(size)-1]
	if last >= 'a' && last <= 'z' {
		size = size[:len(size)-1] + strings.ToUpper(string(last))
	}
	return size
}

func (r *mqlMistralModel) family() (string, error) {
	return familyFromNames(r.Id.Data, r.Root.Data), nil
}

func (r *mqlMistralModel) parameterSize() (string, error) {
	return parseParameterSize(r.Id.Data, r.Root.Data), nil
}

func (r *mqlMistralFineTuningJob) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralFile) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralBatchJob) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralConnector) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralLibrary) id() (string, error) {
	return r.Id.Data, nil
}

// integrationID keys a fine-tuning integration inside its job. A job may carry
// several integrations of the same type, so the project and run name are part
// of the key; without them the second entry would be served the first one's
// values out of the resource cache.
func integrationID(jobID string, in mistralai.WandbIntegration) string {
	runName := ""
	if in.RunName != nil {
		runName = *in.RunName
	}
	return strings.Join([]string{jobID, in.Type, in.Project, runName}, "/")
}

// libraryAccessID keys a share entry inside its library. An organization-wide
// share carries no entity id, so the entity kind is part of the key: keyed on
// the id alone, an Org share and any other share missing an id would collide.
func libraryAccessID(libraryID string, access mistralai.LibraryAccess) string {
	uuid := ""
	if access.ShareWithUUID != nil {
		uuid = *access.ShareWithUUID
	}
	return strings.Join([]string{libraryID, access.ShareWithType, uuid}, "/")
}

func (r *mqlMistralLibrary) accesses() ([]interface{}, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	libraryID := r.Id.Data
	accesses, err := client.ListLibraryAccesses(context.Background(), libraryID)
	if mistralai.IsAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]interface{}, 0, len(accesses))
	for _, a := range accesses {
		mqlAccess, err := CreateResource(r.MqlRuntime, "mistral.library.access", map[string]*llx.RawData{
			"__id":          llx.StringData(libraryAccessID(libraryID, a)),
			"shareWithType": llx.StringData(a.ShareWithType),
			"shareWithUuid": llx.StringDataPtr(a.ShareWithUUID),
			"role":          llx.StringData(a.Role),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAccess)
	}

	return res, nil
}

// replacementModel resolves the successor Mistral names for a deprecated
// model. The workspace model list is consulted first so a query over every
// deprecated model costs one list call rather than one call per model; a
// replacement the list does not carry (a model the key cannot see listed) is
// fetched once on its own.
func (r *mqlMistralModel) replacementModel() (*mqlMistralModel, error) {
	wantID := r.replacementModelID
	if wantID == "" {
		r.ReplacementModel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	mistralRes, err := CreateResource(r.MqlRuntime, "mistral", map[string]*llx.RawData{
		"__id": llx.StringData("mistral"),
	})
	if err != nil {
		return nil, err
	}

	models := mistralRes.(*mqlMistral).GetModels()
	if models.Error == nil {
		for _, m := range models.Data {
			model, ok := m.(*mqlMistralModel)
			if ok && model.Id.Data == wantID {
				return model, nil
			}
		}
	}

	conn := mistralConn(r.MqlRuntime)
	fetched, err := conn.Client().GetModel(context.Background(), wantID)
	if err != nil {
		// A replacement that cannot be read is reported as absent rather than
		// failing the model it hangs off: the deprecation date and every other
		// field of the deprecated model stay queryable.
		r.ReplacementModel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return newMqlModel(r.MqlRuntime, *fetched)
}

func timeFromUnix(ts int64) *time.Time {
	if ts == 0 {
		return nil
	}
	t := time.Unix(ts, 0)
	return &t
}

func timeFromUnixPtr(ts *int64) *time.Time {
	if ts == nil || *ts == 0 {
		return nil
	}
	t := time.Unix(*ts, 0)
	return &t
}

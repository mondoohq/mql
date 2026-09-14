// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/together/connection"
	"go.mondoo.com/mql/types"
)

func togetherConn(runtime *plugin.Runtime) *connection.TogetherConnection {
	return runtime.Connection.(*connection.TogetherConnection)
}

func (r *mqlTogether) id() (string, error) {
	return "together", nil
}

// mqlTogetherInternal memoizes the /whoami response. Seven identity fields are
// backed by it and a query that reads more than one of them must not cost more
// than one call.
//
// The memo latches on success only. sync.Once would also cache a failure, so a
// single transient 429 or DNS blip would lock out every identity field for the
// rest of the scan with no retry path.
type mqlTogetherInternal struct {
	whoamiLock   sync.Mutex
	whoamiLoaded atomic.Bool
	whoami       *together.WhoamiResponse
}

// identity returns the account identity the API key actually authenticates as,
// as reported by GET /whoami. It is fetched once per resource and reused.
func (r *mqlTogether) identity() (*together.WhoamiResponse, error) {
	if r.whoamiLoaded.Load() {
		return r.whoami, nil
	}

	r.whoamiLock.Lock()
	defer r.whoamiLock.Unlock()
	if r.whoamiLoaded.Load() {
		return r.whoami, nil
	}

	conn := togetherConn(r.MqlRuntime)
	who, err := conn.Client().Whoami(context.Background())
	if err != nil {
		return nil, err
	}
	if who == nil {
		return nil, errors.New("together: /whoami returned no account identity")
	}

	r.whoami = who
	r.whoamiLoaded.Store(true)
	return r.whoami, nil
}

// organization reports the organization the API key belongs to. It is read
// back from /whoami: the value must describe the account the token resolves
// to on the server, never a value the caller supplied on the command line.
func (r *mqlTogether) organization() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	if who.OrganizationName != "" {
		return who.OrganizationName, nil
	}
	return who.OrganizationID, nil
}

func (r *mqlTogether) organizationId() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.OrganizationID, nil
}

func (r *mqlTogether) organizationName() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.OrganizationName, nil
}

func (r *mqlTogether) projectId() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.ProjectID, nil
}

func (r *mqlTogether) projectName() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.ProjectName, nil
}

func (r *mqlTogether) apiKeyId() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.APIKeyID, nil
}

func (r *mqlTogether) userId() (string, error) {
	who, err := r.identity()
	if err != nil {
		return "", err
	}
	return who.UserID, nil
}

func (r *mqlTogether) models() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	models, err := client.Models.List(context.Background(), together.ModelListParams{})
	if err != nil {
		return nil, err
	}
	if models == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(*models))
	for _, m := range *models {
		var created *time.Time
		if m.Created > 0 {
			t := time.Unix(m.Created, 0)
			created = &t
		}

		mqlModel, err := CreateResource(r.MqlRuntime, "together.model", map[string]*llx.RawData{
			"__id":          llx.StringData(m.ID),
			"id":            llx.StringData(m.ID),
			"displayName":   llx.StringData(m.DisplayName),
			"type":          llx.StringData(string(m.Type)),
			"organization":  llx.StringData(m.Organization),
			"license":       llx.StringData(m.License),
			"contextLength": llx.IntData(m.ContextLength),
			"link":          llx.StringData(m.Link),
			"created":       llx.TimeDataPtr(created),
			"pricingInput":  llx.FloatData(m.Pricing.Input),
			"pricingOutput": llx.FloatData(m.Pricing.Output),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModel)
	}

	return res, nil
}

func (r *mqlTogether) fineTunes() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.FineTuning.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, j := range resp.Data {
		mqlJob, err := CreateResource(r.MqlRuntime, "together.fineTune", map[string]*llx.RawData{
			"__id":            llx.StringData(j.ID),
			"id":              llx.StringData(j.ID),
			"status":          llx.StringData(j.Status),
			"model":           llx.StringData(j.Model),
			"modelOutputName": llx.StringData(j.ModelOutputName),
			"trainingFile":    llx.StringData(j.TrainingFile),
			"validationFile":  llx.StringData(j.ValidationFile),
			"createdAt":       llx.TimeData(j.CreatedAt),
			"updatedAt":       llx.TimeData(j.UpdatedAt),
			"totalPrice":      llx.IntData(j.TotalPrice),
			"tokenCount":      llx.IntData(j.TokenCount),
			"epochs":          llx.IntData(j.NEpochs),
			"learningRate":    llx.FloatData(j.LearningRate),
			"suffix":          llx.StringData(j.Suffix),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJob)
	}

	return res, nil
}

func (r *mqlTogether) endpoints() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Endpoints.List(context.Background(), together.EndpointListParams{})
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, e := range resp.Data {
		mqlEndpoint, err := CreateResource(r.MqlRuntime, "together.endpoint", map[string]*llx.RawData{
			"__id":      llx.StringData(e.ID),
			"id":        llx.StringData(e.ID),
			"name":      llx.StringData(e.Name),
			"model":     llx.StringData(e.Model),
			"state":     llx.StringData(e.State),
			"owner":     llx.StringData(e.Owner),
			"type":      llx.StringData(e.Type),
			"createdAt": llx.TimeData(e.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEndpoint)
	}

	return res, nil
}

func (r *mqlTogether) files() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Files.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, f := range resp.Data {
		var createdAt *time.Time
		if f.CreatedAt > 0 {
			t := time.Unix(f.CreatedAt, 0)
			createdAt = &t
		}

		mqlFile, err := CreateResource(r.MqlRuntime, "together.file", map[string]*llx.RawData{
			"__id":      llx.StringData(f.ID),
			"id":        llx.StringData(f.ID),
			"filename":  llx.StringData(f.Filename),
			"purpose":   llx.StringData(string(f.Purpose)),
			"fileType":  llx.StringData(string(f.FileType)),
			"bytes":     llx.IntData(f.Bytes),
			"processed": llx.BoolData(f.Processed),
			"createdAt": llx.TimeDataPtr(createdAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}

	return res, nil
}

func (r *mqlTogether) clusters() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Clusters.List(context.Background(), together.BetaClusterListParams{})
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Clusters))
	for _, c := range resp.Clusters {
		mqlCluster, err := CreateResource(r.MqlRuntime, "together.cluster", map[string]*llx.RawData{
			"__id":                 llx.StringData(c.ClusterID),
			"id":                   llx.StringData(c.ClusterID),
			"name":                 llx.StringData(c.ClusterName),
			"clusterType":          llx.StringData(string(c.ClusterType)),
			"gpuType":              llx.StringData(string(c.GPUType)),
			"numGpus":              llx.IntData(c.NumGPUs),
			"region":               llx.StringData(c.Region),
			"status":               llx.StringData(string(c.Status)),
			"billingType":          llx.StringData(string(c.BillingType)),
			"projectId":            llx.StringData(c.ProjectID),
			"cudaVersion":          llx.StringData(c.CudaVersion),
			"nvidiaDriverVersion":  llx.StringData(c.NvidiaDriverVersion),
			"numCpuWorkers":        llx.IntData(c.NumCPUWorkers),
			"oidcIssuer":           llx.StringData(c.OidcConfig.IssuerURL),
			"oidcClientId":         llx.StringData(c.OidcConfig.ClientID),
			"createdAt":            llx.TimeDataPtr(timeOrNil(c.CreatedAt)),
			"reservationStartTime": llx.TimeDataPtr(timeOrNil(c.ReservationStartTime)),
			"reservationEndTime":   llx.TimeDataPtr(timeOrNil(c.ReservationEndTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCluster)
	}

	return res, nil
}

func (r *mqlTogether) secrets() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.Secrets.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, s := range resp.Data {
		createdAt := parseTimeStr(s.CreatedAt)
		updatedAt := parseTimeStr(s.UpdatedAt)

		mqlSecret, err := CreateResource(r.MqlRuntime, "together.secret", map[string]*llx.RawData{
			"__id":          llx.StringData(s.ID),
			"id":            llx.StringData(s.ID),
			"name":          llx.StringData(s.Name),
			"description":   llx.StringData(s.Description),
			"createdBy":     llx.StringData(s.CreatedBy),
			"lastUpdatedBy": llx.StringData(s.LastUpdatedBy),
			"createdAt":     llx.TimeDataPtr(createdAt),
			"updatedAt":     llx.TimeDataPtr(updatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSecret)
	}

	return res, nil
}

// scopedProjectID reports the project a project-scoped list call has to be
// filtered to. The --project option wins when the operator set one, since a key
// with access to several projects has to be able to ask for a single one.
// Otherwise the project the API key itself resolves to is used, taken from the
// /whoami response the root resource already holds.
//
// An empty return value sends the list call out unfiltered, so a failed
// identity lookup is reported rather than swallowed: reporting objects from
// projects the scan was never pointed at is worse than reporting nothing.
func (r *mqlTogether) scopedProjectID() (string, error) {
	if project := togetherConn(r.MqlRuntime).Project(); project != "" {
		return project, nil
	}
	return r.projectId()
}

func (r *mqlTogether) clusterStorageVolumes() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)

	project, err := r.scopedProjectID()
	if err != nil {
		return nil, err
	}

	return listClusterStorageVolumes(r.MqlRuntime, conn.Client(), project)
}

// listClusterStorageVolumes lists project-scoped cluster storage volumes. The
// list endpoint accepts only a project filter and the returned volumes carry no
// cluster reference, so they belong to the account's project and are shared
// across its clusters.
//
// project is empty only for a key that resolves to no project at all. Such an
// account has nothing to filter by, and every volume the key can see is its
// own.
func listClusterStorageVolumes(runtime *plugin.Runtime, client *together.Client, project string) ([]interface{}, error) {
	params := together.BetaClusterStorageListParams{}
	if project != "" {
		params.ProjectID = together.Opt(project)
	}

	resp, err := client.Beta.Clusters.Storage.List(context.Background(), params)
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Volumes))
	for _, v := range resp.Volumes {
		mqlVol, err := CreateResource(runtime, "together.clusterStorageVolume", map[string]*llx.RawData{
			"__id":       llx.StringData(v.VolumeID),
			"volumeId":   llx.StringData(v.VolumeID),
			"volumeName": llx.StringData(v.VolumeName),
			"sizeTib":    llx.IntData(v.SizeTib),
			"status":     llx.StringData(string(v.Status)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVol)
	}

	return res, nil
}

func (r *mqlTogether) deployments() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, d := range resp.Data {
		envVarNames := make([]interface{}, 0, len(d.EnvironmentVariables))
		for _, ev := range d.EnvironmentVariables {
			envVarNames = append(envVarNames, ev.Name)
		}

		mqlDeploy, err := CreateResource(r.MqlRuntime, "together.deployment", map[string]*llx.RawData{
			"__id":                     llx.StringData(d.ID),
			"id":                       llx.StringData(d.ID),
			"name":                     llx.StringData(d.Name),
			"description":              llx.StringData(d.Description),
			"image":                    llx.StringData(d.Image),
			"status":                   llx.StringData(string(d.Status)),
			"gpuType":                  llx.StringData(string(d.GPUType)),
			"gpuCount":                 llx.IntData(d.GPUCount),
			"cpu":                      llx.FloatData(d.CPU),
			"memory":                   llx.FloatData(d.Memory),
			"storage":                  llx.IntData(d.Storage),
			"port":                     llx.IntData(d.Port),
			"healthCheckPath":          llx.StringData(d.HealthCheckPath),
			"desiredReplicas":          llx.IntData(d.DesiredReplicas),
			"readyReplicas":            llx.IntData(d.ReadyReplicas),
			"minReplicas":              llx.IntData(d.MinReplicas),
			"maxReplicas":              llx.IntData(d.MaxReplicas),
			"environmentVariableNames": llx.ArrayData(envVarNames, types.String),
			"createdAt":                llx.TimeDataPtr(timeOrNil(d.CreatedAt)),
			"updatedAt":                llx.TimeDataPtr(timeOrNil(d.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDeploy)
	}

	return res, nil
}

func (r *mqlTogether) batches() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Batches.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(*resp))
	for _, b := range *resp {
		mqlBatch, err := CreateResource(r.MqlRuntime, "together.batch", map[string]*llx.RawData{
			"__id":          llx.StringData(b.ID),
			"id":            llx.StringData(b.ID),
			"status":        llx.StringData(string(b.Status)),
			"modelId":       llx.StringData(b.ModelID),
			"endpoint":      llx.StringData(b.Endpoint),
			"inputFileId":   llx.StringData(b.InputFileID),
			"outputFileId":  llx.StringData(b.OutputFileID),
			"errorFileId":   llx.StringData(b.ErrorFileID),
			"progress":      llx.FloatData(b.Progress),
			"fileSizeBytes": llx.IntData(b.FileSizeBytes),
			"userId":        llx.StringData(b.UserID),
			"createdAt":     llx.TimeDataPtr(timeOrNil(b.CreatedAt)),
			"completedAt":   llx.TimeDataPtr(timeOrNil(b.CompletedAt)),
			"jobDeadline":   llx.TimeDataPtr(timeOrNil(b.JobDeadline)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBatch)
	}

	return res, nil
}

func (r *mqlTogether) evals() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Evals.List(context.Background(), together.EvalListParams{})
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(*resp))
	for _, e := range *resp {
		mqlEval, err := CreateResource(r.MqlRuntime, "together.eval", map[string]*llx.RawData{
			"__id":       llx.StringData(e.WorkflowID),
			"workflowId": llx.StringData(e.WorkflowID),
			"type":       llx.StringData(string(e.Type)),
			"status":     llx.StringData(string(e.Status)),
			"ownerId":    llx.StringData(e.OwnerID),
			"createdAt":  llx.TimeDataPtr(timeOrNil(e.CreatedAt)),
			"updatedAt":  llx.TimeDataPtr(timeOrNil(e.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEval)
	}

	return res, nil
}

func (r *mqlTogether) volumes() ([]interface{}, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.Volumes.List(context.Background())
	if isAccessDenied(err) {
		return []interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []interface{}{}, nil
	}

	res := make([]interface{}, 0, len(resp.Data))
	for _, v := range resp.Data {
		createdAt := parseTimeStr(v.CreatedAt)
		updatedAt := parseTimeStr(v.UpdatedAt)

		mountedBy := make([]interface{}, 0, len(v.MountedBy))
		for _, m := range v.MountedBy {
			mountedBy = append(mountedBy, m)
		}

		mqlVol, err := CreateResource(r.MqlRuntime, "together.volume", map[string]*llx.RawData{
			"__id":           llx.StringData(v.ID),
			"id":             llx.StringData(v.ID),
			"name":           llx.StringData(v.Name),
			"type":           llx.StringData(string(v.Type)),
			"currentVersion": llx.IntData(v.CurrentVersion),
			"mountedBy":      llx.ArrayData(mountedBy, types.String),
			"createdAt":      llx.TimeDataPtr(createdAt),
			"updatedAt":      llx.TimeDataPtr(updatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVol)
	}

	return res, nil
}

func (r *mqlTogetherModel) id() (string, error) {
	return r.Id.Data, nil
}

var (
	paramSizeRe = regexp.MustCompile(`[\-_](\d+(?:\.\d+)?(?:[xX]\d+)?[bBmM])[\-_]?`)
	quantRe     = regexp.MustCompile(`(?i)[\-_](fp8|fp16|fp32|int4|int8|awq|gptq|bnb|q[0-9]+_[a-z0-9_]+)[\-_]?`)
)

// knownFamilies maps the first hyphen-delimited token (after stripping the
// org prefix) to a canonical family name. Digit-stripping heuristics can't
// handle families whose name contains digits (e.g. "GPT4o"), so we use an
// explicit lookup for those.
var knownFamilies = map[string]string{
	"Llama":    "Llama",
	"Qwen":     "Qwen",
	"Mistral":  "Mistral",
	"Mixtral":  "Mixtral",
	"Gemma":    "Gemma",
	"DeepSeek": "DeepSeek",
	"DBRX":     "DBRX",
	"Yi":       "Yi",
	"Phi":      "Phi",
	"GPT4o":    "GPT4o",
}

func modelName(id string) string {
	if idx := strings.Index(id, "/"); idx >= 0 {
		return id[idx+1:]
	}
	return id
}

func (r *mqlTogetherModel) family() (string, error) {
	name := modelName(r.Id.Data)
	name = strings.TrimPrefix(name, "Meta-")
	token := strings.SplitN(name, "-", 2)[0]

	// Check known families first (handles digit-containing names like GPT4o)
	for prefix, family := range knownFamilies {
		if strings.HasPrefix(token, prefix) {
			return family, nil
		}
	}

	// Fallback: strip trailing version digits (e.g. "Falcon180" → "Falcon")
	for i, ch := range token {
		if ch >= '0' && ch <= '9' {
			if i > 0 {
				return token[:i], nil
			}
			break
		}
	}
	if token == "" {
		return name, nil
	}
	return token, nil
}

func (r *mqlTogetherModel) parameterSize() (string, error) {
	name := modelName(r.Id.Data)
	m := paramSizeRe.FindStringSubmatch(name)
	if m == nil {
		return "", nil
	}
	size := m[1]
	// Normalize: uppercase unit letter, preserve lowercase "x" for MoE (8x7B)
	last := size[len(size)-1]
	if last >= 'a' && last <= 'z' {
		size = size[:len(size)-1] + strings.ToUpper(string(last))
	}
	return size, nil
}

func (r *mqlTogetherModel) quantization() (string, error) {
	name := modelName(r.Id.Data)
	m := quantRe.FindStringSubmatch(name)
	if m != nil {
		return strings.ToLower(m[1]), nil
	}
	return "", nil
}

func (r *mqlTogetherModel) description() (string, error) {
	return r.DisplayName.Data, nil
}

func (r *mqlTogetherFineTune) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherEndpoint) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherFile) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherCluster) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherSecret) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherClusterStorageVolume) id() (string, error) {
	return r.VolumeId.Data, nil
}

func (r *mqlTogetherDeployment) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherBatch) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlTogetherEval) id() (string, error) {
	return r.WorkflowId.Data, nil
}

func (r *mqlTogetherVolume) id() (string, error) {
	return r.Id.Data, nil
}

// timeOrNil maps a zero time.Time to nil so absent SDK timestamps render as
// null instead of the year-1 zero value. The Together SDK returns optional
// timestamps as zero-valued time.Time (not pointers), so a job that has not
// completed or a cluster with no reservation window would otherwise surface
// 0001-01-01T00:00:00Z.
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func parseTimeStr(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return &t
		}
	}
	return nil
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var apierr *together.Error
	if errors.As(err, &apierr) {
		return apierr.StatusCode == 403 || apierr.StatusCode == 401
	}
	return false
}

var _ = plugin.StateIsNull

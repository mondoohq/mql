// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	together "github.com/togethercomputer/together-go"
	"github.com/togethercomputer/together-go/packages/respjson"
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
	whoami       *accountIdentity
}

// accountIdentity is the account the API key authenticates as. GET /v3/whoami
// answers with one of several credential variants (project key, organization
// key, user session), each carrying a subset of these values; a value the
// variant does not carry stays empty.
type accountIdentity struct {
	APIKeyID         string
	OrganizationID   string
	OrganizationName string
	ProjectID        string
	ProjectName      string
	UserID           string
}

func identityFromWhoami(who *together.WhoamiResponseUnion) *accountIdentity {
	return &accountIdentity{
		APIKeyID:         who.APIKey.ID,
		OrganizationID:   who.Organization.ID,
		OrganizationName: who.Organization.Name,
		ProjectID:        who.Project.ID,
		ProjectName:      who.Project.Name,
		UserID:           who.User.ID,
	}
}

// identity returns the account identity the API key actually authenticates as,
// as reported by GET /v3/whoami. It is fetched once per resource and reused.
func (r *mqlTogether) identity() (*accountIdentity, error) {
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

	r.whoami = identityFromWhoami(who)
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

func (r *mqlTogether) models() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	// The v1 model list this resource was built on is gone from together-go
	// v0.13. Models.List now lists a project's own custom models, so the
	// catalog of Together-hosted models comes from the supported-model list.
	models, err := collectPages(client.Models.ListSupported(context.Background(), together.ModelListSupportedParams{}))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(models))
	for _, m := range models {
		args := supportedModelArgs(m)
		mqlModel, err := CreateResource(r.MqlRuntime, "together.model", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModel)
	}

	return res, nil
}

// supportedModelArgs maps a supported-model catalog entry onto together.model.
// The model is keyed by its inference name (the Hugging Face style
// `org/model` identifier), which is what the field has always reported and
// what family, parameterSize and quantization parse.
func supportedModelArgs(m together.SupportedModel) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":          llx.StringData(m.Name),
		"id":            llx.StringData(m.Name),
		"displayName":   llx.StringData(m.DisplayName),
		"type":          llx.StringData(m.DisplayType),
		"organization":  llx.StringData(m.Publisher),
		"license":       llx.NilData,
		"contextLength": llx.IntDataPtr(parseContextLength(m.ContextLength)),
		"link":          llx.NilData,
		"created":       llx.TimeDataPtr(timeOrNil(m.CreatedAt)),
		"pricingInput":  llx.NilData,
		"pricingOutput": llx.NilData,
	}
	if m.Pricing.JSON.Input.Valid() {
		args["pricingInput"] = llx.FloatData(m.Pricing.Input)
	}
	if m.Pricing.JSON.Output.Valid() {
		args["pricingOutput"] = llx.FloatData(m.Pricing.Output)
	}
	if m.Description != "" {
		args["description"] = llx.StringData(m.Description)
	}
	return args
}

// parseContextLength reads the catalog's context length, which the API
// serializes as a decimal string. An absent or unreadable value is nil, not 0:
// a zero-token context window is not something a model has.
func parseContextLength(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &n
}

func (r *mqlTogether) fineTunes() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.FineTuning.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Data))
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

func (r *mqlTogether) endpoints() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	project, err := r.scopedProjectID()
	if err != nil {
		return nil, err
	}
	if project == "" {
		return nil, errors.New("together: endpoints are listed per project, and the API key resolves to no project; set --project")
	}

	endpoints, err := collectPages(client.Endpoints.List(context.Background(), together.EndpointListParams{
		ProjectID: together.Opt(project),
	}))
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(endpoints))
	for _, e := range endpoints {
		mqlEndpoint, err := CreateResource(r.MqlRuntime, "together.endpoint", endpointArgs(e))
		if err != nil {
			return nil, err
		}
		ep := mqlEndpoint.(*mqlTogetherEndpoint)
		ep.cacheProjectID = e.ProjectID
		if ep.cacheProjectID == "" {
			ep.cacheProjectID = project
		}
		res = append(res, mqlEndpoint)
	}

	return res, nil
}

func (r *mqlTogether) files() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Files.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Data))
	for _, f := range resp.Data {
		var createdAt *time.Time
		if f.CreatedAt > 0 {
			t := time.Unix(f.CreatedAt, 0)
			createdAt = &t
		}

		mqlFile, err := CreateResource(r.MqlRuntime, "together.file", map[string]*llx.RawData{
			"__id":             llx.StringData(f.ID),
			"id":               llx.StringData(f.ID),
			"filename":         llx.StringData(f.Filename),
			"purpose":          llx.StringData(string(f.Purpose)),
			"fileType":         llx.StringData(string(f.FileType)),
			"bytes":            llx.IntData(f.Bytes),
			"processed":        llx.BoolDataPtr(fileProcessed(f)),
			"processingStatus": llx.StringDataPtr(reportedString(string(f.ProcessingStatus), f.JSON.ProcessingStatus)),
			"createdAt":        llx.TimeDataPtr(createdAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}

	return res, nil
}

// fileProcessed reports whether the file validation pipeline has finished
// with the file. together-go v0.13 replaced the old Processed flag with a
// processing status, so the flag is derived from it: only COMPLETED counts as
// processed. A file that reports no status has no answer, which is null.
func fileProcessed(f together.FileResponse) *bool {
	if !f.JSON.ProcessingStatus.Valid() || f.ProcessingStatus == "" {
		return nil
	}
	done := f.ProcessingStatus == together.FileResponseProcessingStatusCompleted
	return &done
}

func (r *mqlTogether) clusters() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Clusters.List(context.Background(), together.ClusterListParams{})
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Clusters))
	for _, c := range resp.Clusters {
		nodes, err := clusterNodeResources(r.MqlRuntime, c)
		if err != nil {
			return nil, err
		}

		cfg := c.ClusterConfig
		oidc := c.OidcConfig

		mqlCluster, err := CreateResource(r.MqlRuntime, "together.cluster", map[string]*llx.RawData{
			"__id":                       llx.StringData(c.ClusterID),
			"id":                         llx.StringData(c.ClusterID),
			"name":                       llx.StringData(c.ClusterName),
			"clusterType":                llx.StringData(string(c.ClusterType)),
			"gpuType":                    llx.StringData(string(c.GPUType)),
			"numGpus":                    llx.IntData(c.NumGPUs),
			"region":                     llx.StringData(c.Region),
			"status":                     llx.StringData(string(c.Status)),
			"billingType":                llx.StringData(string(c.BillingType)),
			"projectId":                  llx.StringData(c.ProjectID),
			"cudaVersion":                llx.StringData(c.CudaVersion),
			"nvidiaDriverVersion":        llx.StringData(c.NvidiaDriverVersion),
			"numCpuWorkers":              llx.IntData(c.NumCPUWorkers),
			"oidcIssuer":                 llx.StringData(oidc.IssuerURL),
			"oidcClientId":               llx.StringData(oidc.ClientID),
			"oidcGroupClaim":             llx.StringDataPtr(reportedString(oidc.GroupClaim, oidc.JSON.GroupClaim)),
			"oidcGroupPrefix":            llx.StringDataPtr(reportedString(oidc.GroupPrefix, oidc.JSON.GroupPrefix)),
			"oidcUsernameClaim":          llx.StringDataPtr(reportedString(oidc.UsernameClaim, oidc.JSON.UsernameClaim)),
			"oidcUsernamePrefix":         llx.StringDataPtr(reportedString(oidc.UsernamePrefix, oidc.JSON.UsernamePrefix)),
			"kubernetesDashboardEnabled": llx.BoolDataPtr(reportedBool(cfg.KubernetesDashboardEnabled, cfg.JSON.KubernetesDashboardEnabled)),
			"jumphostEnabled":            llx.BoolDataPtr(reportedBool(cfg.JumphostEnabled, cfg.JSON.JumphostEnabled)),
			"sshCaEnabled":               llx.BoolDataPtr(reportedBool(cfg.SSHCaEnabled, cfg.JSON.SSHCaEnabled)),
			"loadBalancer":               llx.StringDataPtr(reportedString(cfg.LoadBalancer, cfg.JSON.LoadBalancer)),
			"ingressEnabled":             llx.BoolDataPtr(reportedBool(cfg.Ingress.Enabled, cfg.Ingress.JSON.Enabled)),
			"nodes":                      llx.ArrayData(nodes, types.Resource("together.cluster.node")),
			"createdAt":                  llx.TimeDataPtr(timeOrNil(c.CreatedAt)),
			"reservationStartTime":       llx.TimeDataPtr(timeOrNil(c.ReservationStartTime)),
			"reservationEndTime":         llx.TimeDataPtr(timeOrNil(c.ReservationEndTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCluster)
	}

	return res, nil
}

// reportedBool carries a boolean through to the schema only when the API
// actually reported it. A control the response says nothing about reaches the
// schema as null, where an equality check on it fails, rather than as a false
// that reads like a measured "not enabled".
func reportedBool(value bool, field respjson.Field) *bool {
	if !field.Valid() {
		return nil
	}
	return &value
}

// reportedString is reportedBool for strings.
func reportedString(value string, field respjson.Field) *string {
	if !field.Valid() {
		return nil
	}
	return &value
}

// Roles a node plays in a cluster. The list response keeps GPU workers and
// control plane nodes in separate collections and names neither in the record
// itself, so the role is set from the collection the node came out of.
const (
	clusterNodeRoleGPUWorker    = "GPU_WORKER"
	clusterNodeRoleControlPlane = "CONTROL_PLANE"
)

// clusterNodeRecord is the union of what a cluster's two kinds of node record
// report. A value the record does not carry stays nil and reaches the schema as
// null, so a control plane node reports no GPU count rather than a zero that
// reads as a measured one.
type clusterNodeRecord struct {
	id                     string
	hostname               string
	role                   string
	status                 string
	publicIPv4             string
	networks               []string
	memoryGib              float64
	numCPUCores            int64
	numGPUs                *int64
	instanceID             *string
	autoRemediationEnabled *bool
	markedForDeletion      *bool
}

func gpuWorkerNodeRecord(n together.ClusterGPUWorkerNode) clusterNodeRecord {
	numGPUs := n.NumGPUs
	return clusterNodeRecord{
		id:                     n.NodeID,
		hostname:               n.HostName,
		role:                   clusterNodeRoleGPUWorker,
		status:                 n.Status,
		publicIPv4:             n.PublicIpv4,
		networks:               n.Networks,
		memoryGib:              n.MemoryGib,
		numCPUCores:            n.NumCPUCores,
		numGPUs:                &numGPUs,
		instanceID:             reportedString(n.InstanceID, n.JSON.InstanceID),
		autoRemediationEnabled: reportedBool(n.AutoRemediationEnabled, n.JSON.AutoRemediationEnabled),
		markedForDeletion:      reportedBool(n.MarkedForDeletion, n.JSON.MarkedForDeletion),
	}
}

func controlPlaneNodeRecord(n together.ClusterControlPlaneNode) clusterNodeRecord {
	rec := clusterNodeRecord{
		id:          n.NodeID,
		hostname:    n.HostName,
		role:        clusterNodeRoleControlPlane,
		status:      n.Status,
		publicIPv4:  n.PublicIpv4,
		memoryGib:   n.MemoryGib,
		numCPUCores: n.NumCPUCores,
	}
	// A control plane node reports one network, where a GPU worker reports a
	// list. Both reach the same field.
	if n.Network != "" {
		rec.networks = []string{n.Network}
	}
	return rec
}

// clusterNodeID keys a node inside its cluster. A node repeats along three
// dimensions, the cluster it belongs to, the part it plays in that cluster, and
// its own identifier, so all three go into the key: two nodes sharing a key
// would be reported as one, carrying the first one's values.
//
// The node identifier is required by the API and the hostname is the fallback
// for a response that omits it anyway. The index is the last resort, and is
// there so that nodes with neither stay separate instead of collapsing onto one
// another.
func clusterNodeID(clusterID string, rec clusterNodeRecord, index int) string {
	key := rec.id
	if key == "" {
		key = rec.hostname
	}
	if key == "" {
		key = "index-" + strconv.Itoa(index)
	}
	return clusterID + "/" + rec.role + "/" + key
}

// clusterNodeResources builds the node resources of one cluster. Everything it
// reads is already in the cluster list response, so a cluster's nodes cost no
// additional API call.
func clusterNodeResources(runtime *plugin.Runtime, c together.Cluster) ([]any, error) {
	records := make([]clusterNodeRecord, 0, len(c.GPUWorkerNodes)+len(c.ControlPlaneNodes))
	for _, n := range c.GPUWorkerNodes {
		records = append(records, gpuWorkerNodeRecord(n))
	}
	for _, n := range c.ControlPlaneNodes {
		records = append(records, controlPlaneNodeRecord(n))
	}

	res := make([]any, 0, len(records))
	for i, rec := range records {
		networks := make([]any, 0, len(rec.networks))
		for _, network := range rec.networks {
			networks = append(networks, network)
		}

		mqlNode, err := CreateResource(runtime, "together.cluster.node", map[string]*llx.RawData{
			"__id":                   llx.StringData(clusterNodeID(c.ClusterID, rec, i)),
			"id":                     llx.StringData(rec.id),
			"hostname":               llx.StringData(rec.hostname),
			"role":                   llx.StringData(rec.role),
			"status":                 llx.StringData(rec.status),
			"publicIpv4":             llx.StringData(rec.publicIPv4),
			"networks":               llx.ArrayData(networks, types.String),
			"memoryGib":              llx.FloatData(rec.memoryGib),
			"numCpuCores":            llx.IntData(rec.numCPUCores),
			"numGpus":                llx.IntDataPtr(rec.numGPUs),
			"instanceId":             llx.StringDataPtr(rec.instanceID),
			"autoRemediationEnabled": llx.BoolDataPtr(rec.autoRemediationEnabled),
			"markedForDeletion":      llx.BoolDataPtr(rec.markedForDeletion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNode)
	}

	return res, nil
}

// isPublic reports whether the node answers on a public address. The list
// response carries a public IPv4 only for a node that has one.
func (r *mqlTogetherClusterNode) isPublic() (bool, error) {
	return r.PublicIpv4.Data != "", nil
}

func (r *mqlTogether) secrets() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.Secrets.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Data))
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

func (r *mqlTogether) clusterStorageVolumes() ([]any, error) {
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
func listClusterStorageVolumes(runtime *plugin.Runtime, client *together.Client, project string) ([]any, error) {
	params := together.ClusterStorageListParams{}
	if project != "" {
		params.ProjectID = together.Opt(project)
	}

	resp, err := client.Clusters.Storage.List(context.Background(), params)
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Volumes))
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

func (r *mqlTogether) deployments() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Data))
	for _, d := range resp.Data {
		envVarNames := make([]any, 0, len(d.EnvironmentVariables))
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

func (r *mqlTogether) batches() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Batches.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(*resp))
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

func (r *mqlTogether) evals() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Evals.List(context.Background(), together.EvalListParams{})
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(*resp))
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

func (r *mqlTogether) volumes() ([]any, error) {
	conn := togetherConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.Beta.Jig.Volumes.List(context.Background())
	if isAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(resp.Data))
	for _, v := range resp.Data {
		createdAt := parseTimeStr(v.CreatedAt)
		updatedAt := parseTimeStr(v.UpdatedAt)

		mountedBy := make([]any, 0, len(v.MountedBy))
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
	if _, after, ok := strings.Cut(id, "/"); ok {
		return after
	}
	return id
}

func (r *mqlTogetherModel) family() (string, error) {
	name := modelName(r.Id.Data)
	name = strings.TrimPrefix(name, "Meta-")
	token, _, _ := strings.Cut(name, "-")

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
	if apierr, ok := errors.AsType[*together.Error](err); ok {
		return apierr.StatusCode == 403 || apierr.StatusCode == 401
	}
	return false
}

// classifyRefusal wraps a 401 or 403 from the API in the matching error kind
// and returns any other error unchanged. Use it on list calls that have no
// earlier empty-list behavior to preserve.
func classifyRefusal(err error) error {
	var apierr *together.Error
	if !errors.As(err, &apierr) {
		return err
	}
	switch apierr.StatusCode {
	case 401:
		return llx.Unauthenticated(err)
	case 403:
		return llx.Forbidden(err)
	}
	return err
}

var _ = plugin.StateIsNull

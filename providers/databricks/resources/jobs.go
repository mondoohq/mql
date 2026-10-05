// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/jobs"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlDatabricksJobInternal keeps the settings the job was built from so tasks
// and job clusters map without re-listing. The list response truncates both
// collections for large jobs and reports that through hasMore, in which case the
// full settings are read once from the job detail.
type mqlDatabricksJobInternal struct {
	settings      jobs.JobSettings
	hasMore       bool
	detailFetched atomic.Bool
	detail        *jobs.Job
	detailLock    sync.Mutex

	// policyCompliant and policyViolations come from one call, fetched at most
	// once per job.
	policyComplianceOnce sync.Once
	policyCompliance     jobCompliance
}

// runAsOf resolves the identity a job executes as. Exactly one of the three name
// fields is set, and a job that sets none runs as its creator.
func runAsOf(runAs *jobs.JobRunAs, creator string) (name string, kind string) {
	if runAs != nil {
		switch {
		case runAs.UserName != "":
			return runAs.UserName, principalKindUser
		case runAs.ServicePrincipalName != "":
			return runAs.ServicePrincipalName, principalKindServicePrincipal
		case runAs.GroupName != "":
			return runAs.GroupName, principalKindGroup
		}
	}
	if creator == "" {
		return "", ""
	}
	return creator, principalKindUser
}

// notificationEmailsOf collects every address a job notifies, about a run
// outcome or about platform maintenance of a continuous job. The API groups
// addresses by event, but for review what matters is the full set of
// recipients, so the events are unioned with duplicates removed.
func notificationEmailsOf(n *jobs.JobEmailNotifications) []string {
	if n == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, group := range [][]string{
		n.OnStart, n.OnSuccess, n.OnFailure,
		n.OnDurationWarningThresholdExceeded, n.OnStreamingBacklogExceeded,
		n.OnMaintenanceStart, n.OnMaintenanceComplete,
	} {
		for _, addr := range group {
			if addr == "" {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

// webhookNotificationIdsOf collects the notification destinations webhooks are
// sent to, unioned across run and maintenance events for the same reason as the
// email addresses.
func webhookNotificationIdsOf(n *jobs.WebhookNotifications) []string {
	if n == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, group := range [][]jobs.Webhook{
		n.OnStart, n.OnSuccess, n.OnFailure,
		n.OnDurationWarningThresholdExceeded, n.OnStreamingBacklogExceeded,
		n.OnMaintenanceStart, n.OnMaintenanceComplete,
	} {
		for i := range group {
			id := group[i].Id
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// jobLibrariesToDict flattens each task library to its type and the coordinate
// or path it resolves to, matching the shape pipelineLibraryToDict produces so
// both collections are queried the same way. The library is a union in which
// exactly one source field is set, and only JSON-native values are used, as llx
// dicts accept nothing else.
func jobLibrariesToDict(libs []compute.Library) []any {
	out := make([]any, 0, len(libs))
	for i := range libs {
		l := libs[i]
		var entry map[string]any
		switch {
		case l.Maven != nil:
			entry = map[string]any{
				"type":       "maven",
				"coordinate": l.Maven.Coordinates,
				"repository": l.Maven.Repo,
			}
		case l.Pypi != nil:
			entry = map[string]any{
				"type":       "pypi",
				"coordinate": l.Pypi.Package,
				"repository": l.Pypi.Repo,
			}
		case l.Cran != nil:
			entry = map[string]any{
				"type":       "cran",
				"coordinate": l.Cran.Package,
				"repository": l.Cran.Repo,
			}
		case l.Jar != "":
			entry = map[string]any{"type": "jar", "path": l.Jar}
		case l.Whl != "":
			entry = map[string]any{"type": "whl", "path": l.Whl}
		case l.Egg != "":
			entry = map[string]any{"type": "egg", "path": l.Egg}
		case l.Requirements != "":
			entry = map[string]any{"type": "requirements", "path": l.Requirements}
		default:
			// A library whose source this SDK version does not model still needs
			// to appear, otherwise the list silently under-reports.
			entry = map[string]any{"type": "", "path": ""}
		}
		out = append(out, entry)
	}
	return out
}

func (r *mqlDatabricks) jobs() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// ExpandTasks makes the list return each job's tasks and job clusters, which
	// avoids a Get per job. Jobs above the expansion limit still need the detail
	// call, and flag that through HasMore.
	list, err := ws.Jobs.ListAll(context.Background(), jobs.ListJobsRequest{ExpandTasks: true})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range list {
		res, err := newMqlDatabricksJob(r.MqlRuntime, list[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlDatabricksJob(runtime *plugin.Runtime, job jobs.BaseJob) (*mqlDatabricksJob, error) {
	settings := jobs.JobSettings{}
	if job.Settings != nil {
		settings = *job.Settings
	}

	runAs, runAsType := runAsOf(settings.RunAs, job.CreatorUserName)

	scheduleCron := ""
	scheduleTimezone := ""
	schedulePause := ""
	if settings.Schedule != nil {
		scheduleCron = settings.Schedule.QuartzCronExpression
		scheduleTimezone = settings.Schedule.TimezoneId
		schedulePause = string(settings.Schedule.PauseStatus)
	}

	continuousPause := ""
	// A job with no maintenance window reports the three window fields as null
	// rather than as ""/0: start hour 0 is a legitimate window (midnight), so a
	// zero value would report a real window on every job that sets none.
	maintenanceDayOfWeek := llx.NilData
	maintenanceStartHour := llx.NilData
	maintenanceTimezoneId := llx.NilData
	if settings.Continuous != nil {
		continuousPause = string(settings.Continuous.PauseStatus)
		if w := settings.Continuous.MaintenanceWindow; w != nil {
			maintenanceDayOfWeek = llx.StringData(string(w.DayOfWeek))
			maintenanceStartHour = llx.IntData(int64(w.StartHour))
			maintenanceTimezoneId = llx.StringData(w.TimezoneId)
		}
	}

	deploymentKind := ""
	deploymentId := ""
	if settings.Deployment != nil {
		deploymentKind = string(settings.Deployment.Kind)
		deploymentId = settings.Deployment.DeploymentId
	}

	gitUrl := ""
	gitProvider := ""
	gitBranch := ""
	gitTag := ""
	gitCommit := ""
	if settings.GitSource != nil {
		gitUrl = settings.GitSource.GitUrl
		gitProvider = string(settings.GitSource.GitProvider)
		gitBranch = settings.GitSource.GitBranch
		gitTag = settings.GitSource.GitTag
		gitCommit = settings.GitSource.GitCommit
	}

	jobId := strconv.FormatInt(job.JobId, 10)
	res, err := CreateResource(runtime, "databricks.job", map[string]*llx.RawData{
		"__id":                                  llx.StringData("databricks.job/" + jobId),
		"id":                                    llx.IntData(job.JobId),
		"name":                                  llx.StringData(settings.Name),
		"description":                           llx.StringData(settings.Description),
		"createdTime":                           llx.TimeDataPtr(epochMsTime(job.CreatedTime)),
		"creatorUserName":                       llx.StringData(job.CreatorUserName),
		"runAs":                                 llx.StringData(runAs),
		"runAsType":                             llx.StringData(runAsType),
		"format":                                llx.StringData(string(settings.Format)),
		"editMode":                              llx.StringData(string(settings.EditMode)),
		"maxConcurrentRuns":                     llx.IntData(int64(settings.MaxConcurrentRuns)),
		"timeoutSeconds":                        llx.IntData(int64(settings.TimeoutSeconds)),
		"tags":                                  llx.MapData(strMap(settings.Tags), types.String),
		"scheduleCronExpression":                llx.StringData(scheduleCron),
		"scheduleTimezoneId":                    llx.StringData(scheduleTimezone),
		"schedulePauseStatus":                   llx.StringData(schedulePause),
		"continuousPauseStatus":                 llx.StringData(continuousPause),
		"continuousMaintenanceWindowDayOfWeek":  maintenanceDayOfWeek,
		"continuousMaintenanceWindowStartHour":  maintenanceStartHour,
		"continuousMaintenanceWindowTimezoneId": maintenanceTimezoneId,
		"performanceTarget":                     llx.StringData(string(settings.PerformanceTarget)),
		"deploymentKind":                        llx.StringData(deploymentKind),
		"deploymentId":                          llx.StringData(deploymentId),
		"parentPath":                            llx.StringData(settings.ParentPath),
		"gitUrl":                                llx.StringData(gitUrl),
		"gitProvider":                           llx.StringData(gitProvider),
		"gitBranch":                             llx.StringData(gitBranch),
		"gitTag":                                llx.StringData(gitTag),
		"gitCommit":                             llx.StringData(gitCommit),
		"notificationEmails":                    llx.ArrayData(strSlice(notificationEmailsOf(settings.EmailNotifications)), types.String),
		"webhookNotificationIds":                llx.ArrayData(strSlice(webhookNotificationIdsOf(settings.WebhookNotifications)), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlJob := res.(*mqlDatabricksJob)
	mqlJob.settings = settings
	mqlJob.hasMore = job.HasMore
	return mqlJob, nil
}

// jobSettings returns the settings to read tasks and job clusters from. The list
// response is authoritative unless it reported truncation, in which case the
// full settings are fetched once and memoized.
func (r *mqlDatabricksJob) jobSettings() (jobs.JobSettings, error) {
	if !r.hasMore {
		return r.settings, nil
	}
	detail, err := r.jobDetail()
	if err != nil {
		return jobs.JobSettings{}, err
	}
	return settingsOf(detail, r.settings), nil
}

// jobDetail reads the job through the get endpoint once and memoizes it.
func (r *mqlDatabricksJob) jobDetail() (*jobs.Job, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	detail, err := ws.Jobs.GetByJobId(context.Background(), r.Id.Data)
	if err != nil {
		return nil, err
	}
	r.detail = detail
	r.detailFetched.Store(true)
	return r.detail, nil
}

// jobEnvironmentVariables returns the job's named environment variable
// entries.
func (r *mqlDatabricksJob) jobEnvironmentVariables() ([]jobs.JobEnvironmentVariables, error) {
	settings, err := r.jobSettings()
	if err != nil {
		return nil, err
	}
	return environmentVariablesOf(settings, r.jobDetail)
}

// environmentVariablesOf picks the environment variable entries out of the
// settings the job was listed with. The list endpoint is not documented to
// carry this block, so an empty block is confirmed against the job detail
// rather than reported as "none": a job whose entries were left out of the list
// would otherwise read as defining no variables at all.
func environmentVariablesOf(settings jobs.JobSettings, detail func() (*jobs.Job, error)) ([]jobs.JobEnvironmentVariables, error) {
	if len(settings.EnvironmentVariables) > 0 {
		return settings.EnvironmentVariables, nil
	}
	d, err := detail()
	if err != nil {
		return nil, err
	}
	return settingsOf(d, settings).EnvironmentVariables, nil
}

// environmentVariableNamesOf collects the names of the variables a job sets
// inline, across all of its entries, sorted and with duplicates removed. Values
// are never read: they are free-form strings that may hold credentials.
func environmentVariableNamesOf(entries []jobs.JobEnvironmentVariables) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for i := range entries {
		if entries[i].Spec == nil {
			continue
		}
		for name := range entries[i].Spec.Variables {
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// environmentVariableFilesOf collects the paths of the .env files a job loads,
// across all of its entries, in declaration order with duplicates removed.
func environmentVariableFilesOf(entries []jobs.JobEnvironmentVariables) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for i := range entries {
		if entries[i].Spec == nil {
			continue
		}
		for _, path := range entries[i].Spec.Files {
			if path == "" {
				continue
			}
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

func (r *mqlDatabricksJob) environmentVariableNames() ([]any, error) {
	entries, err := r.jobEnvironmentVariables()
	if err != nil {
		return nil, err
	}
	return strSlice(environmentVariableNamesOf(entries)), nil
}

func (r *mqlDatabricksJob) environmentVariableFiles() ([]any, error) {
	entries, err := r.jobEnvironmentVariables()
	if err != nil {
		return nil, err
	}
	return strSlice(environmentVariableFilesOf(entries)), nil
}

// settingsOf prefers the detail settings, falling back to the truncated list
// settings when the detail carries none.
func settingsOf(detail *jobs.Job, fallback jobs.JobSettings) jobs.JobSettings {
	if detail != nil && detail.Settings != nil {
		return *detail.Settings
	}
	return fallback
}

func (r *mqlDatabricksJob) jobClusters() ([]any, error) {
	settings, err := r.jobSettings()
	if err != nil {
		return nil, err
	}

	idPrefix := "databricks.job/" + strconv.FormatInt(r.Id.Data, 10)
	out := []any{}
	for i := range settings.JobClusters {
		jc := settings.JobClusters[i]

		// NewCluster became a pointer in SDK v0.172. The API requires it
		// alongside the key, so nil means a shape we do not understand: report
		// the cluster with its key and an empty spec rather than dropping it
		// from the list, which would read as a job with fewer clusters.
		spec := compute.ClusterSpec{}
		if jc.NewCluster != nil {
			spec = *jc.NewCluster
		}

		res, err := newMqlDatabricksClusterSpec(r.MqlRuntime, idPrefix, jobClusterSpecFields(jc.JobClusterKey, spec))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// triggerTypeOf names the kind of source that starts a run. A trigger
// configuration is a union in which exactly one kind member is populated, and
// the populated member is the discriminator. The default branch reports unknown
// so a kind the SDK models but this provider does not classify still appears in
// the list rather than vanishing from it.
func triggerTypeOf(t jobs.TriggerConfiguration) string {
	switch {
	case t.Schedule != nil:
		return "schedule"
	case t.Periodic != nil:
		return "periodic"
	case t.FileArrival != nil:
		return "file_arrival"
	case t.TableUpdate != nil:
		return "table_update"
	case t.Model != nil:
		return "model"
	case t.Continuous != nil:
		return "continuous"
	default:
		return "unknown"
	}
}

func (r *mqlDatabricksJob) triggers() ([]any, error) {
	settings, err := r.jobSettings()
	if err != nil {
		return nil, err
	}

	jobId := strconv.FormatInt(r.Id.Data, 10)
	out := []any{}
	for i := range settings.Triggers {
		t := settings.Triggers[i]

		// Only the members belonging to the trigger's own kind carry values.
		// The rest stay at their zero value, which is what the schema documents
		// for a field that does not apply to this kind.
		args := map[string]*llx.RawData{
			// A trigger carries no key of its own, so the cache id is the job
			// plus the position in the list. That is the order the API returns
			// and the order TriggerDetails is aligned to.
			"__id":                          llx.StringData("databricks.job/" + jobId + "/trigger/" + strconv.Itoa(i)),
			"triggerType":                   llx.StringData(triggerTypeOf(t)),
			"pauseStatus":                   llx.StringData(string(t.PauseStatus)),
			"cronExpression":                llx.StringData(""),
			"timezoneId":                    llx.StringData(""),
			"periodicInterval":              llx.IntData(0),
			"periodicUnit":                  llx.StringData(""),
			"fileArrivalUrl":                llx.StringData(""),
			"tableNames":                    llx.ArrayData([]any{}, types.String),
			"tableUpdateCondition":          llx.StringData(""),
			"modelSecurableName":            llx.StringData(""),
			"modelCondition":                llx.StringData(""),
			"modelAliases":                  llx.ArrayData([]any{}, types.String),
			"continuousTaskRetryMode":       llx.StringData(""),
			"minTimeBetweenTriggersSeconds": llx.IntData(0),
			"waitAfterLastChangeSeconds":    llx.IntData(0),
			"sqlConditionQueryId":           llx.StringData(""),
			"sqlConditionWarehouseId":       llx.StringData(""),
			"sqlConditionTriggerMode":       llx.StringData(""),
		}

		switch {
		case t.Schedule != nil:
			args["cronExpression"] = llx.StringData(t.Schedule.QuartzCronExpression)
			args["timezoneId"] = llx.StringData(t.Schedule.TimezoneId)
		case t.Periodic != nil:
			args["periodicInterval"] = llx.IntData(int64(t.Periodic.Interval))
			args["periodicUnit"] = llx.StringData(string(t.Periodic.Unit))
		case t.FileArrival != nil:
			args["fileArrivalUrl"] = llx.StringData(t.FileArrival.Url)
			args["minTimeBetweenTriggersSeconds"] = llx.IntData(int64(t.FileArrival.MinTimeBetweenTriggersSeconds))
			args["waitAfterLastChangeSeconds"] = llx.IntData(int64(t.FileArrival.WaitAfterLastChangeSeconds))
		case t.TableUpdate != nil:
			args["tableNames"] = llx.ArrayData(strSlice(t.TableUpdate.TableNames), types.String)
			args["tableUpdateCondition"] = llx.StringData(string(t.TableUpdate.Condition))
			args["minTimeBetweenTriggersSeconds"] = llx.IntData(int64(t.TableUpdate.MinTimeBetweenTriggersSeconds))
			args["waitAfterLastChangeSeconds"] = llx.IntData(int64(t.TableUpdate.WaitAfterLastChangeSeconds))
		case t.Model != nil:
			args["modelSecurableName"] = llx.StringData(t.Model.SecurableName)
			args["modelCondition"] = llx.StringData(string(t.Model.Condition))
			args["modelAliases"] = llx.ArrayData(strSlice(t.Model.Aliases), types.String)
			args["minTimeBetweenTriggersSeconds"] = llx.IntData(int64(t.Model.MinTimeBetweenTriggersSeconds))
		case t.Continuous != nil:
			args["continuousTaskRetryMode"] = llx.StringData(string(t.Continuous.TaskRetryMode))
		}

		if c := t.SqlCondition; c != nil {
			args["sqlConditionQueryId"] = llx.StringData(c.SqlQueryId)
			args["sqlConditionWarehouseId"] = llx.StringData(c.WarehouseId)
			args["sqlConditionTriggerMode"] = llx.StringData(string(c.TriggerMode))
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.job.trigger", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// taskTypeOf names the kind of work a task performs. The task is a union in
// which exactly one work field is set, so the set field is the discriminator. An
// empty result means the task uses a kind this SDK version does not model, which
// is reported as empty rather than guessed at.
func taskTypeOf(t jobs.Task) string {
	switch {
	case t.NotebookTask != nil:
		return "notebook"
	case t.SparkJarTask != nil:
		return "spark_jar"
	case t.SparkPythonTask != nil:
		return "spark_python"
	case t.SparkSubmitTask != nil:
		return "spark_submit"
	case t.PipelineTask != nil:
		return "pipeline"
	case t.SqlTask != nil:
		return "sql"
	case t.DbtTask != nil:
		return "dbt"
	case t.DbtCloudTask != nil:
		return "dbt_cloud"
	case t.DbtPlatformTask != nil:
		return "dbt_platform"
	case t.PythonWheelTask != nil:
		return "python_wheel"
	case t.PythonOperatorTask != nil:
		return "python_operator"
	case t.RunJobTask != nil:
		return "run_job"
	case t.ConditionTask != nil:
		return "condition"
	case t.ForEachTask != nil:
		return "for_each"
	case t.DashboardTask != nil:
		return "dashboard"
	case t.PowerBiTask != nil:
		return "power_bi"
	case t.AlertTask != nil:
		return "alert"
	case t.CleanRoomsNotebookTask != nil:
		return "clean_rooms_notebook"
	case t.AiRuntimeTask != nil:
		return "ai_runtime"
	case t.GenAiComputeTask != nil:
		return "gen_ai_compute"
	}
	return ""
}

func (r *mqlDatabricksJob) tasks() ([]any, error) {
	settings, err := r.jobSettings()
	if err != nil {
		return nil, err
	}

	jobId := strconv.FormatInt(r.Id.Data, 10)
	out := []any{}
	for i := range settings.Tasks {
		t := settings.Tasks[i]

		notebookPath := ""
		notebookSource := ""
		if t.NotebookTask != nil {
			notebookPath = t.NotebookTask.NotebookPath
			notebookSource = string(t.NotebookTask.Source)
		}

		sparkJarMainClass := ""
		if t.SparkJarTask != nil {
			sparkJarMainClass = t.SparkJarTask.MainClassName
		}

		sparkPythonFile := ""
		if t.SparkPythonTask != nil {
			sparkPythonFile = t.SparkPythonTask.PythonFile
		}

		var sparkSubmitParameters []string
		if t.SparkSubmitTask != nil {
			sparkSubmitParameters = t.SparkSubmitTask.Parameters
		}

		var dbtCommands []string
		if t.DbtTask != nil {
			dbtCommands = t.DbtTask.Commands
		}

		alertParameters := map[string]any{}
		if t.AlertTask != nil {
			for k, v := range t.AlertTask.Parameters {
				alertParameters[k] = v
			}
		}

		dependsOn := make([]string, 0, len(t.DependsOn))
		for j := range t.DependsOn {
			dependsOn = append(dependsOn, t.DependsOn[j].TaskKey)
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.job.task", map[string]*llx.RawData{
			"__id":                    llx.StringData("databricks.job/" + jobId + "/task/" + t.TaskKey),
			"taskKey":                 llx.StringData(t.TaskKey),
			"description":             llx.StringData(t.Description),
			"taskType":                llx.StringData(taskTypeOf(t)),
			"disabled":                llx.BoolData(t.Disabled),
			"notebookPath":            llx.StringData(notebookPath),
			"notebookSource":          llx.StringData(notebookSource),
			"sparkJarMainClass":       llx.StringData(sparkJarMainClass),
			"sparkPythonFile":         llx.StringData(sparkPythonFile),
			"sparkSubmitParameters":   llx.ArrayData(strSlice(sparkSubmitParameters), types.String),
			"alertParameters":         llx.MapData(alertParameters, types.String),
			"dbtCommands":             llx.ArrayData(strSlice(dbtCommands), types.String),
			"libraries":               llx.ArrayData(jobLibrariesToDict(t.Libraries), types.Dict),
			"dependsOn":               llx.ArrayData(strSlice(dependsOn), types.String),
			"maxRetries":              llx.IntData(int64(t.MaxRetries)),
			"timeoutSeconds":          llx.IntData(int64(t.TimeoutSeconds)),
			"jobClusterKey":           llx.StringData(t.JobClusterKey),
			"environmentVariablesKey": llx.StringData(t.EnvironmentVariablesKey),
		})
		if err != nil {
			return nil, err
		}
		mqlTask := res.(*mqlDatabricksJobTask)
		mqlTask.jobId = jobId
		mqlTask.cacheExistingClusterId = t.ExistingClusterId
		mqlTask.newClusterSpec = t.NewCluster
		if t.PipelineTask != nil {
			mqlTask.cachePipelineId = t.PipelineTask.PipelineId
		}
		out = append(out, mqlTask)
	}
	return out, nil
}

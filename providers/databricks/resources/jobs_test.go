// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/jobs"
	"github.com/databricks/databricks-sdk-go/service/pipelines"
)

func TestPrincipalOf(t *testing.T) {
	tests := []struct {
		name     string
		ac       iam.AccessControlResponse
		wantName string
		wantKind string
	}{
		{
			name:     "user",
			ac:       iam.AccessControlResponse{UserName: "ada@example.com"},
			wantName: "ada@example.com",
			wantKind: principalKindUser,
		},
		{
			name:     "group",
			ac:       iam.AccessControlResponse{GroupName: "data-eng"},
			wantName: "data-eng",
			wantKind: principalKindGroup,
		},
		{
			name:     "service principal",
			ac:       iam.AccessControlResponse{ServicePrincipalName: "9f1c-app-id"},
			wantName: "9f1c-app-id",
			wantKind: principalKindServicePrincipal,
		},
		{
			// An entry naming nobody is unattributable and must be reported as
			// empty so the caller drops it rather than emitting a permission
			// held by "".
			name:     "no principal named",
			ac:       iam.AccessControlResponse{DisplayName: "orphan"},
			wantName: "",
			wantKind: "",
		},
		{
			// The user field wins when more than one is somehow populated, which
			// keeps the classification deterministic.
			name:     "user takes precedence over group",
			ac:       iam.AccessControlResponse{UserName: "ada@example.com", GroupName: "data-eng"},
			wantName: "ada@example.com",
			wantKind: principalKindUser,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotKind := principalOf(tc.ac)
			if gotName != tc.wantName || gotKind != tc.wantKind {
				t.Fatalf("principalOf() = (%q, %q), want (%q, %q)", gotName, gotKind, tc.wantName, tc.wantKind)
			}
		})
	}
}

func TestRunAsOf(t *testing.T) {
	tests := []struct {
		name     string
		runAs    *jobs.JobRunAs
		creator  string
		wantName string
		wantKind string
	}{
		{
			name:     "explicit user",
			runAs:    &jobs.JobRunAs{UserName: "ada@example.com"},
			creator:  "grace@example.com",
			wantName: "ada@example.com",
			wantKind: principalKindUser,
		},
		{
			name:     "explicit service principal",
			runAs:    &jobs.JobRunAs{ServicePrincipalName: "9f1c-app-id"},
			creator:  "grace@example.com",
			wantName: "9f1c-app-id",
			wantKind: principalKindServicePrincipal,
		},
		{
			name:     "explicit group",
			runAs:    &jobs.JobRunAs{GroupName: "data-eng"},
			creator:  "grace@example.com",
			wantName: "data-eng",
			wantKind: principalKindGroup,
		},
		{
			// A job that sets no run-as identity runs as whoever created it, so
			// reporting the creator is what the platform actually does rather
			// than a guess.
			name:     "falls back to creator",
			runAs:    nil,
			creator:  "grace@example.com",
			wantName: "grace@example.com",
			wantKind: principalKindUser,
		},
		{
			name:     "empty run-as struct falls back to creator",
			runAs:    &jobs.JobRunAs{},
			creator:  "grace@example.com",
			wantName: "grace@example.com",
			wantKind: principalKindUser,
		},
		{
			name:     "no identity at all",
			runAs:    nil,
			creator:  "",
			wantName: "",
			wantKind: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotKind := runAsOf(tc.runAs, tc.creator)
			if gotName != tc.wantName || gotKind != tc.wantKind {
				t.Fatalf("runAsOf() = (%q, %q), want (%q, %q)", gotName, gotKind, tc.wantName, tc.wantKind)
			}
		})
	}
}

func TestNotificationEmailsOf(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		if got := notificationEmailsOf(nil); got != nil {
			t.Fatalf("notificationEmailsOf(nil) = %v, want nil", got)
		}
	})

	t.Run("unions events and drops duplicates and blanks", func(t *testing.T) {
		got := notificationEmailsOf(&jobs.JobEmailNotifications{
			OnStart:                            []string{"a@example.com", ""},
			OnSuccess:                          []string{"a@example.com", "b@example.com"},
			OnFailure:                          []string{"c@example.com"},
			OnDurationWarningThresholdExceeded: []string{"b@example.com"},
			OnStreamingBacklogExceeded:         []string{"d@example.com"},
		})
		want := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("notificationEmailsOf() = %v, want %v", got, want)
		}
	})

	t.Run("includes maintenance-only recipients", func(t *testing.T) {
		got := notificationEmailsOf(&jobs.JobEmailNotifications{
			OnFailure:             []string{"oncall@example.com"},
			OnMaintenanceStart:    []string{"platform@example.com", "oncall@example.com"},
			OnMaintenanceComplete: []string{"ops@example.com"},
		})
		want := []string{"oncall@example.com", "platform@example.com", "ops@example.com"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("notificationEmailsOf() = %v, want %v", got, want)
		}
	})

	t.Run("empty notifications yield empty slice", func(t *testing.T) {
		got := notificationEmailsOf(&jobs.JobEmailNotifications{})
		if len(got) != 0 {
			t.Fatalf("notificationEmailsOf() = %v, want empty", got)
		}
	})
}

func TestWebhookNotificationIdsOf(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		if got := webhookNotificationIdsOf(nil); got != nil {
			t.Fatalf("webhookNotificationIdsOf(nil) = %v, want nil", got)
		}
	})

	t.Run("unions events and drops duplicates and blanks", func(t *testing.T) {
		got := webhookNotificationIdsOf(&jobs.WebhookNotifications{
			OnStart:   []jobs.Webhook{{Id: "hook-1"}, {Id: ""}},
			OnSuccess: []jobs.Webhook{{Id: "hook-1"}, {Id: "hook-2"}},
			OnFailure: []jobs.Webhook{{Id: "hook-3"}},
		})
		want := []string{"hook-1", "hook-2", "hook-3"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("webhookNotificationIdsOf() = %v, want %v", got, want)
		}
	})

	t.Run("includes maintenance-only destinations", func(t *testing.T) {
		got := webhookNotificationIdsOf(&jobs.WebhookNotifications{
			OnSuccess:             []jobs.Webhook{{Id: "hook-1"}},
			OnMaintenanceStart:    []jobs.Webhook{{Id: "hook-2"}, {Id: "hook-1"}},
			OnMaintenanceComplete: []jobs.Webhook{{Id: "hook-3"}, {Id: ""}},
		})
		want := []string{"hook-1", "hook-2", "hook-3"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("webhookNotificationIdsOf() = %v, want %v", got, want)
		}
	})
}

func TestEnvironmentVariableNamesOf(t *testing.T) {
	t.Run("nil entries yield empty slice", func(t *testing.T) {
		got := environmentVariableNamesOf(nil)
		if got == nil || len(got) != 0 {
			t.Fatalf("environmentVariableNamesOf(nil) = %#v, want empty non-nil", got)
		}
	})

	t.Run("unions names across entries, sorted, without values", func(t *testing.T) {
		got := environmentVariableNamesOf([]jobs.JobEnvironmentVariables{
			{EnvironmentVariablesKey: "default", Spec: &jobs.JobEnvironmentVariablesSpec{
				Variables: map[string]string{"STAGE": "prod", "DB_PASSWORD": "hunter2", "": "x"},
			}},
			{EnvironmentVariablesKey: "no-spec"},
			{EnvironmentVariablesKey: "etl", Spec: &jobs.JobEnvironmentVariablesSpec{
				Variables: map[string]string{"STAGE": "dev", "API_TOKEN": "s3cret"},
				Files:     []string{"/Volumes/main/env/etl.env"},
			}},
		})
		want := []string{"API_TOKEN", "DB_PASSWORD", "STAGE"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("environmentVariableNamesOf() = %v, want %v", got, want)
		}
	})
}

func TestEnvironmentVariableFilesOf(t *testing.T) {
	t.Run("nil entries yield empty slice", func(t *testing.T) {
		got := environmentVariableFilesOf(nil)
		if got == nil || len(got) != 0 {
			t.Fatalf("environmentVariableFilesOf(nil) = %#v, want empty non-nil", got)
		}
	})

	t.Run("unions files across entries in order without duplicates", func(t *testing.T) {
		got := environmentVariableFilesOf([]jobs.JobEnvironmentVariables{
			{EnvironmentVariablesKey: "default", Spec: &jobs.JobEnvironmentVariablesSpec{
				Files:     []string{"/Workspace/Shared/base.env", ""},
				Variables: map[string]string{"STAGE": "prod"},
			}},
			{EnvironmentVariablesKey: "no-spec"},
			{EnvironmentVariablesKey: "etl", Spec: &jobs.JobEnvironmentVariablesSpec{
				Files: []string{"/Volumes/main/env/etl.env", "/Workspace/Shared/base.env"},
			}},
		})
		want := []string{"/Workspace/Shared/base.env", "/Volumes/main/env/etl.env"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("environmentVariableFilesOf() = %v, want %v", got, want)
		}
	})
}

func TestTaskTypeOf(t *testing.T) {
	tests := []struct {
		name string
		task jobs.Task
		want string
	}{
		{name: "notebook", task: jobs.Task{NotebookTask: &jobs.NotebookTask{}}, want: "notebook"},
		{name: "spark jar", task: jobs.Task{SparkJarTask: &jobs.SparkJarTask{}}, want: "spark_jar"},
		{name: "spark python", task: jobs.Task{SparkPythonTask: &jobs.SparkPythonTask{}}, want: "spark_python"},
		{name: "spark submit", task: jobs.Task{SparkSubmitTask: &jobs.SparkSubmitTask{}}, want: "spark_submit"},
		{name: "pipeline", task: jobs.Task{PipelineTask: &jobs.PipelineTask{}}, want: "pipeline"},
		{name: "sql", task: jobs.Task{SqlTask: &jobs.SqlTask{}}, want: "sql"},
		{name: "dbt", task: jobs.Task{DbtTask: &jobs.DbtTask{}}, want: "dbt"},
		{name: "python wheel", task: jobs.Task{PythonWheelTask: &jobs.PythonWheelTask{}}, want: "python_wheel"},
		{name: "run job", task: jobs.Task{RunJobTask: &jobs.RunJobTask{}}, want: "run_job"},
		{name: "condition", task: jobs.Task{ConditionTask: &jobs.ConditionTask{}}, want: "condition"},
		{name: "for each", task: jobs.Task{ForEachTask: &jobs.ForEachTask{}}, want: "for_each"},
		{name: "dbt cloud", task: jobs.Task{DbtCloudTask: &jobs.DbtCloudTask{}}, want: "dbt_cloud"},
		{name: "dbt platform", task: jobs.Task{DbtPlatformTask: &jobs.DbtPlatformTask{}}, want: "dbt_platform"},
		{name: "python operator", task: jobs.Task{PythonOperatorTask: &jobs.PythonOperatorTask{}}, want: "python_operator"},
		{name: "dashboard", task: jobs.Task{DashboardTask: &jobs.DashboardTask{}}, want: "dashboard"},
		{name: "power bi", task: jobs.Task{PowerBiTask: &jobs.PowerBiTask{}}, want: "power_bi"},
		{name: "alert", task: jobs.Task{AlertTask: &jobs.AlertTask{}}, want: "alert"},
		{name: "clean rooms notebook", task: jobs.Task{CleanRoomsNotebookTask: &jobs.CleanRoomsNotebookTask{}}, want: "clean_rooms_notebook"},
		{name: "ai runtime", task: jobs.Task{AiRuntimeTask: &jobs.AiRuntimeTask{}}, want: "ai_runtime"},
		{name: "gen ai compute", task: jobs.Task{GenAiComputeTask: &jobs.GenAiComputeTask{}}, want: "gen_ai_compute"},
		// A task carrying no work field at all is a kind this SDK version does
		// not model. Reporting empty is honest; guessing a type would be worse
		// than admitting the gap.
		{name: "unmodelled kind", task: jobs.Task{TaskKey: "mystery"}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := taskTypeOf(tc.task); got != tc.want {
				t.Fatalf("taskTypeOf() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJobLibrariesToDict(t *testing.T) {
	got := jobLibrariesToDict([]compute.Library{
		{Maven: &compute.MavenLibrary{Coordinates: "org.example:lib:1.0", Repo: "https://repo.example.com"}},
		{Pypi: &compute.PythonPyPiLibrary{Package: "requests==2.0", Repo: "https://pypi.example.com"}},
		{Cran: &compute.RCranLibrary{Package: "ggplot2", Repo: "https://cran.example.com"}},
		{Jar: "dbfs:/libs/app.jar"},
		{Whl: "/Volumes/main/default/vol/app.whl"},
		{Egg: "dbfs:/libs/legacy.egg"},
		{Requirements: "/Workspace/Repos/app/requirements.txt"},
		// An entry with no source set still has to appear, otherwise the list
		// silently under-reports what the task installs.
		{},
	})

	want := []any{
		map[string]any{"type": "maven", "coordinate": "org.example:lib:1.0", "repository": "https://repo.example.com"},
		map[string]any{"type": "pypi", "coordinate": "requests==2.0", "repository": "https://pypi.example.com"},
		map[string]any{"type": "cran", "coordinate": "ggplot2", "repository": "https://cran.example.com"},
		map[string]any{"type": "jar", "path": "dbfs:/libs/app.jar"},
		map[string]any{"type": "whl", "path": "/Volumes/main/default/vol/app.whl"},
		map[string]any{"type": "egg", "path": "dbfs:/libs/legacy.egg"},
		map[string]any{"type": "requirements", "path": "/Workspace/Repos/app/requirements.txt"},
		map[string]any{"type": "", "path": ""},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("jobLibrariesToDict() = %#v, want %#v", got, want)
	}
}

func TestPipelineLibraryToDict(t *testing.T) {
	got := pipelineLibraryToDict([]pipelines.PipelineLibrary{
		{Notebook: &pipelines.NotebookLibrary{Path: "/Workspace/dlt/bronze"}},
		{File: &pipelines.FileLibrary{Path: "/Workspace/dlt/silver.py"}},
		{Glob: &pipelines.PathPattern{Include: "/Workspace/dlt/**"}},
		{Maven: &compute.MavenLibrary{Coordinates: "org.example:lib:1.0", Repo: "https://repo.example.com"}},
		{Jar: "dbfs:/libs/app.jar"},
		{Whl: "/Volumes/main/default/vol/app.whl"},
		{},
	})

	want := []any{
		map[string]any{"type": "notebook", "path": "/Workspace/dlt/bronze"},
		map[string]any{"type": "file", "path": "/Workspace/dlt/silver.py"},
		map[string]any{"type": "glob", "path": "/Workspace/dlt/**"},
		map[string]any{"type": "maven", "coordinate": "org.example:lib:1.0", "repository": "https://repo.example.com"},
		map[string]any{"type": "jar", "path": "dbfs:/libs/app.jar"},
		map[string]any{"type": "whl", "path": "/Volumes/main/default/vol/app.whl"},
		map[string]any{"type": "", "path": ""},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pipelineLibraryToDict() = %#v, want %#v", got, want)
	}
}

func TestJobClusterSpecFields(t *testing.T) {
	got := jobClusterSpecFields("etl", compute.ClusterSpec{
		SparkVersion:              "14.3.x-scala2.12",
		DataSecurityMode:          compute.DataSecurityModeSingleUser,
		SingleUserName:            "ada@example.com",
		RuntimeEngine:             compute.RuntimeEnginePhoton,
		NodeTypeId:                "i3.xlarge",
		NumWorkers:                4,
		EnableLocalDiskEncryption: true,
		PolicyId:                  "policy-1",
		AwsAttributes: &compute.AwsAttributes{
			InstanceProfileArn: "arn:aws:iam::123456789012:instance-profile/etl",
		},
	})

	if got.key != "etl" {
		t.Fatalf("key = %q, want %q", got.key, "etl")
	}
	if got.dataSecurityMode != string(compute.DataSecurityModeSingleUser) {
		t.Fatalf("dataSecurityMode = %q, want %q", got.dataSecurityMode, compute.DataSecurityModeSingleUser)
	}
	if got.numWorkers != 4 {
		t.Fatalf("numWorkers = %d, want 4", got.numWorkers)
	}
	if got.policyId != "policy-1" {
		t.Fatalf("policyId = %q, want %q", got.policyId, "policy-1")
	}
	if got.instanceProfileArn != "arn:aws:iam::123456789012:instance-profile/etl" {
		t.Fatalf("instanceProfileArn = %q, want the AWS attributes ARN", got.instanceProfileArn)
	}

	t.Run("no aws attributes leaves the profile empty", func(t *testing.T) {
		got := jobClusterSpecFields("", compute.ClusterSpec{SparkVersion: "14.3.x-scala2.12"})
		if got.instanceProfileArn != "" {
			t.Fatalf("instanceProfileArn = %q, want empty", got.instanceProfileArn)
		}
	})
}

func TestPipelineClusterSpecFields(t *testing.T) {
	got := pipelineClusterSpecFields(pipelines.PipelineCluster{
		Label:                     "default",
		NodeTypeId:                "i3.xlarge",
		NumWorkers:                2,
		EnableLocalDiskEncryption: true,
		PolicyId:                  "policy-2",
		AwsAttributes: &compute.AwsAttributes{
			InstanceProfileArn: "arn:aws:iam::123456789012:instance-profile/dlt",
		},
	})

	if got.key != "default" {
		t.Fatalf("key = %q, want %q", got.key, "default")
	}
	if got.numWorkers != 2 {
		t.Fatalf("numWorkers = %d, want 2", got.numWorkers)
	}
	if got.policyId != "policy-2" {
		t.Fatalf("policyId = %q, want %q", got.policyId, "policy-2")
	}
	// A pipeline cluster carries no Spark version, access mode, execution
	// engine, or container image. These must stay empty rather than be given a
	// default, because the API has no value for them.
	if got.sparkVersion != "" || got.dataSecurityMode != "" || got.runtimeEngine != "" || got.dockerImageUrl != "" {
		t.Fatalf("unmodelled fields must stay empty, got %+v", got)
	}
}

func TestSettingsOf(t *testing.T) {
	fallback := jobs.JobSettings{Name: "from-list"}

	t.Run("prefers the detail settings", func(t *testing.T) {
		detail := &jobs.Job{Settings: &jobs.JobSettings{Name: "from-detail"}}
		if got := settingsOf(detail, fallback); got.Name != "from-detail" {
			t.Fatalf("settingsOf() name = %q, want %q", got.Name, "from-detail")
		}
	})

	t.Run("falls back when the detail is nil", func(t *testing.T) {
		if got := settingsOf(nil, fallback); got.Name != "from-list" {
			t.Fatalf("settingsOf() name = %q, want %q", got.Name, "from-list")
		}
	})

	t.Run("falls back when the detail carries no settings", func(t *testing.T) {
		if got := settingsOf(&jobs.Job{}, fallback); got.Name != "from-list" {
			t.Fatalf("settingsOf() name = %q, want %q", got.Name, "from-list")
		}
	})
}

// The notification structs gain an event whenever the Jobs API adds one, and
// the builders list their events by name, so a new event compiles cleanly and
// its recipients silently drop out of the union. These walk every event field
// through reflection and fail at SDK upgrade time instead.

func TestNotificationEmailsOfCoversEverySdkEvent(t *testing.T) {
	typ := reflect.TypeOf(jobs.JobEmailNotifications{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type != reflect.TypeOf([]string{}) || !strings.HasPrefix(f.Name, "On") {
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			n := jobs.JobEmailNotifications{}
			reflect.ValueOf(&n).Elem().Field(i).Set(reflect.ValueOf([]string{"sentinel@example.com"}))
			if got := notificationEmailsOf(&n); !reflect.DeepEqual(got, []string{"sentinel@example.com"}) {
				t.Fatalf("notificationEmailsOf() = %v for jobs.JobEmailNotifications.%s.\n"+
					"The SDK models a notification event that notificationEmailsOf does not read. "+
					"Add it to the union and to the notificationEmails doc comment.", got, f.Name)
			}
		})
	}
}

func TestWebhookNotificationIdsOfCoversEverySdkEvent(t *testing.T) {
	typ := reflect.TypeOf(jobs.WebhookNotifications{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type != reflect.TypeOf([]jobs.Webhook{}) || !strings.HasPrefix(f.Name, "On") {
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			n := jobs.WebhookNotifications{}
			reflect.ValueOf(&n).Elem().Field(i).Set(reflect.ValueOf([]jobs.Webhook{{Id: "sentinel"}}))
			if got := webhookNotificationIdsOf(&n); !reflect.DeepEqual(got, []string{"sentinel"}) {
				t.Fatalf("webhookNotificationIdsOf() = %v for jobs.WebhookNotifications.%s.\n"+
					"The SDK models a notification event that webhookNotificationIdsOf does not read. "+
					"Add it to the union and to the webhookNotificationIds doc comment.", got, f.Name)
			}
		})
	}
}

func TestEnvironmentVariablesOf(t *testing.T) {
	listed := []jobs.JobEnvironmentVariables{{
		EnvironmentVariablesKey: "default",
		Spec:                    &jobs.JobEnvironmentVariablesSpec{Variables: map[string]string{"STAGE": "prod"}},
	}}

	t.Run("entries in the list response are used without a detail call", func(t *testing.T) {
		got, err := environmentVariablesOf(jobs.JobSettings{EnvironmentVariables: listed}, func() (*jobs.Job, error) {
			t.Fatal("detail fetched although the list response carried the entries")
			return nil, nil
		})
		if err != nil {
			t.Fatalf("environmentVariablesOf() error = %v", err)
		}
		if !reflect.DeepEqual(got, listed) {
			t.Fatalf("environmentVariablesOf() = %v, want %v", got, listed)
		}
	})

	t.Run("an empty list block is confirmed against the detail", func(t *testing.T) {
		calls := 0
		got, err := environmentVariablesOf(jobs.JobSettings{}, func() (*jobs.Job, error) {
			calls++
			return &jobs.Job{Settings: &jobs.JobSettings{EnvironmentVariables: listed}}, nil
		})
		if err != nil {
			t.Fatalf("environmentVariablesOf() error = %v", err)
		}
		if calls != 1 {
			t.Fatalf("detail fetched %d times, want 1", calls)
		}
		if !reflect.DeepEqual(got, listed) {
			t.Fatalf("environmentVariablesOf() = %v, want the detail's entries %v", got, listed)
		}
	})

	t.Run("a job with no entries anywhere reports none", func(t *testing.T) {
		got, err := environmentVariablesOf(jobs.JobSettings{}, func() (*jobs.Job, error) {
			return &jobs.Job{Settings: &jobs.JobSettings{}}, nil
		})
		if err != nil || len(got) != 0 {
			t.Fatalf("environmentVariablesOf() = %v, %v; want empty, nil", got, err)
		}
	})

	t.Run("a failed detail call is an error, not an empty answer", func(t *testing.T) {
		_, err := environmentVariablesOf(jobs.JobSettings{}, func() (*jobs.Job, error) {
			return nil, errors.New("PERMISSION_DENIED")
		})
		if err == nil {
			t.Fatal("environmentVariablesOf() error = nil, want the detail error")
		}
	})
}

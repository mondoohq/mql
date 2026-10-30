// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sCronjobInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sCronjob) getCronJob() (*batchv1.CronJob, error) {
	cj, ok := k.obj.(*batchv1.CronJob)
	if ok {
		return cj, nil
	}
	return nil, errors.New("invalid k8s cronjob")
}

func (k *mqlK8s) cronjobs() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(batchv1.SchemeGroupVersion.WithKind("cronjobs")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.cronjob", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sCronjob).obj = resource
		return r, nil
	})
}

func (k *mqlK8sCronjob) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sCronjob) podSpec() (map[string]any, error) {
	podSpec, err := resources.GetPodSpec(k.obj)
	if err != nil {
		return nil, err
	}
	dict, err := convert.JsonToDict(podSpec)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (k *mqlK8sCronjob) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sCronjob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sCronjob](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetCronjobs() })
}

func (k *mqlK8sCronjob) annotations() (map[string]any, error) {
	// Get the CronJob object
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(cj.GetAnnotations()), nil
}

func (k *mqlK8sCronjob) labels() (map[string]any, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(cj.GetLabels()), nil
}

func (k *mqlK8sCronjob) initContainers() ([]any, error) {
	// Get the CronJob object
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return getContainers(cj, &cj.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sCronjob) containers() ([]any, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return getContainers(cj, &cj.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sCronjob) schedule() (string, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return "", err
	}
	return cj.Spec.Schedule, nil
}

func (k *mqlK8sCronjob) timeZone() (string, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return "", err
	}
	if cj.Spec.TimeZone == nil {
		return "", nil
	}
	return *cj.Spec.TimeZone, nil
}

func (k *mqlK8sCronjob) concurrencyPolicy() (string, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return "", err
	}
	return string(cj.Spec.ConcurrencyPolicy), nil
}

func (k *mqlK8sCronjob) startingDeadlineSeconds() (int64, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return 0, err
	}
	if cj.Spec.StartingDeadlineSeconds == nil {
		k.StartingDeadlineSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *cj.Spec.StartingDeadlineSeconds, nil
}

func (k *mqlK8sCronjob) successfulJobsHistoryLimit() (int64, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return 0, err
	}
	if cj.Spec.SuccessfulJobsHistoryLimit == nil {
		return 3, nil
	}
	return int64(*cj.Spec.SuccessfulJobsHistoryLimit), nil
}

func (k *mqlK8sCronjob) failedJobsHistoryLimit() (int64, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return 0, err
	}
	if cj.Spec.FailedJobsHistoryLimit == nil {
		return 1, nil
	}
	return int64(*cj.Spec.FailedJobsHistoryLimit), nil
}

func (k *mqlK8sCronjob) suspend() (bool, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return false, err
	}
	if cj.Spec.Suspend == nil {
		return false, nil
	}
	return *cj.Spec.Suspend, nil
}

func (k *mqlK8sCronjob) active() ([]any, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(cj.Status.Active)
}

func (k *mqlK8sCronjob) lastScheduleTime() (*time.Time, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	if cj.Status.LastScheduleTime == nil {
		k.LastScheduleTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := cj.Status.LastScheduleTime.Time
	return &t, nil
}

func (k *mqlK8sCronjob) lastSuccessfulTime() (*time.Time, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	if cj.Status.LastSuccessfulTime == nil {
		k.LastSuccessfulTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := cj.Status.LastSuccessfulTime.Time
	return &t, nil
}

func (k *mqlK8sCronjob) activeJobs() ([]any, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	allJobs := o.(*mqlK8s).GetJobs()
	if allJobs.Error != nil {
		return nil, allJobs.Error
	}

	wantUIDs := make(map[string]struct{}, len(cj.Status.Active))
	wantNames := make(map[string]struct{}, len(cj.Status.Active))
	for _, ref := range cj.Status.Active {
		if ref.UID != "" {
			wantUIDs[string(ref.UID)] = struct{}{}
		}
		wantNames[ref.Namespace+"/"+ref.Name] = struct{}{}
	}

	out := []any{}
	for i := range allJobs.Data {
		j, ok := allJobs.Data[i].(*mqlK8sJob)
		if !ok {
			continue
		}
		if _, ok := wantUIDs[j.Uid.Data]; ok {
			out = append(out, j)
			continue
		}
		if _, ok := wantNames[j.Namespace.Data+"/"+j.Name.Data]; ok {
			out = append(out, j)
		}
	}
	return out, nil
}

func (k *mqlK8sCronjob) jobs() ([]any, error) {
	cj, err := k.getCronJob()
	if err != nil {
		return nil, err
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	allJobs := o.(*mqlK8s).GetJobs()
	if allJobs.Error != nil {
		return nil, allJobs.Error
	}

	cjUID := string(cj.UID)
	out := []any{}
	for i := range allJobs.Data {
		j, ok := allJobs.Data[i].(*mqlK8sJob)
		if !ok {
			continue
		}
		typedJob, err := j.getJob()
		if err != nil {
			continue
		}
		for _, ownerRef := range typedJob.OwnerReferences {
			if ownerRef.Kind == "CronJob" && string(ownerRef.UID) == cjUID {
				out = append(out, j)
				break
			}
		}
	}
	return out, nil
}

func (k *mqlK8sCronjob) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sCronjob) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

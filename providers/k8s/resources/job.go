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

type mqlK8sJobInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sJob) getJob() (*batchv1.Job, error) {
	j, ok := k.obj.(*batchv1.Job)
	if ok {
		return j, nil
	}
	return nil, errors.New("invalid k8s job")
}

func (k *mqlK8s) jobs() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(batchv1.SchemeGroupVersion.WithKind("jobs")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.job", map[string]*llx.RawData{
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

		r.(*mqlK8sJob).obj = resource
		return r, nil
	})
}

func (k *mqlK8sJob) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sJob) podSpec() (map[string]any, error) {
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

func (k *mqlK8sJob) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sJob](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetJobs() })
}

func (k *mqlK8sJob) annotations() (map[string]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(j.GetAnnotations()), nil
}

func (k *mqlK8sJob) labels() (map[string]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(j.GetLabels()), nil
}

func (k *mqlK8sJob) initContainers() ([]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return getContainers(j, &j.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sJob) containers() ([]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return getContainers(j, &j.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sJob) pods() ([]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return podsMatchingSelector(k.MqlRuntime, j.Spec.Selector, j.Namespace)
}

func (k *mqlK8sJob) parallelism() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.Parallelism == nil {
		return 1, nil
	}
	return int64(*j.Spec.Parallelism), nil
}

func (k *mqlK8sJob) completions() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.Completions == nil {
		// nil means "one per parallelism value"; mirror that so audits don't
		// see a misleading 0.
		if j.Spec.Parallelism != nil {
			return int64(*j.Spec.Parallelism), nil
		}
		return 1, nil
	}
	return int64(*j.Spec.Completions), nil
}

func (k *mqlK8sJob) backoffLimit() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.BackoffLimit == nil {
		return 6, nil
	}
	return int64(*j.Spec.BackoffLimit), nil
}

func (k *mqlK8sJob) backoffLimitPerIndex() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.BackoffLimitPerIndex == nil {
		k.BackoffLimitPerIndex.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*j.Spec.BackoffLimitPerIndex), nil
}

func (k *mqlK8sJob) maxFailedIndexes() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.MaxFailedIndexes == nil {
		k.MaxFailedIndexes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*j.Spec.MaxFailedIndexes), nil
}

func (k *mqlK8sJob) completionMode() (string, error) {
	j, err := k.getJob()
	if err != nil {
		return "", err
	}
	if j.Spec.CompletionMode == nil {
		return "NonIndexed", nil
	}
	return string(*j.Spec.CompletionMode), nil
}

func (k *mqlK8sJob) activeDeadlineSeconds() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.ActiveDeadlineSeconds == nil {
		k.ActiveDeadlineSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *j.Spec.ActiveDeadlineSeconds, nil
}

func (k *mqlK8sJob) ttlSecondsAfterFinished() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Spec.TTLSecondsAfterFinished == nil {
		k.TtlSecondsAfterFinished.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*j.Spec.TTLSecondsAfterFinished), nil
}

func (k *mqlK8sJob) suspend() (bool, error) {
	j, err := k.getJob()
	if err != nil {
		return false, err
	}
	if j.Spec.Suspend == nil {
		return false, nil
	}
	return *j.Spec.Suspend, nil
}

func (k *mqlK8sJob) podReplacementPolicy() (string, error) {
	j, err := k.getJob()
	if err != nil {
		return "", err
	}
	if j.Spec.PodReplacementPolicy == nil {
		k.PodReplacementPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*j.Spec.PodReplacementPolicy), nil
}

func (k *mqlK8sJob) selector() (map[string]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(j.Spec.Selector)
}

func (k *mqlK8sJob) active() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	return int64(j.Status.Active), nil
}

func (k *mqlK8sJob) succeeded() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	return int64(j.Status.Succeeded), nil
}

func (k *mqlK8sJob) failed() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	return int64(j.Status.Failed), nil
}

func (k *mqlK8sJob) ready() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Status.Ready == nil {
		k.Ready.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*j.Status.Ready), nil
}

func (k *mqlK8sJob) terminating() (int64, error) {
	j, err := k.getJob()
	if err != nil {
		return 0, err
	}
	if j.Status.Terminating == nil {
		k.Terminating.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*j.Status.Terminating), nil
}

func (k *mqlK8sJob) completedIndexes() (string, error) {
	j, err := k.getJob()
	if err != nil {
		return "", err
	}
	return j.Status.CompletedIndexes, nil
}

func (k *mqlK8sJob) failedIndexes() (string, error) {
	j, err := k.getJob()
	if err != nil {
		return "", err
	}
	if j.Status.FailedIndexes == nil {
		k.FailedIndexes.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *j.Status.FailedIndexes, nil
}

func (k *mqlK8sJob) startTime() (*time.Time, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	if j.Status.StartTime == nil {
		k.StartTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := j.Status.StartTime.Time
	return &t, nil
}

func (k *mqlK8sJob) completionTime() (*time.Time, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	if j.Status.CompletionTime == nil {
		k.CompletionTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := j.Status.CompletionTime.Time
	return &t, nil
}

func (k *mqlK8sJob) conditions() ([]any, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(j.Status.Conditions)
}

func (k *mqlK8sJob) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sJob) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

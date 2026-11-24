// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlTogetherDeploymentInternal keeps the secret references of the
// deployment's environment variables, by name or ID as the API reports them.
// The secrets accessor resolves them against the secret list.
type mqlTogetherDeploymentInternal struct {
	cacheSecretRefs []string
}

// mqlTogetherDeploymentVolumeMountInternal keeps the volume reference of the
// mount, by name or ID as the API reports it.
type mqlTogetherDeploymentVolumeMountInternal struct {
	cacheVolumeRef string
}

// newDeployment builds a together.deployment from a deployment list entry,
// including its mount sub-resources. Environment variable values never reach
// the schema: only the names, and the secrets the variables read from.
func newDeployment(runtime *plugin.Runtime, d together.Deployment) (*mqlTogetherDeployment, error) {
	envVarNames := make([]any, 0, len(d.EnvironmentVariables))
	for _, ev := range d.EnvironmentVariables {
		envVarNames = append(envVarNames, ev.Name)
	}

	volumeMounts, err := deploymentVolumeMounts(runtime, d)
	if err != nil {
		return nil, err
	}
	modelMounts, err := deploymentModelMounts(runtime, d)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "together.deployment", map[string]*llx.RawData{
		"__id":                              llx.StringData(d.ID),
		"id":                                llx.StringData(d.ID),
		"name":                              llx.StringData(d.Name),
		"description":                       llx.StringData(d.Description),
		"image":                             llx.StringData(d.Image),
		"status":                            llx.StringData(string(d.Status)),
		"gpuType":                           llx.StringData(string(d.GPUType)),
		"gpuCount":                          llx.IntData(d.GPUCount),
		"cpu":                               llx.FloatData(d.CPU),
		"memory":                            llx.FloatData(d.Memory),
		"storage":                           llx.IntData(d.Storage),
		"port":                              llx.IntData(d.Port),
		"healthCheckPath":                   llx.StringData(d.HealthCheckPath),
		"desiredReplicas":                   llx.IntData(d.DesiredReplicas),
		"readyReplicas":                     llx.IntData(d.ReadyReplicas),
		"minReplicas":                       llx.IntData(d.MinReplicas),
		"maxReplicas":                       llx.IntData(d.MaxReplicas),
		"environmentVariableNames":          llx.ArrayData(envVarNames, types.String),
		"plaintextEnvironmentVariableNames": llx.ArrayData(plaintextEnvironmentVariableNames(d.EnvironmentVariables), types.String),
		"volumeMounts":                      llx.ArrayData(volumeMounts, types.Resource("together.deployment.volumeMount")),
		"modelMounts":                       llx.ArrayData(modelMounts, types.Resource("together.deployment.modelMount")),
		"capacityType":                      llx.StringDataPtr(reportedString(string(d.CapacityType), d.JSON.CapacityType)),
		"createdAt":                         llx.TimeDataPtr(timeOrNil(d.CreatedAt)),
		"updatedAt":                         llx.TimeDataPtr(timeOrNil(d.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	deployment := res.(*mqlTogetherDeployment)
	deployment.cacheSecretRefs = secretReferences(d.EnvironmentVariables)
	return deployment, nil
}

// plaintextEnvironmentVariableNames returns the names of the variables that
// do not read their value from a managed secret. The API requires exactly one
// of a plaintext value and a secret reference, so a variable without a secret
// reference carries its value in plaintext, whether or not the response
// echoes that value back.
func plaintextEnvironmentVariableNames(envs []together.DeploymentEnvironmentVariable) []any {
	names := make([]any, 0, len(envs))
	for _, ev := range envs {
		if ev.ValueFromSecret == "" {
			names = append(names, ev.Name)
		}
	}
	return names
}

// secretReferences returns the secret references of the variables, in order
// and without duplicates, since several variables may read the same secret.
func secretReferences(envs []together.DeploymentEnvironmentVariable) []string {
	refs := []string{}
	seen := map[string]bool{}
	for _, ev := range envs {
		if ev.ValueFromSecret == "" || seen[ev.ValueFromSecret] {
			continue
		}
		seen[ev.ValueFromSecret] = true
		refs = append(refs, ev.ValueFromSecret)
	}
	return refs
}

// mountID keys a mount inside its deployment. The mount path is unique within
// a container; the index keeps mounts without a path apart.
func mountID(deploymentID, kind, path string, index int) string {
	key := path
	if key == "" {
		key = "index-" + strconv.Itoa(index)
	}
	return deploymentID + "/" + kind + "/" + key
}

func deploymentVolumeMounts(runtime *plugin.Runtime, d together.Deployment) ([]any, error) {
	res := make([]any, 0, len(d.Volumes))
	for i, v := range d.Volumes {
		var version *int64
		if v.JSON.Version.Valid() {
			n := v.Version
			version = &n
		}
		obj, err := CreateResource(runtime, "together.deployment.volumeMount", map[string]*llx.RawData{
			"__id":    llx.StringData(mountID(d.ID, "volume", v.MountPath, i)),
			"path":    llx.StringData(v.MountPath),
			"version": llx.IntDataPtr(version),
		})
		if err != nil {
			return nil, err
		}
		obj.(*mqlTogetherDeploymentVolumeMount).cacheVolumeRef = v.Name
		res = append(res, obj)
	}
	return res, nil
}

func deploymentModelMounts(runtime *plugin.Runtime, d together.Deployment) ([]any, error) {
	res := make([]any, 0, len(d.ModelMounts))
	for i, m := range d.ModelMounts {
		obj, err := CreateResource(runtime, "together.deployment.modelMount", map[string]*llx.RawData{
			"__id":       llx.StringData(mountID(d.ID, "model", m.MountPath, i)),
			"path":       llx.StringData(m.MountPath),
			"modelId":    llx.StringData(m.ModelID),
			"revisionId": llx.StringDataPtr(nonEmpty(m.RevisionID)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// nonEmpty maps an omitted string onto nil, for values where the API leaves a
// field out to mean "not set".
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (r *mqlTogetherDeployment) secrets() ([]any, error) {
	if len(r.cacheSecretRefs) == 0 {
		return []any{}, nil
	}
	root, err := togetherRoot(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	secrets := root.GetSecrets()
	if secrets.Error != nil {
		return nil, secrets.Error
	}
	return selectSecrets(secrets.Data, r.cacheSecretRefs), nil
}

// selectSecrets picks the secrets the references name, each at most once. A
// reference may carry a secret's name or its ID.
func selectSecrets(secrets []any, refs []string) []any {
	res := []any{}
	for _, raw := range secrets {
		s, ok := raw.(*mqlTogetherSecret)
		if !ok {
			continue
		}
		for _, ref := range refs {
			if ref == s.Id.Data || ref == s.Name.Data {
				res = append(res, s)
				break
			}
		}
	}
	return res
}

func (r *mqlTogetherDeploymentVolumeMount) volume() (*mqlTogetherVolume, error) {
	if r.cacheVolumeRef != "" {
		root, err := togetherRoot(r.MqlRuntime)
		if err != nil {
			return nil, err
		}
		volumes := root.GetVolumes()
		if volumes.Error != nil {
			return nil, volumes.Error
		}
		if v := selectVolume(volumes.Data, r.cacheVolumeRef); v != nil {
			return v, nil
		}
	}
	r.Volume.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// selectVolume finds the volume a mount names. The mount carries the volume's
// ID or its name; the ID is matched first, since a name is only unique while
// nobody reuses it.
func selectVolume(volumes []any, ref string) *mqlTogetherVolume {
	var byName *mqlTogetherVolume
	for _, raw := range volumes {
		v, ok := raw.(*mqlTogetherVolume)
		if !ok {
			continue
		}
		if v.Id.Data == ref {
			return v
		}
		if byName == nil && v.Name.Data == ref {
			byName = v
		}
	}
	return byName
}

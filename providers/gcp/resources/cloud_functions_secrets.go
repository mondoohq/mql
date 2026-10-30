// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// cloudFunctionSecretBinding is the shape shared by the v1 and v2 secret
// bindings. The apiv1 and apiv2 messages are field-identical, so one pair of
// resources serves both generations of the API.
type cloudFunctionSecretBinding struct {
	key          string
	projectID    string
	secret       string
	version      string
	mountPath    string
	versionPaths map[string]string
}

type mqlGcpProjectCloudFunctionSecretEnvVarInternal struct {
	cacheProjectID  string
	cacheSecretName string
}

type mqlGcpProjectCloudFunctionSecretVolumeInternal struct {
	cacheProjectID  string
	cacheSecretName string
}

// resolveFunctionSecret resolves the Secret Manager secret a binding names.
//
// A function may reference a secret in another project, so the binding's own
// projectId is used rather than the function's. A binding that names no secret,
// or one the caller cannot read, resolves to null rather than failing the
// function: a single unreadable secret should not take the whole function's
// configuration with it.
func resolveFunctionSecret(runtime *plugin.Runtime, projectID string, secretName string) (*mqlGcpProjectSecretmanagerServiceSecret, error) {
	if projectID == "" || secretName == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.secretmanagerService.secret", map[string]*llx.RawData{
		"name":      llx.StringData(secretName),
		"projectId": llx.StringData(projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSecretmanagerServiceSecret), nil
}

func (g *mqlGcpProjectCloudFunctionSecretEnvVar) secret() (*mqlGcpProjectSecretmanagerServiceSecret, error) {
	s, err := resolveFunctionSecret(g.MqlRuntime, g.cacheProjectID, g.cacheSecretName)
	if err != nil || s == nil {
		g.Secret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, err
	}
	return s, nil
}

func (g *mqlGcpProjectCloudFunctionSecretVolume) secret() (*mqlGcpProjectSecretmanagerServiceSecret, error) {
	s, err := resolveFunctionSecret(g.MqlRuntime, g.cacheProjectID, g.cacheSecretName)
	if err != nil || s == nil {
		g.Secret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, err
	}
	return s, nil
}

// newMqlFunctionSecretEnvVars builds the environment-variable bindings of a
// function. The cache key carries the environment variable name, which is what
// makes each binding unique within one function.
func newMqlFunctionSecretEnvVars(runtime *plugin.Runtime, parentID string, bindings []cloudFunctionSecretBinding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for _, b := range bindings {
		mqlBinding, err := CreateResource(runtime, "gcp.project.cloudFunction.secretEnvVar", map[string]*llx.RawData{
			"__id":    llx.StringData(parentID + "/secretEnvVar/" + b.key),
			"key":     llx.StringData(b.key),
			"version": llx.StringData(b.version),
		})
		if err != nil {
			return nil, err
		}
		envVar := mqlBinding.(*mqlGcpProjectCloudFunctionSecretEnvVar)
		envVar.cacheProjectID = b.projectID
		envVar.cacheSecretName = b.secret
		res = append(res, mqlBinding)
	}
	return res, nil
}

// newMqlFunctionSecretVolumes builds the mounted-secret bindings of a function.
// The cache key carries the mount path, which is unique within one function.
func newMqlFunctionSecretVolumes(runtime *plugin.Runtime, parentID string, bindings []cloudFunctionSecretBinding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for _, b := range bindings {
		versionPaths := make(map[string]any, len(b.versionPaths))
		for k, v := range b.versionPaths {
			versionPaths[k] = v
		}
		mqlBinding, err := CreateResource(runtime, "gcp.project.cloudFunction.secretVolume", map[string]*llx.RawData{
			"__id":         llx.StringData(parentID + "/secretVolume/" + b.mountPath),
			"mountPath":    llx.StringData(b.mountPath),
			"versionPaths": llx.MapData(versionPaths, types.String),
		})
		if err != nil {
			return nil, err
		}
		volume := mqlBinding.(*mqlGcpProjectCloudFunctionSecretVolume)
		volume.cacheProjectID = b.projectID
		volume.cacheSecretName = b.secret
		res = append(res, mqlBinding)
	}
	return res, nil
}

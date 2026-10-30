// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	kustomizeTypes "sigs.k8s.io/kustomize/api/types"
)

func newMqlConfigMapGenerators(runtime *plugin.Runtime, kustPath string, generators []kustomizeTypes.ConfigMapArgs) ([]any, error) {
	var mqlGens []any
	for i, g := range generators {
		mqlG, err := newMqlKustomizeGenerator(runtime, kustPath, "configmap", i, &g.GeneratorArgs)
		if err != nil {
			return nil, err
		}
		mqlGens = append(mqlGens, mqlG)
	}
	return mqlGens, nil
}

func newMqlSecretGenerators(runtime *plugin.Runtime, kustPath string, generators []kustomizeTypes.SecretArgs) ([]any, error) {
	var mqlGens []any
	for i, g := range generators {
		mqlG, err := newMqlKustomizeGenerator(runtime, kustPath, "secret", i, &g.GeneratorArgs)
		if err != nil {
			return nil, err
		}
		mqlGens = append(mqlGens, mqlG)
	}
	return mqlGens, nil
}

func newMqlKustomizeGenerator(runtime *plugin.Runtime, kustPath string, genType string, index int, g *kustomizeTypes.GeneratorArgs) (*mqlKustomizeGenerator, error) {
	id := "kustomize.generator:" + kustPath + ":" + genType + ":" + strconv.Itoa(index) + ":" + g.Name

	literals := convert.SliceAnyToInterface(g.LiteralSources)
	files := convert.SliceAnyToInterface(g.FileSources)
	envs := convert.SliceAnyToInterface(g.EnvSources)

	res, err := CreateResource(runtime, "kustomize.generator", map[string]*llx.RawData{
		"__id":      llx.StringData(id),
		"name":      llx.StringData(g.Name),
		"type":      llx.StringData(genType),
		"literals":  llx.ArrayData(literals, types.String),
		"files":     llx.ArrayData(files, types.String),
		"envs":      llx.ArrayData(envs, types.String),
		"behavior":  llx.StringData(g.Behavior),
		"namespace": llx.StringData(g.Namespace),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlKustomizeGenerator), nil
}

var _ plugin.Resource = (*mqlKustomizeGenerator)(nil)

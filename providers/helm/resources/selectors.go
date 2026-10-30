// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/helm/connection"
)

// requiredStringArg reads the selector argument a resource can only be reached
// by, erroring when it is absent or empty.
//
// There is no useful bare form of these resources: unlike a resource that can
// take its identity from the asset, `helm.file` and `helm.template` have
// nothing to resolve from without their selector. Accepting the empty case
// would build exactly the husk these inits exist to prevent — an empty `__id`
// that every other bare lookup then aliases onto. The full sets stay reachable
// through `helm.chart.files` and `helm.chart.templates`.
func requiredStringArg(args map[string]*llx.RawData, resource, key, example string) (string, error) {
	var v string
	if raw, ok := args[key]; ok && raw != nil {
		v, _ = raw.Value.(string)
	}
	if v == "" {
		return "", fmt.Errorf("%s requires a %q argument, for example %s", resource, key, example)
	}
	return v, nil
}

// initHelmFile resolves the selector the schema documents,
// `helm.file(path: "NOTES.txt")`, against the loaded charts.
//
// Without it the runtime built the resource from the `path` arg alone:
// `content` came back "" because the Internal cache was never populated (a
// fabricated empty answer), `size`/`isBinary` were left UNSET rather than null,
// and with no `__id` every bare lookup in a session shared the cache key
// `helm.file\x00` — so the second returned the first one's path.
//
// A miss returns an error rather than falling through to `args, nil, nil`,
// which would rebuild the same husk.
func initHelmFile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	path, err := requiredStringArg(args, "helm.file", "path", `helm.file(path: "README.md")`)
	if err != nil {
		return nil, nil, err
	}
	conn, ok := runtime.Connection.(*connection.HelmConnection)
	if !ok {
		// Falling through here would create the resource from the partial args
		// — the same husk, just reached a different way.
		return nil, nil, errors.New("helm.file: unexpected connection type")
	}

	for _, loaded := range conn.Charts() {
		if loaded.Chart == nil {
			continue
		}
		for _, f := range loaded.Chart.Files {
			if f == nil || f.Name != path {
				continue
			}
			mqlFile, err := newMqlHelmFile(runtime, loaded.Chart.Name(), f)
			if err != nil {
				return nil, nil, err
			}
			return args, mqlFile, nil
		}
	}
	return nil, nil, fmt.Errorf("helm: no chart file at path %q", path)
}

// initHelmTemplate resolves `helm.template(name: "templates/deployment.yaml")`
// against the loaded charts, for the same reasons as initHelmFile.
//
// The template is returned unrendered (no `renderedContent`), because rendering
// is a chart-wide operation reached through `helm.chart.templates`. That is a
// visible null rather than a fabricated empty string.
func initHelmTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, err := requiredStringArg(args, "helm.template", "name", `helm.template(name: "templates/deployment.yaml")`)
	if err != nil {
		return nil, nil, err
	}
	conn, ok := runtime.Connection.(*connection.HelmConnection)
	if !ok {
		return nil, nil, errors.New("helm.template: unexpected connection type")
	}

	for _, loaded := range conn.Charts() {
		if loaded.Chart == nil {
			continue
		}
		for _, t := range loaded.Chart.Templates {
			if t == nil || t.Name != name {
				continue
			}
			mqlTemplate, err := newMqlHelmTemplate(runtime, loaded.Chart.Name(), t, "", nil)
			if err != nil {
				return nil, nil, err
			}
			return args, mqlTemplate, nil
		}
	}
	return nil, nil, fmt.Errorf("helm: no chart template named %q", name)
}

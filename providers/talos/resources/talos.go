// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/siderolabs/talos/pkg/machinery/config/configloader"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/talos/connection"
	"go.yaml.in/yaml/v4"
)

const (
	kernelParamStatusType      = "KernelParamStatuses.runtime.talos.dev"
	kernelParamStatusNamespace = "runtime"
	// machineConfigPath is where Talos keeps the machine configuration it
	// applied, as `talosctl read` reads it.
	machineConfigPath = "/system/state/config.yaml"
)

func talosConnection(runtime *plugin.Runtime) *connection.TalosConnection {
	return runtime.Connection.(*connection.TalosConnection)
}

func (r *mqlTalos) id() (string, error) {
	return "talos", nil
}

func (r *mqlTalos) version() (*mqlTalosVersion, error) {
	v, err := talosConnection(r.MqlRuntime).Version()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "talos.version", map[string]*llx.RawData{
		"__id":      llx.StringData("talos.version"),
		"tag":       llx.StringData(v.Tag),
		"sha":       llx.StringData(v.Sha),
		"goVersion": llx.StringData(v.GoVersion),
		"os":        llx.StringData(v.OS),
		"arch":      llx.StringData(v.Arch),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlTalosVersion), nil
}

func (r *mqlTalos) kernelParameters() ([]any, error) {
	conn := talosConnection(r.MqlRuntime)
	items, err := conn.List(kernelParamStatusNamespace, kernelParamStatusType)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(items))
	for _, item := range items {
		spec, err := connection.Spec(item)
		if err != nil {
			return nil, err
		}
		res, err := newKernelParameter(r.MqlRuntime, sysctlKey(item.Metadata().ID()), spec)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func newKernelParameter(runtime *plugin.Runtime, key string, spec map[string]any) (plugin.Resource, error) {
	current, _ := spec["current"].(string)
	def, _ := spec["default"].(string)
	return CreateResource(runtime, "talos.kernelParameter", map[string]*llx.RawData{
		"__id":    llx.StringData("talos.kernelParameter/" + key),
		"key":     llx.StringData(key),
		"current": llx.StringData(current),
		"default": llx.StringData(def),
		"source":  llx.StringData("status"),
	})
}

// sysctlKey turns a KernelParamStatus ID (proc.sys.net.ipv4.tcp_syncookies)
// into the sysctl name (net.ipv4.tcp_syncookies).
func sysctlKey(id string) string {
	return strings.TrimPrefix(id, "proc.sys.")
}

// normalizeKey accepts a sysctl name with dots or slashes, with or without
// /proc/sys, and returns it with dots.
func normalizeKey(key string) string {
	key = strings.TrimPrefix(key, "/")
	key = strings.TrimPrefix(key, "proc/sys/")
	return sysctlKey(strings.ReplaceAll(key, "/", "."))
}

func initTalosKernelParameter(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["key"]
	if !ok {
		return nil, nil, errors.New("talos.kernelParameter needs a key, such as net.ipv4.tcp_syncookies")
	}
	s, _ := raw.Value.(string)
	key := normalizeKey(s)
	if key == "" {
		return nil, nil, errors.New("talos.kernelParameter needs a key, such as net.ipv4.tcp_syncookies")
	}

	conn := talosConnection(runtime)
	r, err := conn.Get(kernelParamStatusNamespace, kernelParamStatusType, "proc.sys."+key)
	if err == nil {
		spec, err := connection.Spec(r)
		if err != nil {
			return nil, nil, err
		}
		current, _ := spec["current"].(string)
		def, _ := spec["default"].(string)
		args["__id"] = llx.StringData("talos.kernelParameter/" + key)
		args["key"] = llx.StringData(key)
		args["current"] = llx.StringData(current)
		args["default"] = llx.StringData(def)
		args["source"] = llx.StringData("status")
		return args, nil, nil
	}
	if !connection.IsNotFound(err) {
		return nil, nil, err
	}

	// Talos doesn't manage the parameter, so its value is the kernel's.
	data, err := conn.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		if errors.Is(err, connection.ErrNeedsAdmin) {
			return nil, nil, fmt.Errorf("talos: Talos doesn't manage %s, and reading it from /proc/sys needs the os:admin role", key)
		}
		return nil, nil, err
	}
	args["__id"] = llx.StringData("talos.kernelParameter/" + key)
	args["key"] = llx.StringData(key)
	args["current"] = llx.StringData(strings.TrimSpace(string(data)))
	args["default"] = llx.NilData
	args["source"] = llx.StringData("proc")
	return args, nil, nil
}

func (r *mqlTalos) machineConfig() ([]any, error) {
	data, err := talosConnection(r.MqlRuntime).ReadFile(machineConfigPath)
	if err != nil {
		return nil, err
	}
	return machineConfigDocs(data)
}

// machineConfigDocs parses a machine configuration and returns its documents
// with the secrets removed.
func machineConfigDocs(data []byte) ([]any, error) {
	cfg, err := configloader.NewFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("talos: parse the machine configuration: %w", err)
	}
	// Talos's own redaction: every key, certificate and token is emptied.
	redacted, err := cfg.RedactSecrets("").EncodeBytes(encoder.WithComments(encoder.CommentsDisabled))
	if err != nil {
		return nil, err
	}

	docs := []any{}
	dec := yaml.NewDecoder(bytes.NewReader(redacted))
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if doc == nil {
			continue
		}
		d, err := toDict(doc)
		if err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, nil
}

// toDict converts decoded YAML into the types a dict holds: maps with string
// keys, lists, strings, float64 numbers and bools.
func toDict(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func initTalosResources(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["type"]
	if !ok {
		return nil, nil, errors.New("talos.resources needs a type, such as SecurityStates.talos.dev")
	}
	typ, _ := raw.Value.(string)
	if typ == "" {
		return nil, nil, errors.New("talos.resources needs a type, such as SecurityStates.talos.dev")
	}
	resolved, ns, err := talosConnection(runtime).ResolveType(typ)
	if err != nil {
		return nil, nil, err
	}
	args["__id"] = llx.StringData("talos.resources/" + ns + "/" + resolved)
	args["type"] = llx.StringData(typ)
	args["resolvedType"] = llx.StringData(resolved)
	args["namespace"] = llx.StringData(ns)
	return args, nil, nil
}

func (r *mqlTalosResources) list() ([]any, error) {
	items, err := talosConnection(r.MqlRuntime).List(r.Namespace.Data, r.ResolvedType.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(items))
	for _, item := range items {
		res, err := newResource(r.MqlRuntime, item)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func newResource(runtime *plugin.Runtime, item resource.Resource) (plugin.Resource, error) {
	m, err := connection.Marshal(item)
	if err != nil {
		return nil, err
	}
	metadata, err := toDict(m["metadata"])
	if err != nil {
		return nil, err
	}
	spec, err := toDict(m["spec"])
	if err != nil {
		return nil, err
	}
	md := item.Metadata()
	return CreateResource(runtime, "talos.resource", map[string]*llx.RawData{
		"__id":      llx.StringData("talos.resource/" + md.Namespace() + "/" + md.Type() + "/" + md.ID()),
		"type":      llx.StringData(md.Type()),
		"namespace": llx.StringData(md.Namespace()),
		"id":        llx.StringData(md.ID()),
		"version":   llx.StringData(md.Version().String()),
		"metadata":  llx.DictData(metadata),
		"spec":      llx.DictData(spec),
	})
}

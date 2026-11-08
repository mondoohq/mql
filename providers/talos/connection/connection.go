// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.yaml.in/yaml/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// OptionTalosconfig is the path of the talosconfig file. Without it, the
	// client reads TALOSCONFIG, then ~/.talos/config.
	OptionTalosconfig = "talosconfig"
	// OptionContext is the talosconfig context to use instead of its current one.
	OptionContext = "context"
	// OptionEndpoints is a comma-separated list of endpoints that replaces the
	// context's endpoints.
	OptionEndpoints = "endpoints"
	// OptionNode is the node the requests go to, through the endpoints. Without
	// it, the context's first node, else the first endpoint.
	OptionNode = "node"
)

// ErrNeedsAdmin is returned when the Talos API refuses a call that only the
// os:admin role may make, such as a file read or a sensitive resource.
var ErrNeedsAdmin = errors.New("the Talos API serves this only to the os:admin role")

type TalosConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *client.Client
	node   string
}

func NewTalosConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*TalosConnection, error) {
	conn := &TalosConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}
	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	opts := []client.OptionFunc{}
	if path := conf.Options[OptionTalosconfig]; path != "" {
		opts = append(opts, client.WithConfigFromFile(path))
	} else {
		opts = append(opts, client.WithDefaultConfig())
	}
	if name := conf.Options[OptionContext]; name != "" {
		opts = append(opts, client.WithContextName(name))
	}
	var endpoints []string
	if list := conf.Options[OptionEndpoints]; list != "" {
		for _, e := range strings.Split(list, ",") {
			if e = strings.TrimSpace(e); e != "" {
				endpoints = append(endpoints, e)
			}
		}
		opts = append(opts, client.WithEndpoints(endpoints...))
	}

	c, err := client.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("talos: %w", err)
	}
	conn.client = c

	conn.node = conf.Options[OptionNode]
	if conn.node == "" {
		conn.node = conf.Host
	}
	cfgCtx := c.GetConfigContext()
	if conn.node == "" && cfgCtx != nil && len(cfgCtx.Nodes) > 0 {
		conn.node = cfgCtx.Nodes[0]
	}
	if conn.node == "" && len(endpoints) > 0 {
		conn.node = endpoints[0]
	}
	if conn.node == "" && cfgCtx != nil && len(cfgCtx.Endpoints) > 0 {
		conn.node = cfgCtx.Endpoints[0]
	}
	if conn.node == "" {
		c.Close() //nolint:errcheck
		return nil, errors.New("talos: no node to connect to: pass one, or set nodes or endpoints in the talosconfig context")
	}

	return conn, nil
}

func (c *TalosConnection) Name() string {
	return "talos"
}

func (c *TalosConnection) Asset() *inventory.Asset {
	return c.asset
}

// Node is the node every request goes to.
func (c *TalosConnection) Node() string {
	return c.node
}

// ctx targets the connection's node, so a request goes to it through the
// endpoints and never fans out to several nodes.
func (c *TalosConnection) ctx() context.Context {
	return client.WithNode(context.Background(), c.node)
}

// Version returns the node's Talos version.
func (c *TalosConnection) Version() (*Version, error) {
	resp, err := c.client.Version(c.ctx())
	if err != nil {
		return nil, wrap(err)
	}
	for _, m := range resp.GetMessages() {
		v := m.GetVersion()
		if v == nil {
			continue
		}
		return &Version{
			Tag:       v.GetTag(),
			Sha:       v.GetSha(),
			GoVersion: v.GetGoVersion(),
			OS:        v.GetOs(),
			Arch:      v.GetArch(),
		}, nil
	}
	return nil, errors.New("talos: the node returned no version")
}

// Version is the node's Talos version.
type Version struct {
	Tag       string
	Sha       string
	GoVersion string
	OS        string
	Arch      string
}

// ResolveType resolves a resource type or alias, as `talosctl get` does, to
// its full type and default namespace.
func (c *TalosConnection) ResolveType(typ string) (resource.Type, resource.Namespace, error) {
	var ns resource.Namespace
	rd, err := c.client.ResolveResourceKind(c.ctx(), &ns, typ)
	if err != nil {
		return "", "", wrap(err)
	}
	spec := rd.TypedSpec()
	if ns == "" {
		ns = spec.DefaultNamespace
	}
	return spec.Type, ns, nil
}

// List returns every resource of the type in the namespace.
func (c *TalosConnection) List(ns resource.Namespace, typ resource.Type) ([]resource.Resource, error) {
	list, err := c.client.COSI.List(c.ctx(), resource.NewMetadata(ns, typ, "", resource.VersionUndefined),
		state.WithListUnmarshalOptions(state.WithSkipProtobufUnmarshal()))
	if err != nil {
		return nil, wrap(err)
	}
	return list.Items, nil
}

// Get returns one resource.
func (c *TalosConnection) Get(ns resource.Namespace, typ resource.Type, id resource.ID) (resource.Resource, error) {
	r, err := c.client.COSI.Get(c.ctx(), resource.NewMetadata(ns, typ, id, resource.VersionUndefined),
		state.WithGetUnmarshalOptions(state.WithSkipProtobufUnmarshal()))
	if err != nil {
		return nil, wrap(err)
	}
	return r, nil
}

// ReadFile reads a file on the node, which only the os:admin role may do.
func (c *TalosConnection) ReadFile(path string) ([]byte, error) {
	r, err := c.client.Read(c.ctx(), path)
	if err != nil {
		return nil, wrap(err)
	}
	defer r.Close() //nolint:errcheck
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, wrap(err)
	}
	return data, nil
}

// IsNotFound reports whether the Talos API has no such resource.
func IsNotFound(err error) bool {
	return err != nil && (state.IsNotFoundError(err) || status.Code(errors.Unwrap(err)) == codes.NotFound ||
		strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "doesn't exist"))
}

// wrap turns the Talos API's permission errors into ErrNeedsAdmin.
func wrap(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.PermissionDenied || strings.Contains(err.Error(), "PermissionDenied") {
		return fmt.Errorf("%w: %v", ErrNeedsAdmin, err)
	}
	if state.IsNotFoundError(err) || status.Code(err) == codes.NotFound {
		return err
	}
	return fmt.Errorf("talos: %w", err)
}

// NodeID returns the node's identity, which Talos generates once and keeps
// across reboots (cluster.Identity, the ID discovery uses).
func (c *TalosConnection) NodeID() (string, error) {
	r, err := c.Get("cluster", "Identities.cluster.talos.dev", "local")
	if err != nil {
		return "", err
	}
	spec, err := Spec(r)
	if err != nil {
		return "", err
	}
	id, _ := spec["nodeId"].(string)
	if id == "" {
		return "", errors.New("talos: the node has no identity")
	}
	return id, nil
}

// Hostname returns the node's hostname, or "" when it has none yet.
func (c *TalosConnection) Hostname() string {
	r, err := c.Get("network", "HostnameStatuses.net.talos.dev", "hostname")
	if err != nil {
		return ""
	}
	spec, err := Spec(r)
	if err != nil {
		return ""
	}
	hostname, _ := spec["hostname"].(string)
	return hostname
}

// Spec returns a resource's spec as a dict, as `talosctl get -o yaml` shows it.
func Spec(r resource.Resource) (map[string]any, error) {
	m, err := Marshal(r)
	if err != nil {
		return nil, err
	}
	spec, _ := m["spec"].(map[string]any)
	return spec, nil
}

// Marshal returns a resource as a dict with its metadata and spec.
func Marshal(r resource.Resource) (map[string]any, error) {
	out, err := resource.MarshalYAML(r)
	if err != nil {
		return nil, err
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

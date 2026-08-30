// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/container"
	containerruntime "go.mondoo.com/mql/providers/os/connection/container/runtime"
	"go.mondoo.com/mql/providers/os/connection/device"
	"go.mondoo.com/mql/providers/os/connection/docker"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh"
	"go.mondoo.com/mql/providers/os/connection/tar"
	"go.mondoo.com/mql/providers/os/connection/vagrant"
	"go.mondoo.com/mql/providers/os/connection/winrm"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id"
	"go.mondoo.com/mql/providers/os/resources"
	"go.mondoo.com/mql/providers/os/resources/discovery/docker_engine"
	"go.mondoo.com/mql/providers/os/resources/discovery/mcp_servers"
	"go.mondoo.com/mql/utils/stringx"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func parseDiscover(flags map[string]*llx.Primitive) *inventory.Discovery {
	discovery := &inventory.Discovery{Targets: []string{"auto"}}
	if flag, ok := flags["discover"]; ok && len(flag.Array) > 0 {
		discovery.Targets = []string{}
		for i := range flag.Array {
			discovery.Targets = append(discovery.Targets, string(flag.Array[i].Value))
		}
	}
	return discovery
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.Flags
	if flags == nil {
		flags = map[string]*llx.Primitive{}
	}

	conf := &inventory.Config{
		Sudo:     shared.ParseSudo(flags),
		Discover: parseDiscover(flags),
		Type:     req.Connector,
	}

	assetName := ""
	port := 0
	switch req.Connector {
	case "local":
		conf.Type = shared.Type_Local.String()
	case "device":
		conf.Type = shared.Type_Device.String()
	case "ssh":
		conf.Type = shared.Type_SSH.String()
		port = 22
	case "winrm":
		conf.Type = shared.Type_Winrm.String()
		port = 5985
	case "vagrant":
		conf.Type = shared.Type_Vagrant.String()
	case "docker":
		if len(req.Args) > 1 {
			// `docker file <path>` is docker-only because a Dockerfile is a
			// docker-specific build recipe, not a runnable container.
			if req.Args[0] == "file" {
				conf.Type = shared.Type_DockerFile.String()
				conf.Path = req.Args[1]
			} else {
				parseContainerSubcommand(req.Args[0], req.Args[1], conf)
			}
		} else {
			connType, err := docker.FindDockerObjectConnectionType(req.Args[0])
			if err != nil {
				return nil, err
			}
			conf.Type = connType
			containerID := req.Args[0]
			conf.Host = containerID
			assetName = containerID
		}
	case "container":
		if len(req.Args) > 1 {
			parseContainerSubcommand(req.Args[0], req.Args[1], conf)
		} else {
			// Unlike `docker`, the `container` connector does not probe a runtime,
			// so a bare argument can only be an image reference. Use explicit
			// `container container <id>` to scan a specific running container.
			if _, err := name.ParseReference(req.Args[0], name.WeakValidation); err != nil {
				return nil, errors.New("`container " + req.Args[0] + "` is not a valid image reference; use `container container <id>` for a running container or `container image <ref>` for an image")
			}
			conf.Type = shared.Type_DockerImage.String()
			conf.Host = req.Args[0]
			assetName = req.Args[0]
		}
	case "filesystem", "fs":
		conf.Type = shared.Type_FileSystem.String()
		if len(req.Args) > 0 {
			conf.Path = req.Args[0]
		} else {
			log.Warn().Msg("no path provided as an arg, looking for --path flag")
		}
	}

	user := ""
	if len(req.Args) != 0 && (!strings.HasPrefix(req.Connector, "docker") && !strings.HasPrefix(req.Connector, "container")) {
		target := req.Args[0]
		if !strings.Contains(target, "://") {
			target = "ssh://" + target
		}

		x, err := url.Parse(target)
		if err != nil {
			return nil, errors.New("incorrect format of target, please use user@host:port")
		}

		user = x.User.Username()
		conf.Host = x.Hostname()
		conf.Path = x.Path
		if sPort := x.Port(); sPort != "" {
			port, err = strconv.Atoi(x.Port())
			if err != nil {
				return nil, errors.New("port '" + x.Port() + "'is incorrectly formatted, must be a number")
			}
		}
	}

	if port > 0 {
		conf.Port = int32(port)
	}

	if x, ok := flags["password"]; ok && len(x.Value) != 0 {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, string(x.Value)))
	}

	identityFileProvided := false
	if x, ok := flags["identity-file"]; ok && len(x.Value) != 0 {
		credential, err := vault.NewPrivateKeyCredentialFromPath(user, string(x.Value), "")
		if err != nil {
			return nil, err
		}
		conf.Credentials = append(conf.Credentials, credential)
		identityFileProvided = true
	}

	if x, ok := flags["path"]; ok && len(x.Value) != 0 {
		conf.Path = string(x.Value)
	}

	if user != "" && !identityFileProvided {
		conf.Credentials = append(conf.Credentials, &vault.Credential{Type: vault.CredentialType_ssh_agent, User: user})
	}

	asset := &inventory.Asset{
		Name:        assetName,
		Connections: []*inventory.Config{conf},
	}

	idDetector := ""
	if flag, ok := flags["id-detector"]; ok {
		if string(flag.Value) != "" {
			idDetector = string(flag.Value)
		}
	}
	if idDetector != "" {
		asset.IdDetector = []string{idDetector}
	}

	if conf.Options == nil {
		conf.Options = map[string]string{}
	}

	if disableCache, ok := flags["disable-cache"]; ok {
		conf.Options["disable-cache"] = strconv.FormatBool(disableCache.RawData().Value.(bool))
	}

	if containerProxy, ok := flags[shared.ContainerProxyOption]; ok {
		proxyVal := containerProxy.RawData().Value.(string)
		if proxyVal != "" {
			conf.Options[shared.ContainerProxyOption] = proxyVal
		}
	}

	if lun, ok := flags["lun"]; ok {
		conf.Options["lun"] = lun.RawData().Value.(string)
	}

	deviceNames := []string{}
	if deviceName, ok := flags["device-name"]; ok {
		deviceNames = append(deviceNames, deviceName.RawData().Value.(string))
	}
	if deviceName, ok := flags["device-names"]; ok {
		deviceNamesList := deviceName.RawData().Value.([]any)
		for _, deviceName := range deviceNamesList {
			deviceNames = append(deviceNames, deviceName.(string))
		}
	}
	conf.Options["device-names"] = strings.Join(deviceNames, ",")

	if serialNumber, ok := flags["serial-number"]; ok {
		conf.Options["serial-number"] = serialNumber.RawData().Value.(string)
	}
	if mountAll, ok := flags["mount-all-partitions"]; ok {
		conf.Options["mount-all-partitions"] = strconv.FormatBool(mountAll.RawData().Value.(bool))
	}
	if skipFstab, ok := flags["skip-attempt-expand-partitions"]; ok {
		conf.Options["skip-attempt-expand-partitions"] = strconv.FormatBool(skipFstab.RawData().Value.(bool))
	}
	if includeMounted, ok := flags["include-mounted"]; ok {
		conf.Options["include-mounted"] = strconv.FormatBool(includeMounted.RawData().Value.(bool))
	}
	if keepMounted, ok := flags["keep-mounted"]; ok {
		conf.Options["keep-mounted"] = strconv.FormatBool(keepMounted.RawData().Value.(bool))
	}

	if platformIDs, ok := flags["platform-ids"]; ok {
		platformIDs := platformIDs.Array
		strs := []string{}
		for _, pID := range platformIDs {
			strs = append(strs, pID.RawData().Value.(string))
		}
		if len(strs) > 0 {
			conf.Options["inject-platform-ids"] = strings.Join(strs, ",")
		}
	}
	res := plugin.ParseCLIRes{
		Asset: asset,
	}

	return &res, nil
}

// LocalAssetReq ist a sample request to connect to the local OS.
// Useful for test automation.
var LocalAssetReq = &plugin.ConnectReq{
	Asset: &inventory.Asset{
		Connections: []*inventory.Config{{
			Type: "local",
		}},
	},
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset information yet.
	if !req.Asset.Connections[0].DelayDiscovery && (req.Asset.Platform == nil || req.Asset.Platform.Name == "") {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	// for some assets we need to do additional asset name detection, eg. macOS
	s.assetName(req.Asset, conn)

	log.Debug().Str("asset", req.Asset.Name).Msg("detected asset")

	var inv *inventory.Inventory
	connType := conn.Asset().Connections[0].Type
	switch connType {
	case shared.Type_DockerRegistry.String(), shared.Type_ContainerRegistry.String():
		regConn := conn.(*container.RegistryConnection)
		inv, err = regConn.DiscoverImages()
		if err != nil {
			return nil, err
		}
	case shared.Type_Local.String(), shared.Type_DockerContainer.String():
		inv, err = s.discoverLocalContainers(conn.Asset().Connections[0])
		if err != nil {
			return nil, err
		}
		mcpInv, err := s.discoverMCPServers(conn)
		if err != nil {
			log.Warn().Err(err).Msg("failed to discover mcp servers")
		} else if mcpInv != nil {
			if inv == nil {
				inv = mcpInv
			} else {
				inv.AddAssets(mcpInv.Spec.GetAssets()...)
			}
		}
	}

	for _, connCreds := range conn.Asset().Connections[0].Credentials {
		switch connCreds.Type {
		case vault.CredentialType_aws_ec2_instance_connect:
			tags, err := s.discoverEc2Tags(conn.Asset().Connections[0], conn.Asset().PlatformIds)
			if err == nil {
				if req.Asset.Labels == nil {
					req.Asset.Labels = map[string]string{}
				}
				maps.Copy(req.Asset.Labels, tags)
			}
		}
	}

	return &plugin.ConnectRes{
		Id:        uint32(conn.ID()),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inv,
	}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	asset := &inventory.Asset{
		Mrn:         req.Asset.Mrn,
		PlatformIds: req.Asset.PlatformIds,
		Platform:    req.Asset.Platform,
		Connections: []*inventory.Config{{
			Type: "mock",
		}},
	}

	conn, err := s.connect(&plugin.ConnectReq{
		Features: req.Features,
		Upstream: req.Upstream,
		Asset:    asset,
	}, callback)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:    uint32(conn.ID()),
		Name:  conn.Name(),
		Asset: asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (shared.Connection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	if conf.Type == "k8s" {
		// Clone to avoid mutating the original config from the calling provider.
		// We must zero ParentConnectionId because that parent lives in the k8s
		// provider process, not here — AddRuntime would fail with "parent connection N not found".
		conf = conf.CloneVT()
		conf.ParentConnectionId = 0
	}

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn shared.Connection
		var err error

		switch conf.Type {
		case shared.Type_Local.String(), "k8s": // FIXME: k8s is a temp workaround for cross-provider resources
			conn = local.NewConnection(connId, conf, asset)

			fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
			if err == nil {
				if asset.Name == "" {
					asset.Name = fingerprint.Name
				}
				asset.PlatformIds = fingerprint.PlatformIDs
				asset.IdDetector = fingerprint.ActiveIdDetectors
				asset.MergePlatform(p)
				appendRelatedAssetsFromFingerprint(fingerprint, asset)
			}
		case shared.Type_Device.String():
			conn, err = device.NewDeviceConnection(connId, conf, asset)
		case shared.Type_SSH.String():
			conn, err = ssh.NewConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}

			fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
			if err == nil {
				if asset.Name == "" && conn.Asset().Connections[0].Runtime != "vagrant" {
					asset.Name = fingerprint.Name
				}
				asset.PlatformIds = fingerprint.PlatformIDs
				asset.IdDetector = fingerprint.ActiveIdDetectors
				asset.MergePlatform(p)
				appendRelatedAssetsFromFingerprint(fingerprint, asset)
			}

		case shared.Type_Winrm.String():
			conn, err = winrm.NewConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}

			fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
			if err == nil {
				asset.Name = fingerprint.Name
				asset.PlatformIds = fingerprint.PlatformIDs
				asset.IdDetector = fingerprint.ActiveIdDetectors
				asset.MergePlatform(p)
				appendRelatedAssetsFromFingerprint(fingerprint, asset)
			}

		case shared.Type_Tar.String():
			conn, err = tar.NewConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}

			fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
			if err == nil {
				asset.Name = fingerprint.Name
				asset.PlatformIds = fingerprint.PlatformIDs
				asset.IdDetector = fingerprint.ActiveIdDetectors
				asset.MergePlatform(p)
				appendRelatedAssetsFromFingerprint(fingerprint, asset)
			}

		case shared.Type_DockerSnapshot.String():
			conn, err = docker.NewSnapshotConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}

			fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
			if err == nil {
				asset.Name = fingerprint.Name
				asset.PlatformIds = fingerprint.PlatformIDs
				asset.IdDetector = fingerprint.ActiveIdDetectors
				asset.MergePlatform(p)
				appendRelatedAssetsFromFingerprint(fingerprint, asset)
			}

		case shared.Type_Vagrant.String():
			conn, err = vagrant.NewVagrantConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}
			// We need to detect the platform for the connection asset here, because
			// this platform information will be used to determine the package manager
			err := s.detect(conn.Asset(), conn)
			if err != nil {
				return nil, err
			}

		case shared.Type_DockerContainer.String():
			conn, err = docker.NewDockerEngineContainer(connId, conf, asset)

		case shared.Type_DockerImage.String():
			conn, err = docker.NewContainerImageConnection(connId, conf, asset)

		case shared.Type_DockerFile.String():
			local := local.NewConnection(connId, conf, asset)
			// we need to identify the local OS family so that we're able to resolve the file details
			// properly
			localFamily := []string{}
			os, ok := detector.DetectOS(local)
			if ok {
				localFamily = os.Family
			}
			conn, err = docker.NewDockerfileConnection(connId, conf, asset, local, localFamily)

		case shared.Type_DockerRegistry.String(), shared.Type_ContainerRegistry.String():
			conn, err = container.NewRegistryConnection(connId, asset)

		case shared.Type_RegistryImage.String():
			conn, err = container.NewRegistryImage(connId, conf, asset)

		case shared.Type_RuntimeImage.String():
			conn, err = containerruntime.NewRuntimeImage(connId, conf, asset)

		case shared.Type_FileSystem.String():
			conn, err = fs.NewConnection(connId, conf, asset)
			if err != nil {
				return nil, err
			}
			// This is a workaround to set Google COS platform IDs when scanned from inside k8s
			pID, err := conn.(*fs.FileSystemConnection).Identifier()
			if err != nil {
				fingerprint, p, err := id.IdentifyPlatform(conn, req, asset.Platform, asset.IdDetector)
				if err == nil {
					asset.Name = fingerprint.Name
					asset.PlatformIds = fingerprint.PlatformIDs
					asset.IdDetector = fingerprint.ActiveIdDetectors
					asset.MergePlatform(p)
				}
			} else {
				// In this case asset.Name should already be set via the inventory
				asset.PlatformIds = []string{pID}
			}

		// Do not expose mock connection as a supported type
		case "mock":
			conn, err = mock.New(connId, asset)

		default:
			return nil, plugin.ErrUnsupportedProvider
		}

		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		conf.Id = connId
		conf.Capabilities = conn.Capabilities().String()

		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	if asset.Platform != nil && asset.Platform.Kind == "" {
		asset.Platform.Kind = inventory.AssetKindBaremetal
	}

	return runtime.Connection.(shared.Connection), nil
}

func (s *Service) discoverEc2Tags(conf *inventory.Config, platformIds []string) (map[string]string, error) {
	if conf == nil {
		return nil, nil
	}
	var instanceId string
	for _, id := range platformIds {
		// we are looking for a platform id similar to:
		// //platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/{}/regions/{}/instances/{id}"
		if strings.Contains(id, "/instances/") {
			parts := strings.Split(id, "/")
			instanceId = parts[len(parts)-1]
		}
	}

	awsConfigOptions := []func(*config.LoadOptions) error{}
	for key, value := range conf.Options {
		switch key {
		case "region":
			awsConfigOptions = append(awsConfigOptions, config.WithRegion(value))
		case "profile":
			awsConfigOptions = append(awsConfigOptions, config.WithSharedConfigProfile(value))
		}
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), awsConfigOptions...)
	if err != nil {
		return nil, err
	}

	ec2svc := ec2.NewFromConfig(cfg)
	filters := []ec2types.Filter{
		{
			Name:   aws.String("resource-id"),
			Values: []string{instanceId},
		},
	}
	tags, err := ec2svc.DescribeTags(context.Background(), &ec2.DescribeTagsInput{Filters: filters})
	if err != nil {
		return nil, err
	}

	m := map[string]string{}
	for _, t := range tags.Tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m, nil
}

func (s *Service) discoverLocalContainers(conf *inventory.Config) (*inventory.Inventory, error) {
	if conf == nil || conf.Discover == nil {
		return nil, nil
	}

	if !stringx.ContainsAnyOf(conf.Discover.Targets, "all", docker_engine.DiscoveryContainerRunning, docker_engine.DiscoveryContainerImages) {
		return nil, nil
	}

	resolvedAssets, err := docker_engine.DiscoverDockerEngineAssets(conf)
	if err != nil {
		return nil, err
	}

	inventory := &inventory.Inventory{}
	inventory.AddAssets(resolvedAssets...)

	return inventory, nil
}

// discoverMCPServers discovers MCP servers configured on the host as their own
// assets. It is opt-in: it runs only when the `mcp-servers` target (or `all`) is
// explicitly requested, so it stays off by default and under `auto`. The os
// provider emits the connection info the AI provider needs; it never connects to
// the MCP server itself. See ADR 030.
func (s *Service) discoverMCPServers(conn shared.Connection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf == nil || conf.Discover == nil {
		return nil, nil
	}
	if !stringx.ContainsAnyOf(conf.Discover.Targets, "all", mcp_servers.DiscoveryMCPServers) {
		return nil, nil
	}

	runtime, err := s.GetRuntime(uint32(conn.ID()))
	if err != nil {
		return nil, err
	}

	resolvedAssets, err := resources.DiscoverMCPServerAssets(runtime, conn.Asset())
	if err != nil {
		return nil, err
	}

	inv := &inventory.Inventory{}
	inv.AddAssets(resolvedAssets...)
	return inv, nil
}

// parseContainerSubcommand translates one of the shared `image|registry|tar|container`
// subcommands (used by both the `docker` and `container` connectors) into the
// matching conf.Type plus host/path assignment. Unknown subcommands are a no-op
// so the caller can layer connector-specific subcommands (e.g. `docker file`).
func parseContainerSubcommand(subcommand, target string, conf *inventory.Config) {
	switch subcommand {
	case "image":
		conf.Type = shared.Type_DockerImage.String()
		conf.Host = target
	case "registry":
		conf.Type = shared.Type_DockerRegistry.String()
		conf.Host = target
		conf.DelayDiscovery = true
	case "tar":
		conf.Type = shared.Type_DockerSnapshot.String()
		conf.Path = target
	case "container":
		conf.Type = shared.Type_DockerContainer.String()
		conf.Host = target
	}
}

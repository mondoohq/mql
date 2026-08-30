// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/discovery/docker_engine"
	"go.mondoo.com/mql/providers/os/resources/discovery/mcp_servers"
)

var Config = plugin.Provider{
	Name:    "os",
	ID:      "go.mondoo.com/mql/providers/os",
	Version: "13.40.9",
	ConnectionTypes: []string{
		shared.Type_Local.String(),
		shared.Type_SSH.String(),
		shared.Type_Tar.String(),
		shared.Type_DockerSnapshot.String(),
		shared.Type_Vagrant.String(),
		shared.Type_DockerContainer.String(),
		shared.Type_DockerImage.String(),
		shared.Type_DockerFile.String(),
		shared.Type_DockerRegistry.String(),
		shared.Type_ContainerRegistry.String(),
		shared.Type_RegistryImage.String(),
		shared.Type_RuntimeImage.String(),
		shared.Type_FileSystem.String(),
		shared.Type_Winrm.String(),
		shared.Type_Device.String(),
	},
	Connectors: []plugin.Connector{
		{
			Name:  "local",
			Use:   "local",
			Short: "your local system",
			Long: `Use the local provider to query your local system. This is the default provider. There's no need to specify local in a command.  

Examples:
  cnspec shell
  cnspec scan
  cnspec scan -o json > FILENAME.json
`,
			MinArgs: 0,
			MaxArgs: 0,
			Discovery: []string{
				docker_engine.DiscoveryContainerRunning,
				docker_engine.DiscoveryContainerImages,
				// advertising the target in --discover help does NOT enable it
				// (opt-in only).
				mcp_servers.DiscoveryMCPServers,
			},
			Flags: []plugin.Flag{
				{
					Long:        "sudo",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Elevate privileges with sudo",
					ConfigEntry: "sudo.active",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
			},
		},
		{
			Name:  "ssh",
			Use:   "ssh user@host",
			Short: "a remote system via SSH",
			Long: `Use the ssh provider to query remote systems using SSH.  

Examples:
  cnspec scan ssh USER@IP-ADDRESS --ask-pass
  cnspec shell ssh USER@IP-ADDRESS --ask-pass
`,
			MinArgs: 1,
			MaxArgs: 1,
			Flags: []plugin.Flag{
				{
					Long:    "sudo",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Elevate privileges with sudo",
				},
				{
					Long:    "insecure",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Disable SSH hostkey verification",
				},
				{
					Long:        "ask-pass",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Prompt for connection password",
					ConfigEntry: "-",
				},
				{
					Long:        "password",
					Short:       "p",
					Type:        plugin.FlagType_String,
					Default:     "",
					Desc:        "Set the connection password for SSH",
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:    "identity-file",
					Short:   "i",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Select a file from which to read the identity (private key) for public key authentication",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
			},
		},
		{
			Name:  "winrm",
			Use:   "winrm user@host",
			Short: "a remote system via WinRM",
			Long: `Use the winrm provider to query remote systems using WinRM.  

Examples:
  cnspec scan winrm USER@HOST --ask-pass
  cnspec shell winrm USER@HOST --ask-pass
`,
			MinArgs: 1,
			MaxArgs: 1,
			Flags: []plugin.Flag{
				{
					Long:    "insecure",
					Default: "false",
					Desc:    "Disable TLS/SSL checks",
					Type:    plugin.FlagType_Bool,
				},
				{
					Long:    "ask-pass",
					Default: "false",
					Desc:    "Prompt for connection password",
					Type:    plugin.FlagType_Bool,
				},
				{
					Long:        "password",
					Short:       "p",
					Default:     "false",
					Desc:        "Set the connection password for SSH",
					Type:        plugin.FlagType_String,
					Option:      plugin.FlagOption_Password,
					ConfigEntry: "-",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
			},
		},
		{
			Name:  "vagrant",
			Use:   "vagrant host",
			Short: "a Vagrant host",
			Long: `Use the vagrant provider to query Vagrant virtual machines.  

Examples:
  cnspec scan vagrant HOST
  cnspec shell vagrant HOST
`,
			MinArgs: 1,
			MaxArgs: 1,
			Flags: []plugin.Flag{
				{
					Long:    "sudo",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Elevate privileges with sudo",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
			},
		},
		{
			Name:  "container",
			Use:   "container",
			Short: "a running container or container image",
			Long: `Use the container provider to query running containers or container images.  

Examples:
  cnspec scan container ubuntu:latest
  cnspec shell container ubuntu:latest
`,
			MinArgs: 1,
			MaxArgs: 2,
			Discovery: []string{
				docker_engine.DiscoveryContainerRunning,
				docker_engine.DiscoveryContainerImages,
			},
			Flags: []plugin.Flag{
				{
					Long:        "sudo",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Elevate privileges with sudo",
					ConfigEntry: "sudo.active",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
				{
					Long:    "disable-cache",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Disable the in-memory cache for images. WARNING: This significantly slows scans.",
				},
				{
					Long:    "container-proxy",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HTTP proxy to use for container pulls",
				},
			},
		},
		{
			Name:  "docker",
			Use:   "docker",
			Short: "a running Docker container, Docker image, or Dockerfile",
			Long: `Use the docker provider to query running Docker containers or container images in public or private container registries using their registry name. Or scan a Dockerfile by specifying its path. 

Examples:
  cnspec scan docker <DOCKER-CONTAINER-ID>
  cnspec scan docker file <FILEPATH>
  cnspec scan docker ubuntu:latest
  cnspec scan docker elastic/elasticsearch:7.2.0
  cnspec scan docker gcr.io/google-containers/ubuntu:22.04
  cnspec scan docker registry.access.redhat.com/ubi8/ubi
`,
			MinArgs: 1,
			MaxArgs: 2,
			Discovery: []string{
				docker_engine.DiscoveryContainerRunning,
				docker_engine.DiscoveryContainerImages,
			},
			Flags: []plugin.Flag{
				{
					Long:        "sudo",
					Type:        plugin.FlagType_Bool,
					Default:     "false",
					Desc:        "Elevate privileges with sudo.",
					ConfigEntry: "sudo.active",
				},
				{
					Long:    "id-detector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "User override for platform ID detection mechanism",
					Option:  plugin.FlagOption_Hidden,
				},
				{
					Long:    "disable-cache",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Disable the in-memory cache for images. WARNING: This significantly slows scans.",
				},
				{
					Long:    "container-proxy",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HTTP proxy to use for container pulls",
				},
			},
		},
		{
			Name:    "filesystem",
			Aliases: []string{"fs"},
			Use:     "filesystem PATH [flags]",
			Short:   "a mounted file system target",
			Long: `Use the filesystem provider to query mounted file systems. 

Examples:
  cnspec scan filesystem <MOUNT-PATH-TO-FILE-SYSTEM>
  cnspec shell fs <MOUNT-PATH-TO-FILE-SYSTEM>
`,
			MinArgs: 0,
			MaxArgs: 1,
			Flags: []plugin.Flag{
				{
					Long:    "path",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Path to a local file or directory for the connection to use",
					Option:  plugin.FlagOption_Deprecated,
				},
			},
		},
		{
			Name:  "device",
			Use:   "device",
			Short: "a block device target",
			Long: `Use the device provider to query block devices. 

Examples:
  cnspec scan device --lun <LOGICAL-UNIT-NUMBER>
  cnspec shell device --device-name <NAME-OF-LINUX-DEVICE>
`,
			MinArgs: 0,
			MaxArgs: 0,
			Flags: []plugin.Flag{
				{
					Long:   "lun",
					Type:   plugin.FlagType_String,
					Desc:   "The logical unit number of the block device. Do not use with --device-name or --serial-number",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "device-name",
					Type:   plugin.FlagType_String,
					Desc:   "The target device, e.g., /dev/sda. Supported only for Linux scanning. Do not use together with --lun or --serial-number",
					Option: plugin.FlagOption_Hidden | plugin.FlagOption_Deprecated,
				},
				{
					Long:   "device-names",
					Type:   plugin.FlagType_List,
					Desc:   "The target devices, e.g., /dev/sda. Supported only for Linux scanning. Do not use together with --lun or --serial-number",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "serial-number",
					Type:   plugin.FlagType_String,
					Desc:   "The serial number of the block device. Supported only for Windows scanning. Do not use together with --device-name or --lun",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "mount-all-partitions",
					Type:   plugin.FlagType_Bool,
					Desc:   "Mount all partitions of the block device",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "skip-attempt-expand-partitions",
					Type:   plugin.FlagType_Bool,
					Desc:   "Skip attempt on trying to discover the fstab file on the device",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "include-mounted",
					Type:   plugin.FlagType_Bool,
					Desc:   "Include mounted block devices in the scan",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "keep-mounted",
					Type:   plugin.FlagType_Bool,
					Desc:   "Keep mounted block devices mounted after the scan",
					Option: plugin.FlagOption_Hidden,
				},
				{
					Long:   "platform-ids",
					Type:   plugin.FlagType_List,
					Desc:   "List of platform IDs to inject to the asset",
					Option: plugin.FlagOption_Hidden,
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=os"},
			Key:          "family",
			Title:        "OS Family",
			Values: map[string]*inventory.AssetUrlBranch{
				// linux, windows, darwin, unix, ...
				"*": {
					Key:   "platform",
					Title: "Platform",
					Values: map[string]*inventory.AssetUrlBranch{
						// redhat, arch, ...
						"*": {
							Key:   "version",
							Title: "Version",
							Values: map[string]*inventory.AssetUrlBranch{
								// any valid version for the OS
								"*": nil,
							},
						},
					},
				},
			},
		},
		{
			PathSegments: []string{"technology=container"},
			Key:          "kind",
			Title:        "Container Kind",
			Values: map[string]*inventory.AssetUrlBranch{
				// container-image, container, ...
				"*": {
					References: []string{"technology=os"},
				},
			},
		},
		{
			PathSegments: []string{"technology=iac", "category=dockerfile"},
		},
	},
	Platforms: detector.CatalogPlatforms(),
}

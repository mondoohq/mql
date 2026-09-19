// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"dario.cat/mergo"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"sigs.k8s.io/yaml"

	// The in-memory vault has no heavy dependencies and stays in the SDK. Linking
	// it here guarantees the memory backend is always registered wherever
	// GetVault is used. Heavy backends (AWS, GCP, HashiCorp, keyring) live in the
	// separate go.mondoo.com/mql/vault module and are opted into by the binary
	// (see vault/register).
	_ "go.mondoo.com/mql/providers-sdk/v1/vault/inmemory"
)

//go:generate protoc --plugin=protoc-gen-go=../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../../../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=../../../:. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size+clone inventory.proto

const (
	InventoryFilePath = "mondoo.app/source-file"
)

var ErrProviderTypeDoesNotMatch = errors.New("provider type does not match")

type Option func(*Inventory)

// passes a list of asset into the Inventory Manager
func WithAssets(assetList ...*Asset) Option {
	return func(inventory *Inventory) {
		inventory.AddAssets(assetList...)
	}
}

func New(opts ...Option) *Inventory {
	inventory := &Inventory{
		Metadata: &ObjectMeta{},
		Spec:     &InventorySpec{},
	}

	for _, option := range opts {
		option(inventory)
	}

	return inventory
}

// InventoryFromYAML create an inventory from yaml contents
func InventoryFromYAML(data []byte) (*Inventory, error) {
	res := New()
	err := yaml.Unmarshal(data, res)
	if err != nil {
		return res, err
	}

	res.MarkRequestedNames()

	return res, nil
}

// MarkRequestedNames marks every named asset in the inventory as carrying a name
// its author chose, so the name outranks whatever a provider detects after
// connecting.
//
// By the time discovery sees an asset, a name an author wrote down and a name a
// provider filled in during its own ParseCLI are the same string in the same
// field; only the marker tells them apart. Call this from every loader that reads
// assets out of a file whose names the user wrote -- a mondoo inventory `name:`,
// an ansible inventory host key -- and not from one that merely copies the
// connection target into the name, where a provider's normalized name is the
// better answer.
func (p *Inventory) MarkRequestedNames() {
	for _, asset := range p.GetSpec().GetAssets() {
		if asset.GetName() != "" {
			asset.NameOverride = true
		}
	}
}

// InventoryFromFile loads an inventory from file system
func InventoryFromFile(path string) (*Inventory, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	inventoryData, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	inventory, err := InventoryFromYAML(inventoryData)
	if err != nil {
		return nil, err
	}

	inventory.ensureRequireMetadataStructs()
	inventory.Metadata.Labels[InventoryFilePath] = absPath

	return inventory, nil
}

func (p *Inventory) ensureRequireMetadataStructs() {
	if p.Metadata == nil {
		p.Metadata = &ObjectMeta{}
	}

	if p.Metadata.Labels == nil {
		p.Metadata.Labels = map[string]string{}
	}
}

// ToYAML returns the inventory as yaml
func (p *Inventory) ToYAML() ([]byte, error) {
	return yaml.Marshal(p)
}

func (p *Inventory) GetVault() (vault.Vault, error) {
	// instantiate with full vault config
	v, err := vault.New(p.Spec.Vault)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// PreProcess extracts all the embedded credentials from the assets and migrates those to in the
// dedicated credentials section. The pre-processed content is optimized for runtime access.
// Re-generating yaml, results into a different yaml output. While the results are identical,
// the yaml file is not.
func (p *Inventory) PreProcess() error {
	if p.Spec == nil {
		p.Spec = &InventorySpec{}
	}

	if p.Spec.Credentials == nil {
		p.Spec.Credentials = map[string]*vault.Credential{}
	}

	// we are going to use the labels in metadata, ensure the structs are in place
	p.ensureRequireMetadataStructs()

	// extract embedded credentials from assets into dedicated section
	for i := range p.Spec.Assets {
		asset := p.Spec.Assets[i]

		for j := range asset.Connections {
			c := asset.Connections[j]
			for k := range c.Credentials {
				cred := c.Credentials[k]
				if cred != nil && cred.SecretId != "" {
					// clean credentials
					// if a secret id with content is provided, we discard the content and always prefer the secret id
					cleanSecrets(cred)
				} else {
					// create secret id and add id to the credential
					secretId := ksuid.New().String()
					cred.SecretId = secretId
					// add a cloned credential to the map
					copy := cloneCred(cred)
					p.Spec.Credentials[secretId] = copy

					// replace current credential the secret id, essentially we just remove all the content
					cleanCred(cred)
				}
			}
		}
	}

	// iterate over all credentials and load private keys references
	for k := range p.Spec.Credentials {
		cred := p.Spec.Credentials[k]

		// ensure the secret id is correct
		cred.SecretId = k
		cred.PreProcess()

		// TODO: we may want to load it but we probably need
		// a local file watcher to detect changes
		if cred.PrivateKeyPath != "" {
			path := cred.PrivateKeyPath

			if strings.HasPrefix(path, "~/") {
				// special handling for ~
				usr, err := user.Current()
				if err != nil {
					return err
				}
				path = filepath.Join(usr.HomeDir, path[2:])
			} else if !filepath.IsAbs(cred.PrivateKeyPath) {
				// special handling for relative filenames, instead of loading
				// private keys from relative to the work directory, we want to
				// load the files relative to the source inventory

				// we handle credentials relative to the inventory file
				fileLoc, ok := p.Metadata.Labels[InventoryFilePath]
				if ok {
					path = filepath.Join(filepath.Dir(fileLoc), path)
				} else {
					absPath, err := filepath.Abs(path)
					if err != nil {
						return err
					}
					path = absPath
				}
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return errors.New("cannot read credential: " + path)
			}
			cred.Secret = data

			// only set the credential type if it is not set, pkcs12 also uses the private key path
			if cred.Type == vault.CredentialType_undefined {
				cred.Type = vault.CredentialType_private_key
			}
		}
	}
	return nil
}

func (p *Inventory) MarkConnectionsInsecure() {
	for i := range p.Spec.Assets {
		asset := p.Spec.Assets[i]
		for j := range asset.Connections {
			asset.Connections[j].Insecure = true
		}
	}
}

func cleanCred(c *vault.Credential) {
	c.User = ""
	c.Type = vault.CredentialType_undefined
	cleanSecrets(c)
}

func cleanSecrets(c *vault.Credential) {
	c.Secret = []byte{}
	c.PrivateKey = ""
	c.PrivateKeyPath = ""
	c.Password = ""
}

func cloneCred(c *vault.Credential) *vault.Credential {
	return c.CloneVT()
}

// Validate ensures consistency within the inventory.
// The implementation expects that PreProcess was executed before.
// - it checks that all secret ids are either part of the credential map or a vault is defined
// - it checks that all credentials have a secret id
func (p *Inventory) Validate() error {
	var err error
	for i := range p.Spec.Assets {
		a := p.Spec.Assets[i]
		for j := range a.Connections {
			conn := a.Connections[j]
			for k := range conn.Credentials {
				cred := conn.Credentials[k]
				err = isValidCredentialRef(cred)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (p *Inventory) AddAssets(assetList ...*Asset) {
	if p.Spec == nil {
		p.Spec = &InventorySpec{}
	}
	p.Spec.Assets = append(p.Spec.Assets, assetList...)
}

func (p *Inventory) ApplyLabels(labels map[string]string) {
	for i := range p.Spec.Assets {
		a := p.Spec.Assets[i]

		if a.Labels == nil {
			a.Labels = map[string]string{}
		}

		for k := range labels {
			a.Labels[k] = labels[k]
		}
	}
}

func (p *Inventory) ApplyCategory(category AssetCategory) {
	for i := range p.Spec.Assets {
		a := p.Spec.Assets[i]
		a.Category = category
	}
}

// isValidCredentialRef ensures an asset credential is defined properly
// The implementation assumes the credentials have been offloaded to the
// credential map before via PreProcess
func isValidCredentialRef(cred *vault.Credential) error {
	if cred.SecretId == "" {
		return errors.New("credential is missing the secret_id")
	}

	// credential references have no type defined
	if cred.Type != vault.CredentialType_undefined {
		return errors.New("credential reference has a wrong type defined")
	}

	return nil
}

// often used family names
var (
	FAMILY_UNIX    = "unix"
	FAMILY_DARWIN  = "darwin"
	FAMILY_LINUX   = "linux"
	FAMILY_BSD     = "bsd"
	FAMILY_WINDOWS = "windows"
)

// Merge performs a deep merge of the provided platform.
func (p *Platform) Merge(pf *Platform) {
	if pf != nil {
		if err := mergo.Merge(p, pf, mergo.WithOverride); err != nil {
			log.Error().Err(err).
				Interface("target", p).
				Interface("source", pf).
				Msg("unable to merge platform details")
		}
	}
}

func (p *Platform) IsFamily(family string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.Family, family)
}

func (p *Platform) PrettyTitle() string {
	if p == nil {
		return ""
	}
	prettyTitle := p.Title

	// extend the title only for OS and k8s objects
	if !p.IsFamily("k8s-workload") && !p.IsFamily("os") {
		return prettyTitle
	}

	var runtimeNiceName string
	runtimeName := p.Runtime
	if runtimeName != "" {
		switch runtimeName {
		case "aws-ec2-instance":
			runtimeNiceName = "AWS EC2 Instance"
		case "azure-vm":
			runtimeNiceName = "Azure Virtual Machine"
		case "docker-container":
			runtimeNiceName = "Docker Container"
		case "docker-image":
			runtimeNiceName = "Docker Image"
		case "gcp-vm":
			runtimeNiceName = "GCP Virtual Machine"
		case "k8s-cluster":
			runtimeNiceName = "Kubernetes Cluster"
		case "k8s-manifest":
			runtimeNiceName = "Kubernetes Manifest File"
		case "vsphere-host":
			runtimeNiceName = "vSphere Host"
		case "vsphere-vm":
			runtimeNiceName = "vSphere Virtual Machine"
		}
	} else {
		runtimeKind := p.GetKind()
		switch runtimeKind {
		case AssetKindBaremetal:
			runtimeNiceName = "Bare metal system"
		case "container":
			runtimeNiceName = "Container"
		case "container-image":
			runtimeNiceName = "Container image"
		case AssetKindCloudVM:
			runtimeNiceName = "Virtual machine"
		case "virtualmachine-image":
			runtimeNiceName = "Virtual machine image"
		}
	}
	// e.g. ", Kubernetes Cluster" and also "Kubernetes, Kubernetes Cluster" do not look nice, so prevent them
	if prettyTitle == "" || strings.Contains(runtimeNiceName, prettyTitle) {
		return runtimeNiceName
	}

	// do not add runtime name when the title is already obvious, e.g. "Network API, Network"
	if !strings.Contains(prettyTitle, runtimeNiceName) {
		prettyTitle += ", " + runtimeNiceName
	}

	return prettyTitle
}

type cloneSettings struct {
	noDiscovery        bool
	parentConnectionId *uint32
	withFilters        bool
}

type CloneOption interface {
	Apply(*cloneSettings)
}

// WithFilters ensures the discovery filters still get copied over
func WithFilters() CloneOption {
	return withFilters{}
}

type withFilters struct{}

func (w withFilters) Apply(o *cloneSettings) { o.withFilters = true }

// WithoutDiscovery removes the discovery flags in the opts to ensure the same discovery does not run again
func WithoutDiscovery() CloneOption {
	return withoutDiscovery{}
}

type withoutDiscovery struct{}

func (w withoutDiscovery) Apply(o *cloneSettings) { o.noDiscovery = true }

// WithoutDiscovery removes the discovery flags in the opts to ensure the same discovery does not run again
func WithParentConnectionId(parentId uint32) CloneOption {
	return withParentConnectionId{parentId: parentId}
}

type withParentConnectionId struct {
	parentId uint32
}

func (w withParentConnectionId) Apply(o *cloneSettings) { o.parentConnectionId = &w.parentId }

func (cfg *Config) Clone(opts ...CloneOption) *Config {
	if cfg == nil {
		return nil
	}

	cloneSettings := &cloneSettings{}
	for _, option := range opts {
		option.Apply(cloneSettings)
	}

	clonedObject := cfg.CloneVT()
	clonedObject.Id = 0
	if cloneSettings.noDiscovery {
		clonedObject.Discover = &Discovery{}
	}
	if cloneSettings.parentConnectionId != nil {
		clonedObject.ParentConnectionId = *cloneSettings.parentConnectionId
	}
	if cloneSettings.withFilters {
		if clonedObject.Discover == nil {
			clonedObject.Discover = &Discovery{}
		}
		clonedObject.Discover.Filter = make(map[string]string)
		maps.Copy(clonedObject.Discover.Filter, cfg.Discover.GetFilter())
	}

	return clonedObject
}

func (c *Config) ToUrl() string {
	schema := c.Type
	if _, ok := c.Options["tls"]; ok {
		schema = "tls"
	}

	host := c.Host
	if strings.HasPrefix(host, "sha256:") {
		host = strings.ReplaceAll(host, "sha256:", "")
	}

	path := c.Path
	if path != "" {
		if path[0] != '/' {
			path = "/" + path
		}
	}

	return schema + "://" + host + path
}

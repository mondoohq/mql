// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/ulikunitz/xz"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/logger/zerologadapter"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"golang.org/x/exp/slices"
)

var (
	SystemPath         string
	HomePath           string
	CustomProviderPath string
	// this is the default path for providers, it's either system or home path, if the user is root the system path is used
	DefaultPath string
	// CachedProviders contains all providers that have been loaded the last time
	// ListActive or ListAll have been called
	CachedProviders []*Provider
	// LastProviderInstall keeps track of when the last provider installation
	// took place relative to this runtime. It is initialized to a non-zero
	// timestamp during this file's init() method. Timestamps are unix seconds.
	LastProviderInstall int64
)

func init() {
	SystemPath = config.SystemDataPath("providers")
	DefaultPath = SystemPath
	if os.Geteuid() != 0 {
		HomePath, _ = config.HomePath("providers")
		DefaultPath = HomePath
	}
	CustomProviderPath = os.Getenv("PROVIDERS_PATH")
	if CustomProviderPath != "" {
		DefaultPath = CustomProviderPath
	}

	LastProviderInstall = time.Now().Unix()

	stampBuiltinSchemas()

	// Initialize the global coordinator instance
	coordinator := newCoordinator()
	Coordinator = coordinator
}

// stampBuiltinSchemas applies the provenance stamp (ADR 040 part 1) to the
// builtin providers' schemas. Builtins never go through Provider.LoadResources,
// which stamps on-disk providers. It runs once at init rather than on every
// builtin start: the schema object is shared with extensibleSchema's
// aggregate, which ranges over ProviderVersions under schema.sync, and a
// concurrent stamp is a map write during that iteration.
func stampBuiltinSchemas() {
	for _, x := range builtinProviders {
		if concrete, ok := x.Runtime.Schema.(*resources.Schema); ok && x.Config != nil {
			stampProviderVersion(concrete, x.Config.ID, x.Config.Version)
		}
	}
}

// deleteProvider removes a single resolved provider from disk. The path it
// removes is the exact one the provider was loaded from, which already honors a
// PROVIDERS_PATH override (or the system/home paths otherwise). Builtin
// providers have no on-disk path and cannot be removed.
func deleteProvider(provider *Provider) error {
	if provider.Path == "" {
		return errors.Newf("provider %q is builtin and cannot be removed", provider.Name)
	}
	if err := os.RemoveAll(provider.Path); err != nil {
		return errors.Wrapf(err, "failed to remove provider %q", provider.Name)
	}
	log.Info().Str("provider", provider.Name).Str("path", provider.Path).Msg("deleted installed provider")
	return nil
}

// Delete removes a single installed provider from disk by name. It resolves the
// provider through ListAll and delegates the removal to deleteProvider.
func Delete(name string) error {
	all, err := ListAll()
	if err != nil {
		return err
	}
	for _, provider := range all {
		if provider.Name == name {
			return deleteProvider(provider)
		}
	}
	return errors.Newf("provider %q not found", name)
}

// DeleteAll removes every installed provider from disk. It goes through ListAll
// — not the raw CachedProviders global — on purpose: ListAll returns the warm
// cache when it's populated and otherwise rescans the provider dirs, so it works
// regardless of cache state. A ListAll error bails rather than acting on a
// partial list; builtin providers are skipped, and per-provider removal errors
// are logged, not fatal (a non-root run can't remove a root-owned system path).
func DeleteAll() error {
	all, err := ListAll()
	if err != nil {
		return err
	}
	for _, provider := range all {
		if provider.Path == "" {
			continue
		}
		if err := deleteProvider(provider); err != nil {
			log.Warn().Err(err).Str("path", provider.Path).Msg("failed to remove installed provider")
		}
	}
	return nil
}

type ProviderLookup struct {
	ID           string
	ProviderName string
	ConnName     string
	ConnType     string
}

func (s ProviderLookup) String() string {
	res := []string{}
	if s.ID != "" {
		res = append(res, "id="+s.ID)
	}
	if s.ProviderName != "" {
		res = append(res, "provider="+s.ProviderName)
	}
	if s.ConnName != "" {
		res = append(res, "conn name="+s.ConnName)
	}
	if s.ConnType != "" {
		res = append(res, "conn type="+s.ConnType)
	}
	return strings.Join(res, " ")
}

type Providers map[string]*Provider

// FIXME: DEPRECATED, remove in v12.0 vv
// Unlike lookup, which searches through providers by ID, connection type and
// connection names, this function only cycles through the index of providers
// (which is based on IDs) in order and returns the first found provider.
// We introduced this function to help transition from versioned IDs in
// providers to unversioned IDs in providers.
func (p Providers) GetFirstID(ids ...string) (*Provider, bool) {
	for _, id := range ids {
		if found, ok := p[id]; ok {
			return found, true
		}
	}
	return nil, false
}

// ^^

// Lookup a provider in this list. If you search via ProviderID we will
// try to find the exact provider. Otherwise we will try to find a matching
// connector type first and name second.
func (p Providers) Lookup(search ProviderLookup) *Provider {
	if search.ID != "" {
		for _, provider := range p {
			if provider.ID == search.ID {
				return provider
			}
		}
	}

	if search.ProviderName != "" {
		for _, provider := range p {
			if provider.Name == search.ProviderName {
				return provider
			}
		}
	}

	if search.ConnType != "" {
		for _, provider := range p {
			if slices.Contains(provider.ConnectionTypes, search.ConnType) {
				return provider
			}
			for i := range provider.Connectors {
				if slices.Contains(provider.Connectors[i].Aliases, search.ConnType) {
					return provider
				}
			}
		}
	}

	if search.ConnName != "" {
		for _, provider := range p {
			for i := range provider.Connectors {
				if provider.Connectors[i].Name == search.ConnName {
					return provider
				}
				if slices.Contains(provider.Connectors[i].Aliases, search.ConnName) {
					return provider
				}
			}
		}
	}

	return nil
}

func (p Providers) Add(nu *Provider) {
	if nu != nil {
		p[nu.ID] = nu
	}
}

type Provider struct {
	*plugin.Provider
	// schemaMu serializes lazy loads of Schema. Schema is read by many
	// callers (often concurrently, e.g. multiple assets connecting at once
	// via Runtime.AddConnection -> EnsureProvider -> installDependencies)
	// while the first reader is still populating it. Every access to
	// Schema must be preceded by a successful LoadResources call so the
	// reader synchronizes with the (single) writer through this mutex.
	schemaMu  sync.Mutex
	Schema    resources.ResourcesSchema
	Path      string
	HasBinary bool
}

var (
	defaultHttpTimeout         = 30 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
)

func httpClientWithRetry() (*http.Client, error) {
	// api_proxy, the environment or the operating system's settings, in that
	// order; see cli/config/proxy.go.
	proxyFn, err := config.ProxyFunc()
	if err != nil {
		log.Fatal().Err(err).Msg("could not parse proxy URL")
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = zerologadapter.New(log.Logger)
	retryClient.HTTPClient = &http.Client{
		Transport: &http.Transport{
			Proxy: proxyFn,
			DialContext: (&net.Dialer{
				Timeout:   defaultHttpTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       defaultIdleConnTimeout,
			TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: defaultHttpTimeout,
	}
	return retryClient.StandardClient(), nil
}

// List providers that are going to be used in their default order:
// builtin > user > system. The providers are also loaded and provider their
// metadata/configuration.
func ListActive() (Providers, error) {
	all, err := ListAll()
	if err != nil {
		return nil, err
	}

	var res Providers = make(map[string]*Provider, len(all))
	for _, v := range all {
		res[v.ID] = v
	}

	// useful for caching; even if the structure gets updated with new providers
	Coordinator.SetProviders(res)
	return res, nil
}

// ListAll available providers, including duplicates between builtin, user,
// and system providers. We only return errors when the things we are trying
// to load don't work.
// Note: We load providers from cache so these expensive calls don't have
// to be repeated. If you want to force a refresh, you can nil out the cache.
func ListAll() ([]*Provider, error) {
	if CachedProviders != nil {
		return CachedProviders, nil
	}

	all := []*Provider{}
	CachedProviders = all

	// This really shouldn't happen, but just in case it does...
	// Logged at debug, not warn: embedders that ship their own builtin providers
	// (e.g. xgrep) intentionally configure no external provider paths, so this is
	// an expected condition rather than a misconfiguration to warn about.
	if SystemPath == "" && HomePath == "" && CustomProviderPath == "" {
		log.Debug().Msg("can't find any paths for providers, none are configured")
		return nil, nil
	}

	sysOk := config.ProbeDir(SystemPath)
	homeOk := config.ProbeDir(HomePath)
	if !sysOk && !homeOk {
		msg := log.Debug()
		if SystemPath != "" {
			msg = msg.Str("system-path", SystemPath)
		}
		if HomePath != "" {
			msg = msg.Str("home-path", HomePath)
		}
		msg.Msg("can't find any paths for providers, none are configured")
	}

	// when the user provides a custom provider path, we always load it and we ignore the system and home path
	// we do not check for its existence, and instead create it on the fly when needed
	if CustomProviderPath != "" {
		cur, err := findProviders(CustomProviderPath)
		if err != nil {
			log.Warn().Str("path", CustomProviderPath).Err(err).Msg("failed to get providers from custom provider path")
		}
		all = append(all, cur...)
	}

	if sysOk && CustomProviderPath == "" {
		cur, err := findProviders(SystemPath)
		if err != nil {
			log.Warn().Str("path", SystemPath).Err(err).Msg("failed to get providers from system path")
		}
		all = append(all, cur...)
	}

	if homeOk && CustomProviderPath == "" {
		cur, err := findProviders(HomePath)
		if err != nil {
			log.Warn().Str("path", HomePath).Err(err).Msg("failed to get providers from home path")
		}
		all = append(all, cur...)
	}

	for _, x := range builtinProviders {
		all = append(all, &Provider{
			Provider: x.Config,
			Schema:   x.Runtime.Schema,
		})
	}

	var res []*Provider
	for i := range all {
		provider := all[i]

		// builtin providers don't need to be loaded, so they are ok to be returned
		if provider.Path == "" {
			res = append(res, provider)
			continue
		}

		// we only add a provider if we can load it, otherwise it has bad
		// consequences for other mechanisms (like attaching shell, listing etc)
		if err := provider.LoadJSON(); err != nil {
			log.Error().Err(err).
				Str("provider", provider.Name).
				Str("path", provider.Path).
				Msg("failed to load provider")
			continue
		}

		// Note: we intentionally do NOT parse the provider's resource schema
		// here. Schemas are large (multiple megabytes across all installed
		// providers, and growing) and are loaded lazily the moment a provider is
		// actually connected (see (*coordinator).LoadSchema / Connect) or its
		// dependencies are inspected (installDependencies). Parsing every
		// provider's schema up front just to build the CLI wastes startup time
		// and memory for providers we never use.

		res = append(res, provider)
	}

	CachedProviders = res
	return res, nil
}

type ProviderNotFoundError struct {
	lookup ProviderLookup
}

func (e *ProviderNotFoundError) Error() string {
	return "cannot find provider for " + e.lookup.String()
}

// EnsureProvider makes sure that a given provider exists and returns it.
// You can supply providers either via:
//  1. providerID, which universally identifies it, e.g. "go.mondoo.com/mql/providers/os"
//  2. connectorName, which is what you see in the CLI e.g. "local", "ssh", ...
//  3. connectorType, which is how assets define the connector type when
//     they are moved between discovery and execution, e.g. "registry-image".
//
// If you disable autoUpdate, it will neither update NOR install missing providers.
//
// If you don't supply existing providers, it will look for alist of all
// active providers first.
func EnsureProvider(search ProviderLookup, autoUpdate bool, existing Providers) (*Provider, error) {
	if existing == nil {
		var err error
		existing, err = ListActive()
		if err != nil {
			return nil, err
		}
	}

	provider := existing.Lookup(search)
	if provider != nil {
		// For already installed providers, ensure all dependencies are installed
		if autoUpdate {
			err := installDependencies(provider, existing)
			if err != nil {
				return nil, err
			}
		}
		return provider, nil
	}

	if search.ID == mockProvider.ID || search.ConnName == "mock" || search.ConnType == "mock" {
		existing.Add(&mockProvider)
		return &mockProvider, nil
	}

	if search.ID == sbomProvider.ID || search.ConnName == "sbom" || search.ConnType == "sbom" {
		existing.Add(&sbomProvider)
		return &sbomProvider, nil
	}

	if search.ID == recordingProviderInstance.ID || search.ConnName == "recording" || search.ConnType == "recording" {
		existing.Add(&recordingProviderInstance)
		return &recordingProviderInstance, nil
	}

	upstream := DefaultProviders.Lookup(search)
	if upstream == nil {
		// we can't find any provider for this connector in our default set
		// FIXME: This causes a panic in the CLI, we should handle this better
		return nil, &ProviderNotFoundError{lookup: search}
	}

	if !autoUpdate {
		return nil, errors.New("cannot find installed provider for " + search.String())
	}

	nu, err := Install(upstream.Name, "")
	if err != nil {
		return nil, err
	}

	existing.Add(nu)
	PrintInstallResults([]*Provider{nu})

	// Check for and install any dependencies this provider requires
	err = installDependencies(nu, existing)
	if err != nil {
		return nil, err
	}

	return nu, nil
}

func Install(name string, version string) (*Provider, error) {
	ctx := context.Background()
	if version == "" {
		// if no version is specified, we default to installing the latest one
		latestVersion, err := registry.GetLatestVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		version = latestVersion
	}

	log.Info().
		Str("version", version).
		Msg("installing provider '" + name + "'")
	return installVersion(ctx, name, version)
}

func installVersion(ctx context.Context, name string, version string) (*Provider, error) {
	logCtx := log.With().Str("provider", name).Str("version", version).Logger()

	res, err := registry.DownloadProvider(ctx, name, version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	var tar []byte
	if tar, err = io.ReadAll(res); err != nil {
		logCtx.Debug().Msg("failed to read body of provider download")
		return nil, errors.Wrap(err, "failed to install "+name+"-"+version+", failed to read body")
	}

	reader := io.NopCloser(
		bytes.NewReader(tar),
	)

	installed, err := InstallIO(reader, InstallConf{
		Dst: DefaultPath,
	})
	if err != nil {
		logCtx.Debug().Msg("failed to install provider")
		return nil, errors.Wrap(err, "failed to install "+name+"-"+version)
	}

	if len(installed) == 0 {
		return nil, errors.New("couldn't find installed provider")
	}
	if len(installed) > 1 {
		logCtx.Warn().Msg("too many providers were installed")
	}
	if installed[0].Version != version {
		return nil, errors.New("version for provider didn't match expected install version: expected " + version + ", installed: " + installed[0].Version)
	}

	return installed[0], nil
}

// InstallSchemaOnly installs only a provider's config and resource schema,
// without downloading the provider binary. The result is enough to compile
// queries against the provider's resources. It is meant for workflows that
// never start the provider; connecting to an asset requires a full install.
func InstallSchemaOnly(name string, version string) (*Provider, error) {
	ctx := context.Background()
	if version == "" {
		// if no version is specified, we default to installing the latest one
		latestVersion, err := registry.GetLatestVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		version = latestVersion
	}

	log.Info().
		Str("version", version).
		Msg("installing schema for provider '" + name + "'")
	return installSchemaVersion(ctx, name, version, DefaultPath)
}

func installSchemaVersion(ctx context.Context, name string, version string, dst string) (*Provider, error) {
	confJSON, schemaJSON, err := registry.DownloadProviderMetadata(ctx, name, version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to install schema for "+name+"-"+version)
	}

	// Pack the two files into an in-memory tar.xz so the install goes
	// through the same path as a full provider archive.
	archive, err := buildTarXz(map[string][]byte{
		name + ".json":           confJSON,
		name + ".resources.json": schemaJSON,
	})
	if err != nil {
		return nil, err
	}

	installed, err := InstallIO(io.NopCloser(bytes.NewReader(archive)), InstallConf{Dst: dst})
	if err != nil {
		return nil, err
	}
	if len(installed) != 1 {
		return nil, errors.New("failed to install schema for provider " + name)
	}
	provider := installed[0]
	if provider.Version != version {
		return nil, errors.New("version for provider didn't match expected install version: expected " + version + ", installed: " + provider.Version)
	}
	return provider, nil
}

// buildTarXz packs the given files into an in-memory tar.xz archive.
func buildTarXz(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	xzWriter, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	tarWriter := tar.NewWriter(xzWriter)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data := files[name]
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(data)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := xzWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// installDependencies ensures all dependencies of a provider are installed
func installDependencies(provider *Provider, existing Providers) error {
	// Builtins have no file-backed schema; their Schema is set at init time
	// in builtinProviders and never mutated again, so reading it is safe.
	// File-backed providers (Path != "") load their schema lazily — call
	// LoadResources unconditionally so the (racy-without-it) Schema read
	// below is synchronized through Provider.schemaMu.
	if provider.Path != "" {
		if err := provider.LoadResources(); err != nil {
			log.Error().Err(err).Str("provider", provider.Name).Msg("failed to load provider schema, unable to look up dependencies")
			return nil
		}
	}
	if provider.Schema == nil {
		return nil
	}

	for _, dependency := range provider.Schema.AllDependencies() {
		// A builtin ships inside this executor; there is no separate binary to
		// download, and asking the installer for one would fail (or worse,
		// fetch something) for a provider that is already loaded. This is the
		// rule the schema generator used to approximate by excluding the name
		// "core", which also covers `mock` and `sbom` and anything built in
		// later.
		//
		// Checked here rather than against `existing`, because ListAll returns
		// early without builtins when no provider paths are configured -- the
		// embedder case -- and the guard has to hold there too.
		if _, isBuiltin := builtinProviders[dependency.Id]; isBuiltin {
			continue
		}

		dependencyLookup := ProviderLookup{
			ID:           dependency.Id,
			ProviderName: dependency.Name,
		}

		// Check if dependency is already installed
		depProvider := existing.Lookup(dependencyLookup)
		if depProvider != nil {
			continue // exist
		}

		upstreamDep := DefaultProviders.Lookup(dependencyLookup)
		if upstreamDep == nil {
			return &ProviderNotFoundError{lookup: dependencyLookup}
		}

		depProvider, err := Install(upstreamDep.Name, "")
		if err != nil {
			return err
		}

		existing.Add(depProvider)
		PrintInstallResults([]*Provider{depProvider})
	}

	return validateDeclaredPeers(provider, existing)
}

// validateDeclaredPeers checks each declared peer that is already installed
// against the floor the provider declares (ADR 042).
//
// Eager, at the point dependencies are ensured, rather than lazily when the
// first cross-call happens: a version mismatch is a property of the install,
// not of the query that happened to trip over it, and surfacing it mid-query
// makes it look like a query problem. Peers that are not installed are not
// reported here -- they fail later, when something actually needs them.
func validateDeclaredPeers(provider *Provider, existing Providers) error {
	if provider.Provider == nil {
		return nil
	}

	for _, dep := range provider.Requires {
		if dep.MinVersion == "" {
			continue
		}
		peer := existing.Lookup(ProviderLookup{ID: dep.ID, ProviderName: dep.Name})
		if peer == nil || peer.Provider == nil || peer.Version == "" {
			continue
		}
		diff, err := (semver.Parser{}).Compare(peer.Version, dep.MinVersion)
		if err != nil {
			// unparseable on either side is not evidence of a mismatch
			continue
		}
		if diff < 0 {
			return errors.Newf("provider %s requires %s >= %s, but %s is installed",
				provider.Name, dep.Name, dep.MinVersion, peer.Version)
		}
	}
	return nil
}

func PrintInstallResults(providers []*Provider) {
	for i := range providers {
		provider := providers[i]
		log.Info().
			Str("version", provider.Version).
			Str("path", provider.Path).
			Msg("successfully installed " + provider.Name + " provider")
	}
}

type InstallConf struct {
	// Dst specify which path to install into.
	Dst string
}

func InstallFile(path string, conf InstallConf) ([]*Provider, error) {
	if !config.ProbeFile(path) {
		return nil, errors.New("please provide a regular file when installing providers")
	}

	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return InstallIO(reader, conf)
}

// kept a tad bit higher to give I/O more time to complete
const osRetryDuration = 100 * time.Millisecond

// In the process of installing larger binaries, we will need time for
// antivirus software to scan it. This is currently set to retry for:
// 100ms (above) * 10 (=1sec) * 60 (=1min) * 3 (=3min)
const maxInstallBinaryRetries = 10 * 60 * 3

// The retries for config files (like JSON) are much shorter, since these
// files are considerably smaller:
// 100ms (above) * 10 (=1sec) * 20 (=20sec)
const maxInstallConfRetries = 10 * 20

// osRetry will try to re-run the given function as long as the resource is busy.
// This is helpful in e.g. Windows systems, which may get an antivirus tool
// check files while we create them (e.g. installing providers).
// It will look for common OS signals that the I/O is busy right now or that
// it asks the caller to run their call again later.
// It is retried every osRetryDuration.
// maxRetry has the maximum number of retries (or -1 for indefinite)
func osRetry(f func() error, maxRetry int) error {
	for maxRetry != 0 {
		err := f()
		if err == nil {
			return nil
		}

		if errno, ok := err.(syscall.Errno); ok && errno.Temporary() {
			time.Sleep(osRetryDuration)
		} else {
			return err
		}

		if maxRetry > 0 {
			maxRetry--
		}
	}
	return nil
}

func InstallIO(reader io.ReadCloser, conf InstallConf) ([]*Provider, error) {
	if conf.Dst == "" {
		conf.Dst = DefaultPath
	}

	if !config.ProbeDir(conf.Dst) {
		log.Debug().Str("path", conf.Dst).Msg("creating providers directory")
		if err := os.MkdirAll(conf.Dst, 0o755); err != nil {
			return nil, errors.New("failed to create " + conf.Dst)
		}
		if !config.ProbeDir(conf.Dst) {
			return nil, errors.New("cannot write to " + conf.Dst)
		}
	}

	log.Debug().Msg("create temp directory to unpack providers")
	tmpdir, err := os.MkdirTemp(conf.Dst, ".providers-unpack")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temporary directory to unpack files")
	}

	// Clean up the temporary directory when we're done, regardless of success or failure.
	defer func() {
		err := osRetry(func() error {
			return os.RemoveAll(tmpdir)
		}, maxInstallConfRetries)
		if err != nil {
			log.Error().Err(err).Msg("failed to remove temporary folder for unpacked provider")
		}
	}()

	log.Debug().Str("path", tmpdir).Msg("unpacking providers")
	files := map[string]struct{}{}
	err = walkTarXz(reader, func(reader *tar.Reader, header *tar.Header) error {
		name, err := archiveFileName(header.Name)
		if err != nil {
			return err
		}
		files[name] = struct{}{}
		dst := filepath.Join(tmpdir, name)
		log.Debug().Str("name", name).Str("dest", dst).Msg("unpacking file")
		writer, err := os.Create(dst)
		if err != nil {
			return err
		}

		if _, err = io.Copy(writer, reader); err != nil {
			writer.Close()
			return err
		}
		// Flush the file's data to disk before it gets renamed into the
		// providers directory. Without this, a crash between the rename and
		// the kernel writing back the page cache can leave the renamed file
		// pointing at unwritten (zeroed) blocks, which later panics schema
		// loading with "invalid character '\x00'". Sync also surfaces
		// writeback errors (e.g. ENOSPC) that Close() would silently drop.
		if err = writer.Sync(); err != nil {
			writer.Close()
			return err
		}
		return writer.Close()
	})
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("move provider to destination")
	providerDirs := []string{}
	for name := range files {
		// Providers are identified by their schema file: every package has
		// one, with or without a binary (schema-only installs have none).
		if !strings.HasSuffix(name, ".resources.json") {
			continue
		}
		providerName := strings.TrimSuffix(name, ".resources.json")

		if _, ok := files[providerName+".json"]; !ok {
			return nil, errors.New("cannot find " + providerName + ".json in the archive")
		}

		// NOTE: we need special handling for windows since binaries have the .exe extension
		binName := ""
		if _, ok := files[providerName]; ok {
			binName = providerName
		} else if _, ok := files[providerName+".exe"]; ok {
			binName = providerName + ".exe"
		}

		dstPath := filepath.Join(conf.Dst, providerName)
		if err = os.MkdirAll(dstPath, 0o755); err != nil {
			return nil, err
		}

		// move the binary (if any) and the associated files
		if binName != "" {
			srcBin := filepath.Join(tmpdir, binName)
			dstBin := filepath.Join(dstPath, binName)
			log.Debug().Str("src", srcBin).Str("dst", dstBin).Msg("move provider binary")
			if err = osRetry(func() error {
				return os.Rename(srcBin, dstBin)
			}, maxInstallBinaryRetries); err != nil {
				return nil, err
			}
			if err = os.Chmod(dstBin, 0o755); err != nil {
				return nil, err
			}
		}

		srcMeta := filepath.Join(tmpdir, providerName)
		dstMeta := filepath.Join(dstPath, providerName)
		if err = osRetry(func() error {
			return os.Rename(srcMeta+".json", dstMeta+".json")
		}, maxInstallConfRetries); err != nil {
			return nil, err
		}
		if err = osRetry(func() error {
			return os.Rename(srcMeta+".resources.json", dstMeta+".resources.json")
		}, maxInstallConfRetries); err != nil {
			return nil, err
		}

		// Flush the directory entries so the renames above are durable;
		// otherwise a crash can leave the provider half-installed.
		syncDir(dstPath)

		providerDirs = append(providerDirs, dstPath)
	}

	log.Debug().Msg("loading providers")
	res := []*Provider{}
	for i := range providerDirs {
		pdir := providerDirs[i]
		provider, err := readProviderDir(pdir)
		if err != nil {
			return nil, err
		}

		if provider == nil {
			log.Error().Err(err).Str("path", pdir).Msg("failed to read provider, please remove or fix it")
			continue
		}

		if err := provider.LoadJSON(); err != nil {
			log.Error().Err(err).Str("path", pdir).Msg("failed to read provider metadata, please remove or fix it")
			continue
		}

		if err := provider.LoadResources(); err != nil {
			log.Error().Err(err).Str("path", pdir).Msg("failed to read provider resources, please remove or fix it")
			continue
		}

		res = append(res, provider)
	}

	// we need to clear out the cache now, because we installed something new,
	// otherwise it will load old data
	CachedProviders = nil
	LastProviderInstall = time.Now().Unix()

	return res, nil
}

// syncDir flushes a directory's entries to disk so that renames into it
// survive a crash. It is best-effort: directory fsync is not supported on
// every platform (notably Windows), so failures are logged, not returned.
// Even when the directory sync is skipped, the per-file Sync in InstallIO
// still prevents the renamed file from pointing at zeroed blocks.
func syncDir(path string) {
	dir, err := os.Open(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("failed to open provider directory for sync")
		return
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("failed to sync provider directory")
	}
}

// archiveFileName returns the file name to unpack an archive entry to.
// Provider archives are flat: the binary, the config and the schema all sit
// at the top level, so every entry has to be a plain file name. Anything
// carrying a directory component would let the archive pick where its
// contents land, so it is rejected instead of unpacked.
func archiveFileName(name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	base := filepath.Base(clean)
	if clean != base || base == "." || base == ".." || base == string(filepath.Separator) {
		return "", errors.New("provider archive contains an unexpected file name: " + name)
	}
	return base, nil
}

func walkTarXz(reader io.Reader, callback func(reader *tar.Reader, header *tar.Header) error) error {
	r, err := xz.NewReader(reader)
	if err != nil {
		return errors.Wrap(err, "failed to read xz")
	}

	tarReader := tar.NewReader(r)
	for {
		header, err := tarReader.Next()
		// end of archive
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "failed to read tar")
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if err = callback(tarReader, header); err != nil {
				return err
			}

		default:
			log.Warn().Str("name", header.Name).Msg("encounter a file in archive that is not supported, skipping it")
		}
	}
	return nil
}

func isOverlyPermissive(path string) (bool, error) {
	stat, err := config.AppFs.Stat(path)
	if err != nil {
		return true, errors.New("failed to analyze " + path)
	}

	mode := stat.Mode()
	// We don't check the permissions for windows
	if runtime.GOOS != "windows" && mode&0o022 != 0 {
		return true, nil
	}

	return false, nil
}

func findProviders(path string) ([]*Provider, error) {
	overlyPermissive, err := isOverlyPermissive(path)
	if err != nil {
		return nil, err
	}
	if overlyPermissive {
		return nil, errors.New("path is overly permissive, make sure it is not writable to others or the group: " + path)
	}

	log.Debug().Str("path", path).Msg("searching providers in path")
	files, err := afero.ReadDir(config.AppFs, path)
	if err != nil {
		return nil, err
	}

	candidates := map[string]struct{}{}
	for i := range files {
		file := files[i]
		if file.Mode().IsDir() {
			candidates[file.Name()] = struct{}{}
		}
	}

	var res []*Provider
	for name := range candidates {
		pdir := filepath.Join(path, name)
		provider, err := readProviderDir(pdir)
		if err != nil {
			return nil, err
		}
		if provider != nil {
			res = append(res, provider)
		}
	}

	return res, nil
}

func readProviderDir(pdir string) (*Provider, error) {
	name := filepath.Base(pdir)
	bin := filepath.Join(pdir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	conf := filepath.Join(pdir, name+".json")
	resources := filepath.Join(pdir, name+".resources.json")

	if !config.ProbeFile(conf) {
		log.Debug().Str("path", conf).Msg("ignoring provider, can't access the plugin config")
		return nil, nil
	}
	if !config.ProbeFile(resources) {
		log.Debug().Str("path", resources).Msg("ignoring provider, can't access the plugin schema")
		return nil, nil
	}

	return &Provider{
		Provider: &plugin.Provider{
			Name: name,
		},
		// Schema is loaded lazily via (*coordinator).LoadSchema when a
		// provider is actually connected. We verified the resources file
		// exists above (ProbeFile); parsing every provider's schema (multiple
		// megabytes in total) up front is wasted work for the providers we
		// never touch.
		Schema:    nil,
		Path:      pdir,
		HasBinary: config.ProbeFile(bin),
	}, nil
}

func TryProviderUpdate(provider *Provider, update UpdateProvidersConfig) (*Provider, error) {
	ctx := context.Background()
	if provider.Path == "" {
		return nil, errors.New("cannot determine installation path for provider")
	}

	// A schema-only installation has no binary to run. Whatever its version,
	// complete it by installing the full package for that version. This check
	// comes before any freshness check: a provider whose schema is current is
	// still unusable without its binary.
	if !provider.HasBinary {
		log.Info().
			Str("version", provider.Version).
			Msg("provider '" + provider.Name + "' is installed schema-only, downloading its binary")
		completed, err := installVersion(ctx, provider.Name, provider.Version)
		if err != nil {
			return nil, err
		}
		PrintInstallResults([]*Provider{completed})

		if providers, err := ListActive(); err == nil {
			if err := installDependencies(completed, providers); err != nil {
				return nil, err
			}
		}
		return completed, nil
	}

	statPath := provider.confJSONPath()
	stat, err := os.Stat(statPath)
	if err != nil {
		return nil, err
	}

	if update.RefreshInterval > 0 {
		mtime := stat.ModTime()
		secs := time.Since(mtime).Seconds()
		if secs < float64(update.RefreshInterval) {
			lastRefresh := time.Since(mtime).String()
			log.Debug().
				Str("last-refresh", lastRefresh).
				Str("provider", provider.Name).
				Msg("no need to update provider")
			return provider, nil
		}
	}

	latest, err := registry.GetLatestVersion(ctx, provider.Name)
	if err != nil {
		log.Warn().Msg(err.Error())
		// we can just continue with the existing provider, no need to error up,
		// the warning is enough since we are still functional
		return provider, nil
	}

	semver := semver.Parser{}
	diff, err := semver.Compare(provider.Version, latest)
	if err != nil {
		return nil, err
	}
	if diff >= 0 {
		// Even if the provider doesn't need updating, we should check for any missing dependencies
		if providers, err := ListActive(); err == nil {
			err := installDependencies(provider, providers)
			if err != nil {
				return nil, err
			}
		}
		return provider, nil
	}

	log.Info().
		Str("installed", provider.Version).
		Str("latest", latest).
		Msg("found a new version for '" + provider.Name + "' provider")
	provider, err = installVersion(ctx, provider.Name, latest)
	if err != nil {
		return nil, err
	}
	PrintInstallResults([]*Provider{provider})
	now := time.Now()
	if err := os.Chtimes(statPath, now, now); err != nil {
		log.Warn().
			Str("provider", provider.Name).
			Msg("failed to update refresh time on provider")
	}

	// After updating the provider, also install any dependencies it requires
	if providers, err := ListActive(); err == nil {
		err := installDependencies(provider, providers)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}

func (p *Provider) LoadJSON() error {
	path := p.confJSONPath()
	res, err := afero.ReadFile(config.AppFs, path)
	if err != nil {
		return errors.New("failed to read provider json from " + path + ": " + err.Error())
	}

	if err := json.Unmarshal(res, &p.Provider); err != nil {
		return errors.New("failed to parse provider json from " + path + ": " + err.Error())
	}
	return nil
}

// LoadResources reads and parses the provider's resource schema from disk
// into p.Schema. Safe to call concurrently and idempotent: the first
// successful call populates Schema; subsequent calls return immediately.
// Callers that need to read Schema must call LoadResources first so the
// read synchronizes-after the write via schemaMu.
func (p *Provider) LoadResources() error {
	p.schemaMu.Lock()
	defer p.schemaMu.Unlock()
	if p.Schema != nil {
		return nil
	}

	path := filepath.Join(p.Path, p.Name+".resources.json")
	res, err := afero.ReadFile(config.AppFs, path)
	if err != nil {
		return errors.New("failed to read provider resources json from " + path + ": " + err.Error())
	}

	// Unmarshal into a concrete *resources.Schema rather than the
	// resources.ResourcesSchema interface field directly: json.Unmarshal
	// cannot target a nil interface. Previously this worked only because the
	// field was pre-populated with a concrete value before LoadResources ran.
	var schema resources.Schema
	if err := json.Unmarshal(res, &schema); err != nil {
		return errors.New("failed to parse provider resources json from " + path + ": " + err.Error())
	}
	// Stamp the reader-schema provenance (ADR 040 part 1). The installed
	// provider binary is the authority on its own version, so we take it from
	// the config rather than from the serialized schema, which predates this
	// field and will not carry it for a while yet.
	stampProviderVersion(&schema, p.ID, p.Version)
	stampProviderRoot(&schema, p.ID, p.Root)

	p.Schema = &schema
	return nil
}

// stampProviderVersion records which release of a provider produced a schema,
// keyed the same way ResourceInfo.Provider is keyed so the compiler can get
// from a resolved (or unresolved) name back to a version. It never clobbers an
// entry that is already there: a schema that carries its own provenance is
// more specific than what we can infer from the installed binary.
func stampProviderVersion(schema *resources.Schema, id string, version string) {
	if schema == nil || id == "" || version == "" {
		return
	}
	if schema.ProviderVersions == nil {
		schema.ProviderVersions = map[string]string{}
	}
	if _, ok := schema.ProviderVersions[id]; !ok {
		schema.ProviderVersions[id] = version
	}
}

// stampProviderRoot records the root a provider declares for its assets, keyed
// like ProviderVersions. It travels with the schema so a compile that has no
// runtime - a policy bundle, a lint, an editor - can still tell a resource that
// hangs off the asset's tree from one that does not. Same never-clobber rule:
// a schema that carries its own is more specific than the installed binary.
func stampProviderRoot(schema *resources.Schema, id string, root string) {
	if schema == nil || id == "" || root == "" {
		return
	}
	if schema.ProviderRoots == nil {
		schema.ProviderRoots = map[string]string{}
	}
	if _, ok := schema.ProviderRoots[id]; !ok {
		schema.ProviderRoots[id] = root
	}
}

func (p *Provider) confJSONPath() string {
	return filepath.Join(p.Path, p.Name+".json")
}

func (p *Provider) binPath() string {
	name := p.Name
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(p.Path, name)
}

func MustLoadSchema(name string, data []byte) *resources.Schema {
	var res resources.Schema
	if err := json.Unmarshal(data, &res); err != nil {
		panic("failed to embed schema for " + name + ": " + err.Error())
	}
	return &res
}

func MustLoadSchemaFromFile(name string, path string) *resources.Schema {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic("cannot read schema file: " + path + ": " + err.Error())
	}
	return MustLoadSchema(name, raw)
}

func LoadAssetUrlSchema() (*inventory.AssetUrlSchema, error) {
	providers, err := ListAll()
	if err != nil {
		return nil, err
	}

	s, err := inventory.NewAssetUrlSchema("technology")
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=saas"},
		Key:          "provider",
		Title:        "Provider",
	})
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=iac"},
		Key:          "category",
		Title:        "Category",
	})
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=network"},
		Key:          "category",
		Title:        "Category",
	})
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=directory-service"},
		Key:          "provider",
		Title:        "Provider",
	})
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=virtualization"},
		Key:          "provider",
		Title:        "Provider",
	})
	if err != nil {
		return nil, err
	}

	err = s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=ai"},
		Key:          "provider",
		Title:        "Provider",
	})
	if err != nil {
		return nil, err
	}

	for _, provider := range providers {
		for _, b := range provider.AssetUrlTrees {
			if err := s.Add(b); err != nil {
				return nil, err
			}
		}
	}

	if err := s.RefreshCache(); err != nil {
		return nil, err
	}

	return s, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
	"go.mondoo.com/mql/utils/stringx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultShutdownTimeout = time.Duration(time.Second * 120)

// Can be used to infer that detecting a provider has failed because there were no available connection options.
var ErrNoConnections = errors.New("asset has no connections, can't detect provider")

// Runtimes are associated with one asset and carry all providers
// and open connections for that asset.
type Runtime struct {
	Provider       *ConnectedProvider
	UpstreamConfig *upstream.UpstreamConfig
	AutoUpdate     UpdateProvidersConfig

	recording llx.Recording
	features  []byte
	// coordinator is used to grab providers
	coordinator ProvidersCoordinator
	// providers for with open connections
	providers map[string]*ConnectedProvider
	isClosed  bool
	close     sync.Once
	// translations is the downgrade catalog, built on first use so a compile
	// that needs no fallbacks never starts a provider to ask.
	translations     llx.TranslationSource
	translationsOnce sync.Once
	shutdownTimeout  time.Duration

	// criticalErrors collects serious errors (e.g. recovered provider panics)
	// that should be reported to an error tracker even though execution continues.
	criticalErrors []error

	// resolvedAssets caches the runtime opened for each asset anchor this
	// runtime resolved into, and subRuntimes owns them so they are torn down
	// with this runtime rather than left for the coordinator. resolveChain is
	// the path of anchors that led here, which is what bounds a cycle across
	// runtimes. See asset_resolver.go and ADR 031.
	resolvedAssets map[string]*Runtime
	subRuntimes    []*Runtime
	resolveChain   []string

	// used to lock unsafe tasks
	mu sync.Mutex
}

type ConnectedProvider struct {
	Instance        *RunningProvider
	Connection      *plugin.ConnectRes
	ConnectionError error
}

func (c *coordinator) RuntimeWithShutdownTimeout(timeout time.Duration) *Runtime {
	runtime := c.NewRuntime()
	runtime.shutdownTimeout = timeout
	return runtime
}

type shutdownResult struct {
	Response *plugin.ShutdownRes
	Error    error
}

func (r *Runtime) tryShutdown() shutdownResult {
	for _, provider := range r.providers {
		if provider.Connection == nil {
			continue
		}
		_, err := provider.Instance.Plugin.Disconnect(&plugin.DisconnectReq{Connection: provider.Connection.Id})
		if err != nil {
			if status, ok := status.FromError(err); ok {
				if status.Code() == 12 {
					log.Warn().Msg("please update the provider plugin for " + provider.Instance.Name)
					continue
				}
			}
			log.Error().Err(err).Msg("failed to disconnect from provider " + provider.Instance.Name)
		}
	}
	return shutdownResult{}
}

func (r *Runtime) Close() {
	r.isClosed = true
	r.close.Do(func() {
		// Runtimes opened for other assets are owned by this one (ADR 031).
		r.closeSubRuntimes()

		if err := r.Recording().Save(); err != nil {
			log.Error().Err(err).Msg("failed to save recording")
		}

		response := make(chan shutdownResult, 1)
		go func() {
			response <- r.tryShutdown()
		}()
		select {
		case <-time.After(r.shutdownTimeout):
			log.Error().Str("provider", r.Provider.Instance.Name).Msg("timed out shutting down the provider")
		case result := <-response:
			if result.Error != nil {
				log.Error().Err(result.Error).Msg("failed to shutdown the provider")
			}
		}
		r.coordinator.RemoveRuntime(r)
	})
}

// CriticalErrors returns serious errors (e.g. recovered provider panics) that
// occurred during execution. These errors were handled gracefully (execution
// continued), but they should still be reported to an error tracker like Sentry.
func (r *Runtime) CriticalErrors() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]error, len(r.criticalErrors))
	copy(out, r.criticalErrors)
	return out
}

func (r *Runtime) addCriticalError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	const maxCriticalErrors = 100
	if len(r.criticalErrors) < maxCriticalErrors {
		r.criticalErrors = append(r.criticalErrors, err)
	}
}

func (r *Runtime) Recording() llx.Recording {
	return r.recording
}

func (r *Runtime) AssetMRN() string {
	if r.Provider != nil && r.Provider.Connection != nil && r.Provider.Connection.Asset != nil {
		return r.Provider.Connection.Asset.Mrn
	}
	return ""
}

// UseProvider sets the main provider for this runtime.
func (r *Runtime) UseProvider(id string) error {
	res, err := r.addProvider(id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.Provider = res
	r.mu.Unlock()
	return nil
}

// UseBuiltinProvider sets a builtin (in-process) provider as the runtime's
// main provider and connects it, so its resources resolve without spawning a
// subprocess and without any real connection. Unlike a bare UseProvider +
// plugin.Connect, the connection is backed by the runtime's callbacks, so the
// provider can create or resolve resources through the runtime — matching how
// Connect wires every other provider. Used for the core provider when running
// MQL as a pure expression engine.
func (r *Runtime) UseBuiltinProvider(id string, features []byte) error {
	if err := r.UseProvider(id); err != nil {
		return err
	}
	r.features = features

	callbacks := &providerCallbacks{runtime: r}
	conn, err := r.Provider.Instance.Plugin.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{{Type: "in-process"}},
		},
		Features: features,
	}, callbacks)
	if err != nil {
		return errors.New("failed to connect builtin provider '" + id + "': " + err.Error())
	}

	r.Provider.Connection = conn
	r.AddConnectedProvider(r.Provider)
	return nil
}

func (r *Runtime) AddConnectedProvider(c *ConnectedProvider) {
	r.mu.Lock()
	r.providers[c.Instance.ID] = c
	r.mu.Unlock()
}

// UseInProcessProvider registers a caller-supplied, in-process provider plugin
// with this runtime and connects it, so its resources can be created and their
// fields resolved on demand without spawning a provider subprocess. The
// connection is backed by the runtime's callbacks, so a custom resource's
// field resolvers may reference other resources just like any built-in
// provider.
//
// The provider's schema is what queries compile against; register it with the
// coordinator (e.g. via the ExtensibleSchema interface) before compiling. The
// config ID must match the provider ID recorded on that schema's resources.
func (r *Runtime) UseInProcessProvider(config plugin.Provider, schema resources.ResourcesSchema, plug plugin.ProviderPlugin, features []byte) error {
	if plug == nil {
		return errors.New("cannot register in-process provider '" + config.Name + "': no plugin provided")
	}

	if r.features == nil {
		r.features = features
	}

	running := &RunningProvider{
		Name:     config.Name,
		ID:       config.ID,
		Version:  config.Version,
		Plugin:   plug,
		Schema:   schema,
		Requires: config.Requires,
		Root:     config.Root,
	}
	connected := &ConnectedProvider{Instance: running}

	callbacks := &providerCallbacks{runtime: r}
	conn, err := plug.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{{Type: config.Name}},
		},
		Features: features,
	}, callbacks)
	if err != nil {
		return errors.New("failed to connect in-process provider '" + config.Name + "': " + err.Error())
	}

	connected.Connection = conn
	r.AddConnectedProvider(connected)
	return nil
}

// ConnectedProviderIDs returns the IDs of all connected providers
func (r *Runtime) ConnectedProviderIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	return ids
}

func (r *Runtime) setProviderConnection(c *plugin.ConnectRes, err error) {
	r.mu.Lock()
	r.Provider.Connection = c
	r.Provider.ConnectionError = err
	r.mu.Unlock()
}

// crossProviderAsset returns a clone of the main provider's asset with
// ParentConnectionId cleared. Parent-child resource cache sharing only
// applies within the same provider; passing the original parent ID to an
// unrelated provider triggers a spurious "parent connection not found"
// warning because that provider never had the parent's runtime.
func (r *Runtime) crossProviderAsset() *inventory.Asset {
	asset := r.Provider.Connection.Asset.CloneVT()
	if len(asset.Connections) > 0 {
		asset.Connections[0].ParentConnectionId = 0
	}
	return asset
}

func (r *Runtime) addProvider(id string) (*ConnectedProvider, error) {
	// TODO: we need to detect only the shared running providers
	running, err := r.coordinator.GetRunningProvider(id, r.AutoUpdate)
	if err != nil {
		return nil, err
	}

	res := &ConnectedProvider{Instance: running}
	r.AddConnectedProvider(res)

	return res, nil
}

// addRecordedProvider is addProvider for a provider that is being mock-connected
// from a recording.
//
// It reuses a running instance this runtime already carries instead of asking
// the coordinator to start one. A runtime created for another asset inherits its
// parent's providers (NewRuntimeFrom), so the instance is usually right there -
// and it is the only one available when the providers were registered directly
// on a runtime rather than through the coordinator, which is what an in-process
// host does.
//
// The ConnectedProvider is always fresh: the inherited one holds the *parent's*
// connection, and those structs are shared by pointer, so mock-connecting into
// it would replace the connection the parent is still using.
func (r *Runtime) addRecordedProvider(id string) (*ConnectedProvider, error) {
	r.mu.Lock()
	existing := r.providers[id]
	r.mu.Unlock()

	if existing == nil || existing.Instance == nil {
		return r.addProvider(id)
	}

	res := &ConnectedProvider{Instance: existing.Instance}
	r.AddConnectedProvider(res)
	return res, nil
}

// DetectProvider will try to detect and start the right provider for this
// runtime. Generally recommended when you receive an asset to be scanned,
// but haven't initialized any provider. It will also try to install providers
// if necessary (and enabled)
func (r *Runtime) DetectProvider(asset *inventory.Asset) error {
	provider, err := r.providerForAsset(asset)
	if err != nil {
		return err
	}
	return r.UseProvider(provider.ID)
}

func (r *Runtime) providerForAsset(asset *inventory.Asset) (*Provider, error) {
	if asset == nil {
		return nil, errors.New("please provide an asset to detect the provider")
	}
	if len(asset.Connections) == 0 {
		return nil, ErrNoConnections
	}

	var errs multierr.Errors
	for i := range asset.Connections {
		conn := asset.Connections[i]
		if conn.Type == "" {
			errs.Add(errors.New("no connection `type` provided in inventory"))
			continue
		}

		provider, err := EnsureProvider(ProviderLookup{ConnType: conn.Type}, r.AutoUpdate.Enabled, r.coordinator.Providers())
		if err != nil {
			errs.Add(err)
			continue
		}

		return provider, nil
	}

	return nil, multierr.Wrap(errs.Deduplicate(), "cannot find provider for this asset")
}

func (r *Runtime) EnsureProvidersConnected() error {
	if r.Provider == nil {
		return errors.New("cannot reconnect, no provider set")
	}

	if r.Provider.Connection == nil {
		return errors.New("cannot reconnect, no connection set")
	}

	err := r.Provider.Instance.Reconnect()
	if err != nil {
		return err
	}

	for _, p := range r.providers {
		if err := p.Instance.Reconnect(); err != nil {
			return err
		}
	}

	return nil
}

// Connect to an asset using the main provider
func (r *Runtime) Connect(req *plugin.ConnectReq) error {
	if r.Provider == nil {
		return errors.New("cannot connect, please select a provider first")
	}

	if req.Asset == nil {
		return errors.New("cannot connect, no asset info provided")
	}

	asset := req.Asset
	if len(asset.Connections) == 0 {
		return errors.New("cannot connect to asset, no connection info provided")
	}

	// If there is no connection ID set, we need to assign one from the coordinator
	if asset.Connections[0].Id == 0 {
		asset.Connections[0].Id = Coordinator.NextConnectionId()
	}

	r.features = req.Features
	callbacks := providerCallbacks{
		runtime: r,
	}

	// TODO: we probably want to check here if the provider is dead and restart it
	// if r.Provider.Instance.isCloseOrShutdown() {

	// }

	conn, err := r.Provider.Instance.Plugin.Connect(req, &callbacks)
	r.setProviderConnection(conn, err)
	if err != nil {
		return err
	}

	// TODO: This is a stopgap that detects if the connect call returned an asset
	// that is different from the provider we used for connecting. We will keep
	// supporting this approach throughout v9 but plan to change it in the future,
	// so that the connect call sticks to connecting only and instead introduce
	// a separate discover call to handle this behavior.
	//
	// This stopgap makes sure that if the connection indicates a different provider,
	// it is the intention of the provider author to switch the asset to said provider.
	//
	// Additionally, we do not loop this connect+recheck approach indefinitely.
	// We only run it once and only accept one asset switch. This will be
	// changed once we have an explicit discover call in plugins.
	postProvider, err := r.providerForAsset(r.Provider.Connection.Asset)
	if err != nil {
		return err
	}
	if postProvider.ID != r.Provider.Instance.ID {
		req.Asset = r.crossProviderAsset()
		err = r.UseProvider(postProvider.ID)
		if err != nil {
			return err
		}

		conn, err := r.Provider.Instance.Plugin.Connect(req, &callbacks)
		r.setProviderConnection(conn, err)
		if err != nil {
			return err
		}
	}

	if !r.Provider.Connection.Asset.Connections[0].DelayDiscovery {
		r.Recording().EnsureAsset(r.Provider.Connection.Asset, r.Provider.Instance.ID, r.Provider.Connection.Id, asset.Connections[0])
	}
	// r.schema.prioritizeIDs(BuiltinCoreID, r.Provider.Instance.ID)
	return nil
}

func (r *Runtime) AssetUpdated(asset *inventory.Asset) {
	// Discovery hands each asset out as an independent clone of the connection asset
	// (see discovery.CreateAssetWithRuntime), so metadata a caller adds to that clone
	// after connecting is invisible to the providers: every provider connect derives
	// its asset from r.Provider.Connection.Asset (crossProviderAsset), and the core
	// provider snapshots that into the `asset` resource once, at Connect. Copy the two
	// fields the `asset` resource exposes back onto the connection asset so a later
	// provider start observes them.
	//
	// This is what makes upstream-synced annotations reach MQL. cnspec merges the
	// annotations returned by SynchronizeAssets onto the scanned asset and calls this
	// method; without the copy, asset.annotations keeps only the locally supplied set
	// and any policy or risk factor keyed on a server-side annotation never matches.
	syncAssetMetadata(r.Provider, asset)

	rec := r.Recording()
	rec.EnsureAsset(
		asset,
		r.Provider.Instance.ID,
		r.Provider.Connection.Id,
		asset.Connections[0])
}

// syncAssetMetadata copies the mutable metadata of an updated asset onto the
// provider's connection asset. Only labels and annotations are copied: they are the
// fields CreateAssetResourceArgs reads that a caller may legitimately change after
// connecting, whereas platform data and connections describe how the connection was
// established and must not be rewritten underneath it.
//
// This works by getting ahead of the provider start rather than by refreshing an
// already-built resource, which is deliberate: the generated CreateResource discards a
// newly built resource when one is already cached under the same id
// (`if x, ok := runtime.Resources.Get(id); ok { return x, nil }`), so re-creating
// `asset` returns the stale instance. Providers are started lazily on first use of one
// of their resources and the connection is then cached, and no MQL runs before the
// caller that updates the asset, so the copy lands before the snapshot is taken. If
// that ever stops holding, the fix is to make resource creation replace a cached
// instance, not to call CreateResource again here.
func syncAssetMetadata(provider *ConnectedProvider, asset *inventory.Asset) {
	if provider == nil || provider.Connection == nil || asset == nil {
		return
	}
	connAsset := provider.Connection.Asset
	if connAsset == nil || connAsset == asset {
		return
	}
	if asset.Labels != nil {
		connAsset.Labels = asset.Labels
	}
	if asset.Annotations != nil {
		connAsset.Annotations = asset.Annotations
	}
}

func (r *Runtime) CreateResource(name string, args map[string]*llx.Primitive) (llx.Resource, error) {
	provider, info, err := r.lookupResourceProvider(name)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, errors.New("cannot create '" + name + "', no resource info found")
	}
	name = info.Id

	// Resources without providers are bridging resources only. They are static in nature.
	if provider == nil {
		return &llx.MockResource{Name: name}, nil
	}

	if provider.Connection == nil {
		return nil, errors.New("no connection to provider")
	}

	req := &plugin.DataReq{
		Connection: provider.Connection.Id,
		Resource:   name,
		Args:       args,
	}
	res, err := provider.Instance.Plugin.GetData(req)
	if err != nil {
		return nil, err
	}

	if _, ok := r.Recording().GetResource(llx.AssetRecordingLookup{ConnectionId: provider.Connection.Id}, name, string(res.Data.Value)); !ok {
		addDataReq := llx.AddDataReq{
			ConnectionID:      provider.Connection.Id,
			Resource:          name,
			ResourceID:        string(res.Data.Value),
			RequestResourceId: req.ResourceId,
			Args:              args,
			Data:              nil,
			Field:             "",
		}
		r.Recording().AddData(addDataReq)
	}

	typ := types.Type(res.Data.Type)
	return &llx.MockResource{Name: typ.ResourceName(), ID: string(res.Data.Value)}, nil
}

func PrimitiveArgsToResultArgs(args map[string]*llx.Primitive) map[string]*llx.Result {
	res := make(map[string]*llx.Result, len(args))
	for k, v := range args {
		res[k] = &llx.Result{Data: v}
	}
	return res
}

func (r *Runtime) CloneResource(src llx.Resource, id string, fields []string, args map[string]*llx.Primitive) (llx.Resource, error) {
	name := src.MqlName()
	srcID := src.MqlID()

	provider, _, err := r.lookupResourceProvider(name)
	if err != nil {
		return nil, err
	}

	for i := range fields {
		field := fields[i]
		data, err := provider.Instance.Plugin.GetData(&plugin.DataReq{
			Connection: provider.Connection.Id,
			Resource:   name,
			ResourceId: srcID,
			Field:      field,
		})
		if err != nil {
			return nil, err
		}
		args[field] = data.Data
	}

	args["__id"] = llx.StringPrimitive(id)

	_, err = provider.Instance.Plugin.StoreData(&plugin.StoreReq{
		Connection: provider.Connection.Id,
		Resources: []*plugin.ResourceData{{
			Name:   name,
			Id:     id,
			Fields: PrimitiveArgsToResultArgs(args),
		}},
	})
	if err != nil {
		return nil, err
	}

	return &llx.MockResource{Name: name, ID: id}, nil
}

func (r *Runtime) Unregister(watcherUID string) error {
	// TODO: we don't unregister just yet...
	return nil
}

// WatchAndUpdate a resource field and call the function if it changes with its current value
func (r *Runtime) WatchAndUpdate(resource llx.Resource, field string, watcherUID string, callback func(res any, err error)) error {
	raw, err := r.watchAndUpdate(resource.MqlName(), resource.MqlID(), field, watcherUID)
	if raw != nil {
		callback(raw.Value, raw.Error)
	}
	return err
}

func (r *Runtime) watchAndUpdate(resource string, resourceID string, field string, watcherUID string) (*llx.RawData, error) {
	provider, info, fieldInfo, err := r.lookupFieldProvider(resource, field)
	if err != nil {
		return nil, err
	}
	if fieldInfo == nil {
		return nil, errors.New("cannot get field '" + field + "' for resource '" + resource + "'")
	}

	if info.Provider != fieldInfo.Provider {
		// technically we don't need to look up the resource provider, since
		// it had to have been called beforehand to get here
		_, err := provider.Instance.Plugin.StoreData(&plugin.StoreReq{
			Connection: provider.Connection.Id,
			Resources: []*plugin.ResourceData{{
				Name: resource,
				Id:   resourceID,
			}},
		})
		if err != nil {
			return nil, multierr.Wrap(err, "failed to create reference resource "+resource+" in provider "+provider.Instance.Name)
		}
	}

	if cached, ok := r.Recording().GetData(llx.AssetRecordingLookup{ConnectionId: provider.Connection.Id}, resource, resourceID, field); ok {
		return cached, nil
	}

	req := &plugin.DataReq{
		Connection: provider.Connection.Id,
		Resource:   resource,
		ResourceId: resourceID,
		Field:      field,
	}
	data, err := provider.Instance.Plugin.GetData(req)
	if err != nil {
		// Recoverable errors can continue with the execution,
		// they only store errors in the place of actual data.
		// Every other error is thrown up the chain.
		handled, err := r.handlePluginError(err, provider, resource, field)
		if !handled {
			return nil, err
		}
		data = &plugin.DataRes{Error: err.Error()}
	}

	var raw *llx.RawData
	if data.Error != "" {
		raw = &llx.RawData{Error: errors.New(data.Error)}
	} else {
		if data.Data == nil {
			// The provider answered with neither data nor an error. This
			// happens when the requested field's TValue was never set on the
			// resource (e.g. a resource created from partial init args, or an
			// accessor returning nil without marking the field null) —
			// TValue.ToDataRes encodes an unset field as an empty DataRes.
			// Log-only: the conversion below still receives the nil primitive
			// and coerces it to null exactly as before; this line just adds
			// the provider/resource/field attribution that the anonymous
			// "primitive with no type information" error lacks.
			log.Error().
				Str("provider", provider.Instance.Name).
				Str("resource", resource).
				Str("id", resourceID).
				Str("field", field).
				Msg("provider returned no data and no error for a field; the field was never set on the resource (provider bug)")
		}
		raw = data.Data.RawData()
	}

	addDataReq := llx.AddDataReq{
		ConnectionID:      provider.Connection.Id,
		Resource:          resource,
		ResourceID:        resourceID,
		RequestResourceId: req.ResourceId,
		Data:              raw,
		Field:             field,
	}
	r.Recording().AddData(addDataReq)
	return raw, nil
}

func (r *Runtime) handlePluginError(err error, provider *ConnectedProvider, resource string, field string) (bool, error) {
	// Build a context suffix so reported errors include which resource/field
	// was being accessed when the failure occurred.
	var ctx string
	if resource != "" {
		ctx = " (resource=" + resource
		if field != "" {
			ctx += ", field=" + field
		}
		ctx += ")"
	}

	st, ok := status.FromError(err)
	if !ok {
		// Transport-level errors (e.g. "dial tcp" connection failures) don't
		// carry a gRPC status code. Record them as critical so they reach
		// error reporting (Sentry) via runtime.CriticalErrors().
		base := "the '" + provider.Instance.Name + "' provider connection failed" + ctx + ": " + err.Error()
		transportErr := errors.New(base + buildCrashDiagnostics(provider.Instance))
		r.addCriticalError(transportErr)
		return false, transportErr
	}

	switch st.Code() {
	case codes.Internal:
		// A recovered panic in the provider sends an Internal error prefixed
		// with "panic in provider ". Only apply panic-specific handling when
		// this prefix is present; other Internal errors fall through.
		if strings.HasPrefix(st.Message(), "panic in provider ") {
			log.Error().Str("provider", provider.Instance.Name).Msg(st.Message())
			panicErr := errors.New("the '" + provider.Instance.Name + "' provider panicked" + ctx + ": " + st.Message())
			r.addCriticalError(panicErr)
			return true, panicErr
		}

	case codes.Unavailable:
		// Happens when the plugin crashes or the gRPC connection drops.
		// TODO: try to restart the plugin and reset its connections
		provider.Instance.isClosed = true
		base := "the '" + provider.Instance.Name + "' provider crashed" + ctx + ": " + err.Error()
		provider.Instance.err = errors.New(base + buildCrashDiagnostics(provider.Instance))
		r.addCriticalError(provider.Instance.err)
		return false, provider.Instance.err
	}
	return false, err
}

// buildCrashDiagnostics returns a multi-line suffix to append to a crash error
// with whatever extra context we have about the dead/dying provider:
// version, uptime, whether the subprocess actually exited (and if so, its
// exit code or killing signal plus peak RSS), whether the shutdown was
// triggered by a heartbeat probe, and the most recent stderr (panic/fatal
// trace if one was captured).
//
// Returns "" when there's nothing useful to report, so the message stays
// compact for cases where the optional context is unavailable (mostly tests
// and builtin providers).
func buildCrashDiagnostics(p *RunningProvider) string {
	if p == nil {
		return ""
	}

	var meta []string
	if v := strings.TrimSpace(p.Version); v != "" {
		meta = append(meta, "version="+v)
	}
	if up := p.uptime(); up > 0 {
		meta = append(meta, "uptime="+up.Round(time.Millisecond).String())
	}
	if exited, ps := p.awaitExit(2 * time.Second); exited {
		meta = append(meta, "subprocess=exited")
		// Exit disposition separates the silent-death causes: a SIGKILL with
		// empty stderr and no trigger= flag is near-certainly the OOM
		// killer, a regular exit code points at the plugin terminating
		// itself. Peak RSS (bytes) corroborates the OOM classification
		// without host access.
		meta = append(meta, "exit="+formatExitStatus(ps))
		if rss := maxRSSBytes(ps); rss > 0 {
			meta = append(meta, "max_rss="+strconv.FormatInt(rss, 10))
		}
	} else if p.startedAt.IsZero() {
		// builtin/in-process — no subprocess to report on
	} else {
		meta = append(meta, "subprocess=running")
	}
	if p.hadHeartbeatFailure() {
		meta = append(meta, "trigger=heartbeat-timeout")
	} else if p.wasKilledLocally() {
		// We sent the kill signal ourselves (shutdown race) — without this
		// flag, our own SIGKILL would wear the OOM killer's fingerprint.
		meta = append(meta, "trigger=local-kill")
	}

	var sb strings.Builder
	if len(meta) > 0 {
		sb.WriteString("\n[")
		sb.WriteString(strings.Join(meta, " "))
		sb.WriteString("]")
	}

	// Prefer a panic/fatal tail when one was captured — it points at the line
	// of provider code that died. Fall back to a tail of recent stderr for
	// OS-level kills (OOM, SIGKILL) that exit before writing anything
	// panic-shaped: the lines just before death can still hint at the
	// resource being processed when it happened.
	if tail := p.crashTail(); len(tail) > 0 {
		// Cap to keep error messages bounded — a panic with hundreds of
		// blocked goroutines could otherwise produce a multi-MB string and
		// bloat Sentry events. Take from the start: Go runtime fatals print
		// the panicking goroutine first, so the most actionable frames are
		// at the beginning. The other goroutines' stacks rarely add value
		// beyond the panicking one's.
		const maxTail = 80
		truncated := false
		if len(tail) > maxTail {
			tail = tail[:maxTail]
			truncated = true
		}
		sb.WriteString("\nplugin stderr (panic/fatal trace):\n")
		sb.WriteString(strings.Join(tail, "\n"))
		if truncated {
			sb.WriteString("\n... (trace truncated)")
		}
	} else if snap := p.stderrSnapshot(); len(snap) > 0 {
		const maxFallback = 30
		if len(snap) > maxFallback {
			snap = snap[len(snap)-maxFallback:]
		}
		sb.WriteString("\nplugin stderr (last ")
		sb.WriteString(strconv.Itoa(len(snap)))
		sb.WriteString(" lines):\n")
		sb.WriteString(strings.Join(snap, "\n"))
	}

	return sb.String()
}

type providerCallbacks struct {
	recording *recording.Asset
	runtime   *Runtime
}

// runtimeFromCallback recovers the runtime a builtin provider service is
// connecting on behalf of.
//
// The builtin services (mock, sbom) are single instances shared by every
// runtime in the process, so they cannot keep the runtime in a field: whoever
// connected last would overwrite it, and a concurrent connect would then read
// another runtime's providers and recording. The callback the connect is handed
// already belongs to exactly one runtime, which makes it the right place to
// take it from.
//
// A nil or foreign callback means the caller has no in-process runtime to offer,
// which these services cannot work without - so it is an error rather than a
// dereference.
func runtimeFromCallback(callback plugin.ProviderCallback) (*Runtime, error) {
	cb, ok := callback.(*providerCallbacks)
	if !ok || cb == nil || cb.runtime == nil {
		return nil, errors.New("cannot connect: this provider needs an in-process runtime, and the connect call supplied none")
	}
	return cb.runtime, nil
}

func (p *providerCallbacks) GetRecording(req *plugin.DataReq) (*plugin.ResourceData, error) {
	fields, ok := p.recordedFields(req)
	if !ok {
		return nil, nil
	}

	res := plugin.ResourceData{
		Name:   req.Resource,
		Id:     req.ResourceId,
		Fields: make(map[string]*llx.Result, len(fields)),
	}
	for k, v := range fields {
		res.Fields[k] = v.Result()
	}

	return &res, nil
}

// recordedFields reads a recorded resource for a callback.
//
// Callbacks built for one asset carry that asset's recording directly. The ones
// Runtime.Connect builds do not - they are made for a live connection, which
// has no recording to carry - so they resolve through the runtime's own
// recording, keyed by the connection the request came in on. That is the path a
// recorded asset connected for cross-asset resolution takes (ADR 031), and
// dereferencing the nil is what it used to do instead.
func (p *providerCallbacks) recordedFields(req *plugin.DataReq) (map[string]*llx.RawData, bool) {
	if p.recording != nil {
		resource, ok := p.recording.GetResource(req.Resource, req.ResourceId)
		if !ok {
			return nil, false
		}
		return resource.Fields, true
	}
	if p.runtime == nil || p.runtime.Recording() == nil {
		return nil, false
	}
	return p.runtime.Recording().GetResource(
		llx.AssetRecordingLookup{ConnectionId: req.Connection}, req.Resource, req.ResourceId)
}

func (p *providerCallbacks) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	if req.Field == "" {
		res, err := p.runtime.CreateResource(req.Resource, req.Args)
		if err != nil {
			return nil, err
		}

		return &plugin.DataRes{
			Data: &llx.Primitive{
				Type:  string(types.Resource(res.MqlName())),
				Value: []byte(res.MqlID()),
			},
		}, nil
	}

	raw, err := p.runtime.watchAndUpdate(req.Resource, req.ResourceId, req.Field, "")
	if raw == nil {
		return nil, err
	}
	res := raw.Result()
	return &plugin.DataRes{
		Data:  res.Data,
		Error: res.Error,
	}, err
}

func (p *providerCallbacks) Collect(req *plugin.DataRes) error {
	panic("NOT YET IMPLEMENTED")
	return nil
}

func (r *Runtime) EnableResourcesRecording() error {
	if _, ok := r.recording.(recording.Null); !ok {
		return nil
	}

	recording, err := recording.NewWithFile("", recording.RecordingOptions{
		DoRecord:        true,
		PrettyPrintJSON: false,
		DoNotSave:       true,
	})
	if err != nil {
		return err
	}

	return r.SetRecording(recording)
}

// EnsureResourcesRecording makes this runtime record resource data for
// asset, regardless of when it is called relative to the runtime's
// connection. It mounts an in-memory recording if none is mounted (the same
// Null-only swap as EnableResourcesRecording, so a recording the caller
// mounted — e.g. via --record — is never clobbered) and registers asset
// with the mounted recording.
//
// The registration is what makes late enabling work, and it encodes three
// invariants of the recording machinery that callers should not have to
// know: assets are normally registered at CONNECT time (a recording mounted
// afterwards knows no connections), AddData silently drops rows for
// connections the recording does not know, and readers look assets up by
// the identity on the registered asset — so asset should be the one
// carrying the identity readers will use (e.g. the platform-assigned MRN),
// with the connection config whose Id writes are keyed under. An asset with
// no connections mounts the recording and skips registration: the runtime
// has not connected yet, and connect-time registration will cover it.
func (r *Runtime) EnsureResourcesRecording(asset *inventory.Asset) error {
	if err := r.EnableResourcesRecording(); err != nil {
		return err
	}
	if asset == nil || len(asset.Connections) == 0 {
		return nil
	}

	providerID := ""
	var connectionID uint32
	if r.Provider != nil && r.Provider.Instance != nil {
		providerID = r.Provider.Instance.ID
	}
	if r.Provider != nil && r.Provider.Connection != nil {
		connectionID = r.Provider.Connection.Id
	}

	// Register under the config of the runtime's ACTIVE connection when the
	// asset carries several: the recording indexes writes by conf.Id, and
	// AddData silently drops rows for connection ids it does not know — so
	// registering a non-active connection's config would reproduce exactly
	// the silent-drop failure this method exists to prevent. Fall back to
	// the first connection when none matches (or the runtime has not
	// connected yet, where connect-time registration covers the rest).
	conf := asset.Connections[0]
	if connectionID > 0 {
		for _, c := range asset.Connections {
			if c != nil && c.Id == connectionID {
				conf = c
				break
			}
		}
	}
	if conf != nil {
		// A nil connection config cannot be registered (EnsureAsset derefs
		// it); in that case the recording stays mounted and connect-time
		// registration covers the asset once a real connection exists.
		r.recording.EnsureAsset(asset, providerID, connectionID, conf)
	}
	return nil
}

func (r *Runtime) SetRecording(recording llx.Recording) error {
	r.recording = recording
	if r.Provider == nil || r.Provider.Instance == nil {
		log.Warn().Msg("set recording while no provider is set on runtime")
	}
	// The builtin mock and sbom services used to be handed this runtime here,
	// to be read back when they connect. They take it from the connect
	// callback instead: one service instance is shared by every runtime, so a
	// field on it is whichever runtime set a recording most recently, not the
	// one connecting. See runtimeFromCallback.
	return nil
}

// SetMockRecording is only used for test utilities. Please do not use it!
//
// Deprecated: This function may not be necessary anymore, consider removing.
func (r *Runtime) SetMockRecording(anyRecording llx.Recording, providerID string, mockConnection bool) error {
	r.recording = anyRecording

	multiRecording, ok := anyRecording.(recording.MultiAsset)
	if !ok {
		return nil
	}

	assetRecordings := multiRecording.GetAssetRecordings()
	if len(assetRecordings) == 0 {
		return nil
	}
	assetRecording := assetRecordings[0]
	asset := assetRecording.Asset

	provider, ok := r.providers[providerID]
	if !ok {
		return errors.New("cannot set recording, provider '" + providerID + "' not found")
	}

	if mockConnection {
		// Dom: we may need to retain the original asset ID, not sure yet...
		asset.Id = "mock-asset"
		asset.Connections = []*inventory.Config{{
			Id:   Coordinator.NextConnectionId(),
			Type: "mock",
		}}

		callbacks := providerCallbacks{
			recording: assetRecording,
			runtime:   r,
		}

		provider.Connection, provider.ConnectionError = provider.Instance.Plugin.Connect(&plugin.ConnectReq{
			Asset:        asset,
			Upstream:     r.UpstreamConfig,
			HasRecording: true,
		}, &callbacks)
		if provider.ConnectionError != nil {
			return multierr.Wrap(provider.ConnectionError, "failed to set mock connection for recording")
		}
	}

	if provider.Connection == nil {
		// Dom: we may need to cancel the entire setup here, may need to be reconsidered...
		log.Warn().Msg("recording cannot determine asset, no connection was set up!")
	} else {
		multiRecording.SetAssetRecording(provider.Connection.Id, assetRecording)
	}

	return nil
}

func (r *Runtime) lookupResourceProvider(resource string) (*ConnectedProvider, *resources.ResourceInfo, error) {
	info, err := r.lookupResource(resource)
	if err != nil {
		return nil, nil, err
	}

	if info.Provider == "" {
		// This case happens when the resource is only bridging a resource chain,
		// i.e. it is extending in nature (which we only test for the warning).
		if !info.IsExtension {
			log.Warn().Msg("found a resource without a provider: '" + resource + "'")
		}
		return nil, info, nil
	}

	if provider := r.providers[info.Provider]; provider != nil {
		return provider, info, provider.ConnectionError
	}

	staticProvider, ok := r.Provider.Instance.Plugin.(plugin.StaticProvider)
	if ok {
		log.Debug().
			Str("provider", staticProvider.StaticName()).
			Msg("using static provider for resource field lookup")
		// this ensures we do not create other providers for resources that would normally handle them
		// e.g. asking for 'aws' would normally be handled by the 'aws' provider,
		// but if the main provider is a static provider, we assume it can handle all resources it provides
		return r.Provider, info, r.Provider.ConnectionError
	}

	providerConn := r.Provider.Instance.ID
	crossProviderList := []string{
		"go.mondoo.com/mql/providers/core",
		"go.mondoo.com/mql/providers/network",
		"go.mondoo.com/mql/providers/os",
		"go.mondoo.com/mql/providers/ms365",
		"go.mondoo.com/mql/providers/azure",
		"go.mondoo.com/mql/providers/networkdiscovery",
		"go.mondoo.com/mql/providers/ai",
		"go.mondoo.com/mql/providers/ipinfo",
		"go.mondoo.com/mql/providers/yara",
		// DEPRECATED, remove in v15.0 vv
		// As of v14 every shipped provider uses the version-less
		// "go.mondoo.com/mql/providers/<name>" form above, so nothing built from
		// this tree matches the two blocks below any more. They are NOT dead: a
		// provider is installed and versioned independently of the engine, so a
		// v14+ engine routinely runs against provider binaries released before
		// the ID change, which still report their old IDs from their own
		// <name>.json. Deleting these entries breaks cross-provider calls for
		// those users, silently -- the failure surfaces only as "incorrect
		// provider for asset" at the gate below.
		//
		// ADR 042 retires this whitelist wholesale in v15, replacing it with
		// consumer-declared dependencies. Until then, keep every entry.
		"go.mondoo.com/cnquery/providers/core",
		"go.mondoo.com/cnquery/providers/network",
		"go.mondoo.com/cnquery/providers/os",
		"go.mondoo.com/cnquery/providers/ms365",
		"go.mondoo.com/cnquery/providers/azure",
		"go.mondoo.com/cnquery/providers/networkdiscovery",
		"go.mondoo.com/cnquery/providers/ai",
		"go.mondoo.com/cnquery/providers/ipinfo",
		"go.mondoo.com/cnquery/providers/yara",
		// Providers traditionally had a version indication in their ID. With v10
		// this is no longer necessary (but still supported due to a bug,
		// see https://github.com/mondoohq/mql/pull/3053). This block covers the
		// last providers to carry one; same v15 removal as the block above.
		"go.mondoo.com/cnquery/v9/providers/core",
		"go.mondoo.com/cnquery/v9/providers/network",
		"go.mondoo.com/cnquery/v9/providers/os",
		"go.mondoo.com/cnquery/v9/providers/ms365",
		"go.mondoo.com/cnquery/v9/providers/azure",
		// ^^
	}

	// ADR 042 step 3: the gate accepts a declared dependency OR the legacy
	// whitelist, and logs when only the legacy path matched. Every remaining
	// legacy-only hit is a missing declaration; when that log goes quiet for a
	// release, the whitelist can be deleted (step 5, v15).
	minVersion, declared := r.declaresPeer(r.Provider.Instance, info.Provider)
	legacy := stringx.Contains(crossProviderList, info.Provider)

	if !declared && !legacy {
		log.Debug().Str("infoProvider", info.Provider).Str("connectionProvider", providerConn).Msg("mismatch between expected and received provider, ignoring provider")
		return nil, nil, errors.New("incorrect provider for asset, not adding " + info.Provider)
	}
	if !declared && legacy {
		log.Warn().
			Str("caller", providerConn).
			Str("peer", info.Provider).
			Msg("undeclared cross-provider call, allowed by the legacy whitelist; add it to Requires in the caller's config.go (ADR 042)")
	}

	res, err := r.addProvider(info.Provider)
	if err != nil {
		return nil, nil, multierr.Wrap(err, "failed to start provider '"+info.Provider+"'")
	}

	if err := checkPeerVersion(res.Instance, minVersion); err != nil {
		return nil, nil, err
	}

	res.Connection, res.ConnectionError = res.Instance.Plugin.Connect(&plugin.ConnectReq{
		Features: r.features,
		Upstream: r.UpstreamConfig,
		Asset:    r.crossProviderAsset(),
	}, nil)
	if res.ConnectionError != nil {
		return nil, nil, res.ConnectionError
	}

	return res, info, nil
}

func (r *Runtime) lookupResource(resource string) (*resources.ResourceInfo, error) {
	info := r.coordinator.Schema().Lookup(resource)
	if info == nil {
		// Typed for the same reason a missing field is: this is what version
		// skew looks like when a whole resource is new, and the executor has to
		// be able to tell it apart from a genuine failure.
		return nil, &llx.ErrResourceNotFound{Resource: resource}
	}

	// prioritize ids
	resourcesPerProvider := map[string]*resources.ResourceInfo{
		info.Provider: info,
	}
	for _, other := range info.Others {
		resourcesPerProvider[other.Provider] = other
	}

	priority := []string{BuiltinCoreID, r.Provider.Instance.ID}
	for i := len(priority) - 1; i >= 0; i-- {
		id := priority[i]
		if s := resourcesPerProvider[id]; s != nil {
			info = s
		}
	}
	return info, nil
}

func (r *Runtime) lookupFieldProvider(resource string, field string) (*ConnectedProvider, *resources.ResourceInfo, *resources.Field, error) {
	// First grab the resource from the correct provider
	resourceInfo, err := r.lookupResource(resource)
	if err != nil {
		return nil, nil, nil, err
	}

	// Then find the field we are looking for
	fieldInfo, ok := resourceInfo.Fields[field]
	if !ok {
		// Typed, because the executor has to tell this apart from other
		// failures: a field the reader has never heard of is the signature of
		// version skew, and only skew may be degraded rather than propagated.
		return nil, nil, nil, &llx.ErrFieldNotFound{Resource: resource, Field: field}
	}

	fieldsPerProvider := map[string]*resources.Field{
		fieldInfo.Provider: fieldInfo,
	}

	// Make a flat list of all definitions of this field in all providers
	for _, rI := range resourceInfo.Others {
		if f, ok := rI.Fields[field]; ok {
			fieldsPerProvider[f.Provider] = f

			for _, otherF := range f.Others {
				fieldsPerProvider[otherF.Provider] = otherF
			}
		}
	}

	for _, otherF := range fieldInfo.Others {
		fieldsPerProvider[otherF.Provider] = otherF
	}

	// prioritize ids
	priority := []string{BuiltinCoreID, r.Provider.Instance.ID}
	priorityMatched := false
	for i := len(priority) - 1; i >= 0; i-- {
		id := priority[i]
		if s := fieldsPerProvider[id]; s != nil {
			fieldInfo = s
			priorityMatched = true
		}
	}

	// Fallback: prefer a provider already running on this runtime over
	// spawning a new one whose connection type may not match the asset.
	//
	// When multiple providers define the same top-level resource (e.g. both
	// `os` and `vsphere` declare a `vulnmgmt` resource), schema aggregation
	// is non-deterministic — Schema.LookupField documents that "which
	// provider becomes the primary [is] non-deterministic". If the loser
	// gets picked here, Connect() below will be invoked on this runtime's
	// asset with the wrong provider, which typically rejects with
	// ErrUnsupportedProvider and surfaces to users as "unsupported platform"
	// even when the asset is fully supported by the sibling provider.
	//
	// A provider that's already in r.providers has been initialized for this
	// runtime (either as the primary or via a connector's MockConnect — e.g.
	// the sbom provider initializes the os provider this way), so it is
	// known-compatible with the asset. Prefer it over an as-yet-unstarted
	// provider when neither priority entry matched.
	//
	// Only runs when the priority loop didn't pick anything — if core or the
	// active connector was an explicit match, that selection is intentional
	// and must not be overridden.
	if !priorityMatched && r.providers[fieldInfo.Provider] == nil {
		// Sort for determinism only; alphabetical order carries no semantic
		// preference between sibling providers. The selection still has to
		// satisfy "already running on this runtime", so the tie-breaker only
		// matters when two compatible siblings are both initialized — rare in
		// practice. Schema aggregation should ideally make this case
		// impossible, but until then a stable order beats map iteration.
		providerIDs := make([]string, 0, len(fieldsPerProvider))
		for id := range fieldsPerProvider {
			providerIDs = append(providerIDs, id)
		}
		sort.Strings(providerIDs)
		for _, id := range providerIDs {
			if r.providers[id] != nil {
				fieldInfo = fieldsPerProvider[id]
				break
			}
		}
	}

	staticProvider, ok := r.Provider.Instance.Plugin.(plugin.StaticProvider)
	if ok {
		log.Debug().
			Str("provider", staticProvider.StaticName()).
			Msg("using static provider for resource field")
		// this ensures we do not create other providers for resources that would normally handle them
		// e.g. asking for 'aws' would normally be handled by the 'aws' provider,
		// but if the main provider is a static provider, we assume it can handle all resources it provides
		return r.Provider, resourceInfo, fieldInfo, r.Provider.ConnectionError
	}

	if provider := r.providers[fieldInfo.Provider]; provider != nil {
		return provider, resourceInfo, fieldInfo, provider.ConnectionError
	}

	// ADR 042 step 3: the same predicate as the resource path, but **log-only**
	// here. This path allows everything today -- it is how GetSharedData and
	// every query-driven field access reach a foreign provider -- so enforcing
	// it now would break callers that the resource-path gate never saw. The log
	// measures the population first; v15 turns it into the same check.
	if _, declared := r.declaresPeer(r.Provider.Instance, fieldInfo.Provider); !declared {
		log.Warn().
			Str("caller", r.Provider.Instance.ID).
			Str("peer", fieldInfo.Provider).
			Str("resource", resource).
			Str("field", field).
			Msg("undeclared cross-provider field access, allowed for now; add it to Requires in the caller's config.go (ADR 042)")
	}

	res, err := r.addProvider(fieldInfo.Provider)
	if err != nil {
		return nil, nil, nil, multierr.Wrap(err, "failed to start provider '"+fieldInfo.Provider+"'")
	}

	res.Connection, res.ConnectionError = res.Instance.Plugin.Connect(&plugin.ConnectReq{
		Features: r.features,
		Upstream: r.UpstreamConfig,
		Asset:    r.crossProviderAsset(),
	}, nil)
	if res.ConnectionError != nil {
		return nil, nil, nil, res.ConnectionError
	}

	return res, resourceInfo, fieldInfo, nil
}

func (r *Runtime) Schema() resources.ResourcesSchema {
	return r.coordinator.Schema()
}

// AssetRoot implements llx.AssetRootSource: the root of the connected asset's
// tree (ADR 031).
//
// The connection's answer wins. A provider's static declaration has to cover
// every platform it serves, so for `os` it is the `os.any` union; the connection
// knows which family it actually reached and says so in ConnectRes. Preferring
// it is what makes `_` on a Linux host mean `os.linux`, so the query is bounded
// by what that platform has rather than by the union of every platform. The
// concrete root is a member of the declared union, so this is a refinement of
// the declaration and not a disagreement with it.
//
// Falls back to the static declaration when the connection says nothing, which
// is every provider that has not implemented this yet, and to "" when there is
// no root at all - where `_` keeps failing.
//
// Only the main provider is consulted. A runtime can have several providers
// attached - a cross-provider call adds one - but they are all answering about
// the same asset, and the asset is rooted where its own connection put it.
func (r *Runtime) AssetRoot() string {
	if r.Provider == nil {
		return ""
	}
	if root := r.Provider.Connection.GetRoot(); root != "" {
		return root
	}
	return r.DeclaredAssetRoot()
}

// DeclaredAssetRoot implements llx.AssetRootSource: the root the provider
// declares statically, which for a multi-platform provider is the union of its
// roots.
func (r *Runtime) DeclaredAssetRoot() string {
	if r.Provider == nil || r.Provider.Instance == nil {
		return ""
	}
	return r.Provider.Instance.Root
}

// TranslationsFor implements llx.TranslationSource, so a compile that has a
// runtime has the downgrade catalog too (ADR 040 part 6).
//
// This is what makes the mechanism reachable without any caller assembling it:
// mql is the only compiler there is, so whatever compiles content - here or in
// anything built on this - reaches the catalog through the runtime it already
// has. The lookup is lazy and cached, so a compile that emits no fallbacks
// starts no providers.
func (r *Runtime) TranslationsFor(provider string) []*llx.TranslationStep {
	r.translationsOnce.Do(func() {
		r.translations = NewTranslationSource(r)
	})
	return r.translations.TranslationsFor(provider)
}

// UnavailableTranslationProviders names providers whose catalog could not be
// read during this runtime's compiles, for the one aggregate warning.
func (r *Runtime) UnavailableTranslationProviders() UnavailableProviders {
	if r.translations == nil {
		return nil
	}
	if src, ok := r.translations.(*translationSource); ok {
		return src.Unavailable()
	}
	return nil
}

func (r *Runtime) asset() *inventory.Asset {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Provider == nil || r.Provider.Connection == nil {
		return nil
	}
	return r.Provider.Connection.Asset
}

// declaresPeer reports whether the calling provider declares a dependency on
// the target provider, and the floor it declared (ADR 042 step 3).
//
// The declaration of record is `Requires` in the caller's own config.go,
// carried into its manifest. Matching is by ID first and name second.
//
// The name fallback is not laziness about identity. Every provider built from
// this tree uses the version-less `go.mondoo.com/mql/providers/<name>` ID, but
// providers are installed and versioned independently of the engine, so a v14
// caller routinely runs against a peer binary released before that change,
// which reports `go.mondoo.com/cnquery[/v9]/providers/<name>` from its own
// <name>.json. A declaration naming the normalized ID would not match it.
//
// Getting that wrong would not merely reject a call -- the legacy whitelist
// would still allow it -- it would log a correctly-declared call as
// "legacy-only". That log is the retirement signal for the whitelist itself
// (ADR 042 step 5: delete it after a release with zero legacy-only hits), so
// false positives from mixed installs would keep the condition from ever being
// met. The fallback retires with the whitelist, not before.
func (r *Runtime) declaresPeer(caller *RunningProvider, targetProviderID string) (string, bool) {
	if caller == nil {
		return "", false
	}
	if caller.ID == targetProviderID {
		return "", true
	}

	targetName := path.Base(targetProviderID)
	for _, dep := range caller.Requires {
		if dep.ID == targetProviderID || (dep.Name != "" && dep.Name == targetName) {
			return dep.MinVersion, true
		}
	}
	return "", false
}

// checkPeerVersion reports whether a started peer satisfies the floor the
// caller declared.
//
// This is the runtime half of the split in ADR 042: the build checks that a
// referenced resource *exists* in the peer's schema, because mid-PR the peer's
// config.go still carries the pre-release version and a build-time comparison
// would fail with the resource sitting right there. The version is checked
// here, against the peer that is actually installed -- the only place the two
// can genuinely disagree.
//
// A mismatch fails the call rather than warning, which is safe because the
// declared floor and the support boundary are the same number: floors start at
// lrcore.SupportedBaseline (13.0.0), and v14 deprecates everything below
// v13.0.0, so a refused peer is one that is already out of support. A floor
// above the baseline only ever comes from referencing a field that peer version
// genuinely does not have, where proceeding would produce a null that reads as
// a passing check.
func checkPeerVersion(peer *RunningProvider, minVersion string) error {
	if minVersion == "" || peer == nil || peer.Version == "" {
		return nil
	}
	diff, err := (semver.Parser{}).Compare(peer.Version, minVersion)
	if err != nil {
		// An unparseable version on either side is not evidence of a mismatch;
		// reporting one would break a call over a formatting problem.
		return nil
	}
	if diff < 0 {
		return errors.New("provider " + peer.Name + " " + peer.Version +
			" is older than the required " + minVersion)
	}
	return nil
}

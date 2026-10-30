// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package testutils

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils/mockprovider"
	networkconf "go.mondoo.com/mql/providers/network/config"
	networkprovider "go.mondoo.com/mql/providers/network/provider"
	osconf "go.mondoo.com/mql/providers/os/config"
	osprovider "go.mondoo.com/mql/providers/os/provider"
)

var (
	Features     mql.Features
	TestutilsDir string
)

func init() {
	logger.InitTestEnv()

	var err error
	Features, err = mql.InitFeatures(strings.Split(os.Getenv("FEATURES"), ",")...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	fmt.Println("---> active features: " + Features.String())

	_, pathToFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to get runtime for testutils for mql providers")
	}
	TestutilsDir = path.Dir(pathToFile)
}

type tester struct {
	Runtime llx.Runtime
}

type SchemaProvider struct {
	Provider string
	Path     string
}

func InitTester(runtime llx.Runtime) *tester {
	return &tester{
		Runtime: runtime,
	}
}

func (ctx *tester) Compile(query string) (*llx.CodeBundle, error) {
	return mqlc.Compile(query, nil, mqlc.NewConfig(ctx.Runtime.Schema(), Features))
}

func (ctx *tester) ExecuteCode(bundle *llx.CodeBundle, props map[string]*llx.Primitive) (map[string]*llx.RawResult, error) {
	return exec.ExecuteCode(ctx.Runtime, bundle, props, Features)
}

func (ctx *tester) TestQueryPWithError(t *testing.T, query string, props mqlc.PropsHandler) ([]*llx.RawResult, error) {
	t.Helper()
	bundle, err := mqlc.Compile(query, props, mqlc.NewConfig(ctx.Runtime.Schema(), Features))
	if err != nil {
		return nil, fmt.Errorf("failed to compile code: %w", err)
	}
	err = mqlc.Invariants.Check(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to check invariants: %w", err)
	}
	return ctx.TestMqlc(t, bundle, props.Available()), nil
}

func (ctx *tester) TestQueryP(t *testing.T, query string, props mqlc.PropsHandler) []*llx.RawResult {
	t.Helper()
	bundle, err := mqlc.Compile(query, props, mqlc.NewConfig(ctx.Runtime.Schema(), Features))
	if err != nil {
		t.Fatal("failed to compile code: " + err.Error())
	}
	err = mqlc.Invariants.Check(bundle)
	require.NoError(t, err)
	return ctx.TestMqlc(t, bundle, props.Available())
}

func (ctx *tester) TestQuery(t *testing.T, query string) []*llx.RawResult {
	return ctx.TestQueryP(t, query, mqlc.EmptyPropsHandler)
}

func (ctx *tester) TestMqlc(t *testing.T, bundle *llx.CodeBundle, props map[string]*llx.Primitive) []*llx.RawResult {
	t.Helper()

	resultMap, err := exec.ExecuteCode(ctx.Runtime, bundle, props, Features)
	require.NoError(t, err)

	lastQueryResult := &llx.RawResult{}
	results := make([]*llx.RawResult, 0, len(resultMap)+1)

	refs := make([]uint64, 0, len(bundle.CodeV2.Checksums))
	for _, datapointArr := range [][]uint64{bundle.CodeV2.Datapoints(), bundle.CodeV2.Entrypoints()} {
		refs = append(refs, datapointArr...)
	}

	slices.Sort(refs)

	for idx, ref := range refs {
		checksum := bundle.CodeV2.Checksums[ref]
		if d, ok := resultMap[checksum]; ok {
			results = append(results, d)
			if idx+1 == len(refs) {
				lastQueryResult.CodeID = d.CodeID
				if d.Data.Error != nil {
					lastQueryResult.Data = &llx.RawData{
						Error: d.Data.Error,
					}
				} else {
					success, valid := d.Data.IsSuccess()
					lastQueryResult.Data = llx.BoolData(success && valid)
				}
			}
		}
	}

	results = append(results, lastQueryResult)
	return results
}

func MustLoadSchema(provider SchemaProvider) *resources.Schema {
	if provider.Path == "" && provider.Provider == "" {
		panic("cannot load schema without provider name or path")
	}
	var lrPath string
	var versionsPath string
	if provider.Provider != "" {
		switch provider.Provider {
		// special handling for the mockprovider
		case "mockprovider":
			lrPath = filepath.Join(TestutilsDir, "mockprovider/resources/mockprovider.lr")
		default:
			lrPath = filepath.Join(TestutilsDir, "../../../providers/"+provider.Provider+"/resources/"+provider.Provider+".lr")
			versionsPath = filepath.Join(TestutilsDir, "../../../providers/"+provider.Provider+"/resources/"+provider.Provider+".lr.versions")
		}
	} else if provider.Path != "" {
		lrPath = provider.Path
	}

	res, err := lrcore.Resolve(lrPath, func(path string) ([]byte, error) { return os.ReadFile(path) })
	if err != nil {
		panic(err.Error())
	}
	schema, err := lrcore.Schema(res)
	if err != nil {
		panic(err.Error())
	}

	if versionsPath != "" {
		versions, err := lrcore.ReadVersions(versionsPath)
		if err == nil {
			lrcore.InjectVersions(schema, versions)
		}
	}

	return schema
}

func Local() llx.Runtime {
	osSchema := MustLoadSchema(SchemaProvider{Provider: "os"})
	coreSchema := MustLoadSchema(SchemaProvider{Provider: "core"})
	networkSchema := MustLoadSchema(SchemaProvider{Provider: "network"})
	mockSchema := MustLoadSchema(SchemaProvider{Provider: "mockprovider"})

	// Merge os+core before storing in the global extensibleSchema.
	// osSchema.Add(coreSchema) mutates osSchema.Resources in place.
	// If we store osSchema first and mutate it later, another goroutine's
	// unsafeRefresh may iterate osSchema.Resources concurrently, causing
	// a fatal "concurrent map iteration and map write" error.
	mergedOsSchema := osSchema.Add(coreSchema)

	schema := providers.Coordinator.Schema().(providers.ExtensibleSchema)
	schema.Add(providers.BuiltinCoreID, coreSchema)
	schema.Add(osconf.Config.Name, osSchema)
	schema.Add(networkconf.Config.Name, networkSchema)
	schema.Add(mockprovider.Config.Name, mockSchema)

	runtime := providers.Coordinator.NewRuntime()
	_ = providers.SetDefaultRuntime(runtime)
	runtime.AutoUpdate = providers.UpdateProvidersConfig{
		Enabled:         false,
		RefreshInterval: 60 * 60,
	}

	provider := &providers.RunningProvider{
		Name:   osconf.Config.Name,
		ID:     osconf.Config.ID,
		Plugin: osprovider.Init(),
		Schema: mergedOsSchema,
	}
	runtime.Provider = &providers.ConnectedProvider{Instance: provider}
	runtime.AddConnectedProvider(runtime.Provider)

	provider = &providers.RunningProvider{
		Name:   networkconf.Config.Name,
		ID:     networkconf.Config.ID,
		Plugin: networkprovider.Init(),
		Schema: networkSchema,
	}
	runtime.AddConnectedProvider(&providers.ConnectedProvider{Instance: provider})

	provider = &providers.RunningProvider{
		Name:   mockprovider.Config.Name,
		ID:     mockprovider.Config.ID,
		Plugin: mockprovider.Init(),
		Schema: mockSchema,
	}
	runtime.AddConnectedProvider(&providers.ConnectedProvider{Instance: provider})

	// Since the testutils runtime is meant to be used with in-memory
	// providers only, we deactivate any type of discovery on the system.
	// This prevents us from accidentally pulling locally installed providers
	// which may not work with the current dependencies. The task of testing
	// those falls to an integration environment, not to unit tests.
	providers.Coordinator.DeactivateProviderDiscovery()

	return runtime
}

func mockRuntime(testdata string) llx.Runtime {
	return mockRuntimeAbs(filepath.Join(TestutilsDir, testdata))
}

func MockFromRecording(recording llx.Recording) llx.Runtime {
	runtime := Local().(*providers.Runtime)

	err := runtime.SetMockRecording(recording, runtime.Provider.Instance.ID, true) //nolint:staticcheck // TODO: migrate off deprecated API
	if err != nil {
		panic("failed to set recording: " + err.Error())
	}
	err = runtime.SetMockRecording(recording, networkconf.Config.ID, true) //nolint:staticcheck // TODO: migrate off deprecated API
	if err != nil {
		panic("failed to set recording: " + err.Error())
	}
	err = runtime.SetMockRecording(recording, mockprovider.Config.ID, true) //nolint:staticcheck // TODO: migrate off deprecated API
	if err != nil {
		panic("failed to set recording: " + err.Error())
	}

	return runtime
}

func mockRuntimeAbs(testdata string) llx.Runtime {
	abs, _ := filepath.Abs(testdata)
	recording, err := recording.LoadRecordingFile(abs)
	if err != nil {
		panic("failed to load recording: " + err.Error())
	}
	roRecording := recording.ReadOnly()

	return MockFromRecording(roRecording)
}

func RecordingFromAsset(a *inventory.Asset) llx.Recording {
	recording, err := recording.FromAsset(a)
	if err != nil {
		panic("failed to create recording from an asset: " + err.Error())
	}
	roRecording := recording.ReadOnly()

	return roRecording
}

func MockFromAsset(a *inventory.Asset) llx.Runtime {
	return MockFromRecording(RecordingFromAsset(a))
}

func LinuxMock() llx.Runtime {
	return mockRuntime("testdata/arch.json")
}

// CrossAssetMock is LinuxMock plus a second recorded asset that names `muser`
// as the resource anchoring it (ADR 031). It is what a query resolving into
// another asset needs and a single-asset recording cannot provide.
func CrossAssetMock() llx.Runtime {
	return mockRuntime("testdata/cross-asset.json")
}

// CrossAssetLiveMock is CrossAssetMock with the reverse edge left out, so the
// recorded leg of resolution finds nothing and the target has to be asked for
// from the provider that owns the anchor resource (ADR 031 phase 8).
func CrossAssetLiveMock() llx.Runtime {
	return mockRuntime("testdata/cross-asset-live.json")
}

func KubeletMock() llx.Runtime {
	return mockRuntime("testdata/kubelet.json")
}

func KubeletAKSMock() llx.Runtime {
	return mockRuntime("testdata/kubelet-aks.json")
}

func KubeletEKSMock() llx.Runtime {
	return mockRuntime("testdata/kubelet-eks.json")
}

func WindowsMock() llx.Runtime {
	return mockRuntime("testdata/windows.json")
}

func RecordingMock(absTestdataPath string) llx.Runtime {
	return mockRuntimeAbs(absTestdataPath)
}

type SimpleTest struct {
	Code        string
	ResultIndex int
	Expectation any
	Error       string
}

func (ctx *tester) TestSimple(t *testing.T, tests []SimpleTest) {
	t.Helper()
	for i := range tests {
		cur := tests[i]
		t.Run(cur.Code, func(t *testing.T) {
			res := ctx.TestQuery(t, cur.Code)
			assert.NotEmpty(t, res)

			if len(res) <= cur.ResultIndex {
				t.Error("insufficient results, looking for result idx " + strconv.Itoa(cur.ResultIndex))
				return
			}

			data := res[cur.ResultIndex].Data
			if cur.Error != "" {
				require.NotNil(t, data.Error)
				assert.Equal(t, cur.Error, data.Error.Error())
			} else {
				require.NoError(t, data.Error)
				assert.Equal(t, cur.Expectation, data.Value)
			}
		})
	}
}

func (ctx *tester) TestNoErrorsNonEmpty(t *testing.T, tests []SimpleTest) {
	t.Helper()
	for i := range tests {
		cur := tests[i]
		t.Run(cur.Code, func(t *testing.T) {
			res := ctx.TestQuery(t, cur.Code)
			assert.NotEmpty(t, res)
		})
	}
}

func (ctx *tester) TestSimpleErrors(t *testing.T, tests []SimpleTest) {
	for i := range tests {
		cur := tests[i]
		t.Run(cur.Code, func(t *testing.T) {
			res := ctx.TestQuery(t, cur.Code)
			assert.NotEmpty(t, res)
			assert.Equal(t, cur.Expectation, res[cur.ResultIndex].Result().Error)
			assert.Nil(t, res[cur.ResultIndex].Data.Value)
		})
	}
}

func (ctx *tester) TestCompileErrors(t *testing.T, tests []SimpleTest) {
	for i := range tests {
		cur := tests[i]
		t.Run(cur.Code, func(t *testing.T) {
			res := ctx.TestQuery(t, cur.Code)
			assert.NotEmpty(t, res)
			assert.Equal(t, cur.Expectation, res[cur.ResultIndex].Result().Error)
			assert.Nil(t, res[cur.ResultIndex].Data.Value)
		})
	}
}

func TestNoResultErrors(t *testing.T, r []*llx.RawResult) bool {
	var found bool
	for i := range r {
		err := r[i].Data.Error
		if err != nil {
			t.Error("result has error: " + err.Error())
			found = true
		}
	}
	return found
}

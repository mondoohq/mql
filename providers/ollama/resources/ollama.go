// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/ollama/ollama/api"
	modeltypes "github.com/ollama/ollama/types/model"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ollama/connection"
	"go.mondoo.com/mql/types"
)

func ollamaConn(runtime *plugin.Runtime) *connection.OllamaConnection {
	return runtime.Connection.(*connection.OllamaConnection)
}

func (r *mqlOllama) id() (string, error) {
	return "ollama", nil
}

func (r *mqlOllama) host() (string, error) {
	return ollamaConn(r.MqlRuntime).Host(), nil
}

func (r *mqlOllama) version() (string, error) {
	return ollamaConn(r.MqlRuntime).Version(context.Background())
}

func (r *mqlOllama) tls() (bool, error) {
	return ollamaConn(r.MqlRuntime).TLS(), nil
}

func (r *mqlOllama) isLocal() (bool, error) {
	return ollamaConn(r.MqlRuntime).IsLocal(), nil
}

// authRequiredStatuses are the answers that mean the request was refused for
// lack of credentials, whoever refused it: the instance itself, or a proxy in
// front of it.
var authRequiredStatuses = []int{
	http.StatusUnauthorized,
	http.StatusForbidden,
	http.StatusProxyAuthRequired,
}

// readOpenStatuses are the answers that mean an unauthenticated read was
// served.
var readOpenStatuses = []int{http.StatusOK}

// writeOpenStatuses are the answers that mean an unauthenticated write reached
// the instance's own handler and was turned away only because the probe's body
// is unparseable. Nothing stood between the caller and the write path, so a
// well-formed request from the same caller would have been carried out.
var writeOpenStatuses = []int{http.StatusBadRequest, http.StatusUnprocessableEntity}

// classifyAuthProbe turns the status an unauthenticated probe was answered with
// into whether that access path demands credentials. Anything outside the two
// known sets (a redirect to a login page, a gateway error, an endpoint the
// instance does not serve) says nothing reliable, and guessing either way would
// be worse than reporting that we could not tell.
func classifyAuthProbe(code int, openStatuses []int, access string) (bool, error) {
	if slices.Contains(authRequiredStatuses, code) {
		return true, nil
	}
	if slices.Contains(openStatuses, code) {
		return false, nil
	}
	return false, fmt.Errorf("cannot determine whether %s authentication is required: unauthenticated request answered with status %d", access, code)
}

func (r *mqlOllama) authenticationRequired() (bool, error) {
	code, err := ollamaConn(r.MqlRuntime).AnonymousStatus(context.Background())
	if err != nil {
		return false, err
	}
	return classifyAuthProbe(code, readOpenStatuses, "read")
}

func (r *mqlOllama) writeAuthenticationRequired() (bool, error) {
	code, err := ollamaConn(r.MqlRuntime).AnonymousWriteStatus(context.Background())
	if err != nil {
		return false, err
	}
	return classifyAuthProbe(code, writeOpenStatuses, "write")
}

func (r *mqlOllama) cloudEnabled() (bool, error) {
	status, err := ollamaConn(r.MqlRuntime).Client().CloudStatusExperimental(context.Background())
	if err != nil {
		if isEndpointUnavailable(err) {
			r.CloudEnabled.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		return false, err
	}
	return !status.Cloud.Disabled, nil
}

func (r *mqlOllama) cloudAccount() (*mqlOllamaAccount, error) {
	user, err := ollamaConn(r.MqlRuntime).Client().Whoami(context.Background())
	if err != nil {
		// An instance that is not signed in rejects the request, and one built
		// before cloud accounts existed does not serve the endpoint at all.
		// Both mean there is no account to report.
		if isEndpointUnavailable(err) || isUnauthenticated(err) {
			r.CloudAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	id := user.ID.String()
	if user.Email == "" && user.Name == "" {
		r.CloudAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(r.MqlRuntime, "ollama.account", map[string]*llx.RawData{
		"__id":  llx.StringData(id),
		"id":    llx.StringData(id),
		"email": llx.StringData(user.Email),
		"name":  llx.StringData(user.Name),
		"plan":  llx.StringData(user.Plan),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOllamaAccount), nil
}

// isEndpointUnavailable reports whether the instance answered as though it does
// not serve the endpoint at all, which is how an Ollama build older than the
// endpoint responds. The caller treats it as "no answer available" rather than
// as a failure, so one old server does not fail a whole scan.
func isEndpointUnavailable(err error) bool {
	var statusErr api.StatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.StatusCode {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	}
	return false
}

// isUnauthenticated reports whether the instance refused the request for lack
// of credentials.
func isUnauthenticated(err error) bool {
	var statusErr api.StatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden
}

func (r *mqlOllama) models() ([]interface{}, error) {
	conn := ollamaConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.List(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}

	res := make([]interface{}, 0, len(resp.Models))
	for _, m := range resp.Models {
		mqlModel, err := CreateResource(r.MqlRuntime, "ollama.model", ollamaModelArgs(m))
		if err != nil {
			return nil, err
		}
		if len(m.Capabilities) > 0 {
			model := mqlModel.(*mqlOllamaModel)
			model.listCapabilities = make([]string, len(m.Capabilities))
			for i, c := range m.Capabilities {
				model.listCapabilities[i] = string(c)
			}
		}
		res = append(res, mqlModel)
	}

	return res, nil
}

// ollamaModelArgs builds the full set of resource args for an installed model.
// The name is the stable, unique identifier a user selects by, so it is used as
// the cache key. The digest is not unique: aliased tags (e.g. "llama3.1:latest"
// and "llama3.1:8b") share one manifest digest, so keying on it would collapse
// distinct models into a single cached resource.
func ollamaModelArgs(m api.ListModelResponse) map[string]*llx.RawData {
	families := make([]interface{}, len(m.Details.Families))
	for i, f := range m.Details.Families {
		families[i] = f
	}

	registry, namespace, repository, tag := modelRef(m.Name)

	return map[string]*llx.RawData{
		"__id":              llx.StringData(m.Name),
		"name":              llx.StringData(m.Name),
		"model":             llx.StringData(m.Model),
		"modifiedAt":        llx.TimeData(m.ModifiedAt),
		"size":              llx.IntData(m.Size),
		"digest":            llx.StringData(m.Digest),
		"format":            llx.StringData(m.Details.Format),
		"family":            llx.StringData(m.Details.Family),
		"families":          llx.ArrayData(families, types.String),
		"parameterSize":     llx.StringData(m.Details.ParameterSize),
		"quantizationLevel": llx.StringData(m.Details.QuantizationLevel),
		"parentModel":       llx.StringData(m.Details.ParentModel),
		"registry":          llx.StringData(registry),
		"namespace":         llx.StringData(namespace),
		"repository":        llx.StringData(repository),
		"tag":               llx.StringData(tag),
		"remoteModel":       llx.StringData(m.RemoteModel),
		"remoteHost":        llx.StringData(m.RemoteHost),
	}
}

// modelRef splits a model name into the registry coordinates it resolves to.
// Ollama fills in its defaults (registry.ollama.ai, library, latest) for the
// parts a short name leaves out, so an unqualified name such as
// "llama3.1:latest" still reports where the content came from. A name Ollama
// cannot parse yields empty parts rather than guessed ones, because reporting
// the default registry for a name we failed to read would claim provenance we
// never established.
func modelRef(name string) (registry, namespace, repository, tag string) {
	ref := modeltypes.ParseName(name)
	if !ref.IsValid() {
		return "", "", "", ""
	}
	return ref.Host, ref.Namespace, ref.Model, ref.Tag
}

// errModelNotFound reports that the Ollama instance does not list the
// requested model. Callers that can legitimately reference a model which is
// not installed use errors.Is to tell absence apart from a transport failure.
var errModelNotFound = errors.New("ollama model not found")

// modelNotFoundError names the missing model while keeping errModelNotFound in
// the chain, so the message stays useful without forcing callers to match on it.
func modelNotFoundError(name string) error {
	return fmt.Errorf("%w: %q", errModelNotFound, name)
}

// initOllamaModel resolves an installed model from just its name, so a
// cross-reference like ollama.runningModel.model returns full, real metadata
// (size, modifiedAt, digest, ...) rather than placeholder values. Models
// created directly via ollama.models carry a digest and skip this path.
func initOllamaModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Created directly with full metadata (carries a digest); nothing to resolve.
	if _, ok := args["digest"]; ok {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("ollama.model init requires a name or digest")
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("ollama.model init requires a non-empty name")
	}

	// Reuse an already-listed model instead of calling the API again.
	if x, ok := runtime.Resources.Get("ollama.model\x00" + name); ok {
		return nil, x, nil
	}

	conn := ollamaConn(runtime)
	resp, err := conn.Client().List(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, m := range resp.Models {
		if m.Name == name {
			return ollamaModelArgs(m), nil, nil
		}
	}

	return nil, nil, modelNotFoundError(name)
}

func (r *mqlOllama) runningModels() ([]interface{}, error) {
	conn := ollamaConn(r.MqlRuntime)
	client := conn.Client()

	resp, err := client.ListRunning(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to list running models: %w", err)
	}

	res := make([]interface{}, 0, len(resp.Models))
	for _, m := range resp.Models {
		mqlRunning, err := CreateResource(r.MqlRuntime, "ollama.runningModel", map[string]*llx.RawData{
			"__id":          llx.StringData("running/" + m.Name),
			"name":          llx.StringData(m.Name),
			"digest":        llx.StringData(m.Digest),
			"expiresAt":     llx.TimeData(m.ExpiresAt),
			"sizeVram":      llx.IntData(m.SizeVRAM),
			"contextLength": llx.IntData(int64(m.ContextLength)),
		})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlRunning)
	}

	return res, nil
}

type mqlOllamaModelInternal struct {
	// fetched is read on fetchShow's fast path, outside the mutex that guards
	// the write, so it is atomic rather than a plain bool. show is written
	// before fetched is stored and read only once fetched reads true, so that
	// store and load order the two.
	fetched atomic.Bool
	show    *api.ShowResponse
	lock    sync.Mutex

	// listCapabilities holds the capabilities the model listing already
	// reported, so reading the capabilities field costs nothing extra. Nil when
	// the listing did not carry them, which is how a server older than the field
	// answers and how a model reached by cross-reference rather than by listing
	// arrives; the per-model Show call is then still made.
	listCapabilities []string
}

func (r *mqlOllamaModel) fetchShow() (*api.ShowResponse, error) {
	if r.fetched.Load() {
		return r.show, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.show, nil
	}
	conn := ollamaConn(r.MqlRuntime)
	show, err := conn.Client().Show(context.Background(), &api.ShowRequest{
		Model: r.GetName().Data,
	})
	if err != nil {
		return nil, err
	}
	r.show = show
	r.fetched.Store(true)
	return r.show, nil
}

func (r *mqlOllamaModel) id() (string, error) {
	return r.Name.Data, nil
}

func (r *mqlOllamaModel) license() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(show.License), nil
}

func (r *mqlOllamaModel) modelfile() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return show.Modelfile, nil
}

func (r *mqlOllamaModel) adapters() ([]interface{}, error) {
	show, err := r.fetchShow()
	if err != nil {
		return nil, err
	}

	targets := modelfileAdapters(show.Modelfile)
	res := make([]interface{}, len(targets))
	for i, t := range targets {
		res[i] = t
	}
	return res, nil
}

// modelfileAdapters returns the target of every ADAPTER instruction in a
// Modelfile. Instruction names are case-insensitive and separated from their
// target by whitespace; targets may be quoted. Comment lines are skipped,
// because `ollama show` emits a commented FROM header that would otherwise
// read as an instruction.
func modelfileAdapters(modelfile string) []string {
	var res []string

	// SplitSeq walks the same substrings without materializing a header for
	// every line, which matters because a Modelfile is mostly PARAMETER lines
	// this never looks at.
	for line := range strings.SplitSeq(modelfile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		sep := strings.IndexFunc(line, unicode.IsSpace)
		if sep < 0 || !strings.EqualFold(line[:sep], "ADAPTER") {
			continue
		}

		target := strings.TrimSpace(line[sep:])
		if unquoted, err := strconv.Unquote(target); err == nil {
			target = unquoted
		}
		if target != "" {
			res = append(res, target)
		}
	}

	return res
}

func (r *mqlOllamaModel) system() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return show.System, nil
}

func (r *mqlOllamaModel) template() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return show.Template, nil
}

func (r *mqlOllamaModel) capabilities() ([]interface{}, error) {
	// The model listing reports capabilities, so asking every model to describe
	// itself again would cost one extra request per installed model on a query
	// that is often the whole point of the scan.
	if len(r.listCapabilities) > 0 {
		caps := make([]interface{}, len(r.listCapabilities))
		for i, c := range r.listCapabilities {
			caps[i] = c
		}
		return caps, nil
	}

	show, err := r.fetchShow()
	if err != nil {
		return nil, err
	}
	caps := make([]interface{}, len(show.Capabilities))
	for i, c := range show.Capabilities {
		caps[i] = string(c)
	}
	return caps, nil
}

// parameters returns the PARAMETER block of the model's Modelfile verbatim, the
// runtime defaults the server applies to every request for this model.
func (r *mqlOllamaModel) parameters() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(show.Parameters), nil
}

func (r *mqlOllamaModel) renderer() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return show.Renderer, nil
}

func (r *mqlOllamaModel) parser() (string, error) {
	show, err := r.fetchShow()
	if err != nil {
		return "", err
	}
	return show.Parser, nil
}

func (r *mqlOllamaModel) info() (*mqlOllamaModelInfo, error) {
	show, err := r.fetchShow()
	if err != nil {
		return nil, err
	}

	mi := show.ModelInfo
	arch := getString(mi, "general.architecture")

	languages := getStringSlice(mi, "general.languages")
	tags := getStringSlice(mi, "general.tags")
	datasets := getStringSlice(mi, "general.datasets")

	res, err := CreateResource(r.MqlRuntime, "ollama.model.info", map[string]*llx.RawData{
		"__id":              llx.StringData(r.Name.Data + "/info"),
		"architecture":      llx.StringData(arch),
		"basename":          llx.StringData(getString(mi, "general.basename")),
		"finetune":          llx.StringData(getString(mi, "general.finetune")),
		"sizeLabel":         llx.StringData(getString(mi, "general.size_label")),
		"license":           llx.StringData(getString(mi, "general.license")),
		"author":            llx.StringData(getString(mi, "general.author")),
		"description":       llx.StringData(getString(mi, "general.description")),
		"parameterCount":    llx.IntData(getInt(mi, "general.parameter_count")),
		"languages":         llx.ArrayData(languages, types.String),
		"tags":              llx.ArrayData(tags, types.String),
		"datasets":          llx.ArrayData(datasets, types.String),
		"contextLength":     llx.IntData(getArchInt(mi, arch, "context_length")),
		"embeddingLength":   llx.IntData(getArchInt(mi, arch, "embedding_length")),
		"blockCount":        llx.IntData(getArchInt(mi, arch, "block_count")),
		"feedForwardLength": llx.IntData(getArchInt(mi, arch, "feed_forward_length")),
		"headCount":         llx.IntData(getArchInt(mi, arch, "attention.head_count")),
		"headCountKv":       llx.IntData(getArchInt(mi, arch, "attention.head_count_kv")),
		"vocabSize":         llx.IntData(getArchInt(mi, arch, "vocab_size")),
		"expertCount":       llx.IntData(getArchInt(mi, arch, "expert_count")),
		"expertUsedCount":   llx.IntData(getArchInt(mi, arch, "expert_used_count")),
		"tokenizerModel":    llx.StringData(getString(mi, "tokenizer.ggml.model")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOllamaModelInfo), nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]any, key string) int64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		}
	}
	return 0
}

func getArchInt(m map[string]any, arch, key string) int64 {
	return getInt(m, arch+"."+key)
}

func getStringSlice(m map[string]any, key string) []interface{} {
	v, ok := m[key]
	if !ok || v == nil {
		return []interface{}{}
	}
	switch s := v.(type) {
	case []any:
		res := make([]interface{}, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				res = append(res, str)
			}
		}
		return res
	}
	return []interface{}{}
}

func (r *mqlOllamaModelInfo) id() (string, error) {
	return r.Architecture.Data + "/" + r.Basename.Data + "/" + r.SizeLabel.Data, nil
}

func (r *mqlOllamaRunningModel) id() (string, error) {
	return "running/" + r.Name.Data, nil
}

func (r *mqlOllamaRunningModel) model() (*mqlOllamaModel, error) {
	res, err := NewResource(r.MqlRuntime, "ollama.model", map[string]*llx.RawData{
		"name": llx.StringData(r.GetName().Data),
	})
	if err != nil {
		// /api/ps can report a model that /api/tags does not list: one that was
		// loaded and then deleted, or a cloud-resident model. That is a real
		// absence, not a failure to read. Any other error still propagates.
		if errors.Is(err, errModelNotFound) {
			r.Model.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlOllamaModel), nil
}

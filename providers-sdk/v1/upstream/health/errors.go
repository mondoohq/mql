// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/ranger-rpc"
)

//go:generate protoc --plugin=protoc-gen-go=../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../../../../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size errors.proto

// ReportOption configures optional fields on error reports.
type ReportOption func(*reportOptions)

type reportOptions struct {
	tags map[string]string
}

// WithTags attaches arbitrary key-value tags to the error report.
// These are forwarded to the platform and surfaced as Sentry tags.
func WithTags(tags map[string]string) ReportOption {
	return func(o *reportOptions) {
		if o.tags == nil {
			o.tags = make(map[string]string, len(tags))
		}
		for k, v := range tags {
			o.tags[k] = v
		}
	}
}

func applyOptions(opts []ReportOption) reportOptions {
	var o reportOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type PanicReportFn func(product, version, build string, r any, stacktrace []byte)

func ReportPanic(product, version, build string, reporters ...PanicReportFn) {
	if build == "" {
		return // avoid reporting panics from environments that don't set this variable
	}

	if r := recover(); r != nil {
		handlePanic(product, version, build, r, nil, reporters)

		// output error to console
		panic(r)
	}
}

// Tag keys for query-context panic tags. The platform's error report
// handler reads these to surface the crashing query in obslog
// (mondoo.query.text / mondoo.query.code_id) and Sentry.
const (
	TagQueryCodeID = "queryCodeID"
	TagQuerySource = "querySource"
)

// querySourceMax bounds the query source attached to a panic report,
// mirroring the platform's slow-query text bound. Large enough for any
// real check; bounded so a pathological bundle can't bloat the report.
const querySourceMax = 2048

// QueryPanicTags builds the crash-time tags identifying the query an
// executor was running when it panicked. Returns nil when there is no
// query context so callers can pass the result straight to
// ReportPanicWithTags.
func QueryPanicTags(codeID, source string) map[string]string {
	if codeID == "" && source == "" {
		return nil
	}
	tags := make(map[string]string, 2)
	if codeID != "" {
		tags[TagQueryCodeID] = codeID
	}
	if source != "" {
		if r := []rune(source); len(r) > querySourceMax {
			source = string(r[:querySourceMax])
		}
		tags[TagQuerySource] = source
	}
	return tags
}

// PanicTagsFn supplies tags for a panic report. It is invoked only while a
// panic is being recovered, so implementations can cheaply close over mutable
// state — e.g. the query an executor is currently running — and snapshot it
// at crash time.
type PanicTagsFn func() map[string]string

// ReportPanicWithTags is ReportPanic with crash-time tags attached to the
// report. Tags are forwarded to the platform (obslog fields and Sentry tags),
// which is how an executor can record WHICH query was running when the engine
// panicked — the stacktrace alone only shows where it died.
//
// Like ReportPanic, it must be invoked directly via defer.
func ReportPanicWithTags(product, version, build string, tagsFn PanicTagsFn, reporters ...PanicReportFn) {
	if build == "" {
		return // avoid reporting panics from environments that don't set this variable
	}

	if r := recover(); r != nil {
		var tags map[string]string
		if tagsFn != nil {
			tags = tagsFn()
		}
		handlePanic(product, version, build, r, tags, reporters)

		// output error to console
		panic(r)
	}
}

// ReportRecoveredPanic reports an already-recovered panic without
// re-panicking. Use it when the caller recovers a panic itself and converts
// it into an error instead of crashing the process. The caller supplies the
// stacktrace (it typically needs one for its own logging anyway) — capture
// it via debug.Stack() inside the deferred function that recovered, so it
// still points at the panic site.
func ReportRecoveredPanic(product, version, build string, r any, stacktrace []byte, tags map[string]string, reporters ...PanicReportFn) {
	if build == "" {
		return // avoid reporting panics from environments that don't set this variable
	}
	handlePanicWithStack(product, version, build, r, stacktrace, tags, reporters)
}

func handlePanic(product, version, build string, r any, tags map[string]string, reporters []PanicReportFn) {
	handlePanicWithStack(product, version, build, r, debug.Stack(), tags, reporters)
}

func handlePanicWithStack(product, version, build string, r any, stack []byte, tags map[string]string, reporters []PanicReportFn) {
	sendPanic(product, version, build, r, stack, tags)

	// call additional reporters
	for _, reporter := range reporters {
		reporter(product, version, build, r, stack)
	}
}

// sendPanic sends a panic to the mondoo platform for further analysis if the
// service account is configured.
// This function does not return an error as it is not critical to send the panic to the platform.
func sendPanic(product, version, build string, r any, stacktrace []byte, tags map[string]string) {
	// 1. read config
	opts, err := config.Read()
	if err != nil {
		log.Error().Err(err).Msg("failed to read config")
		return
	}

	serviceAccount := opts.GetServiceCredential()
	if serviceAccount == nil {
		log.Error().Msg("no service account configured")
		return
	}

	// 2. create local support bundle
	event := panicEvent(product, version, build, r, stacktrace, tags)
	event.ServiceAccountMrn = opts.ServiceAccountMrn
	event.AgentMrn = opts.AgentMrn

	// 3. send error to mondoo platform
	sendErrorToMondooPlatform(serviceAccount, event)

	log.Info().Msg("reported panic to Mondoo Platform")
}

// panicEvent builds the error report for a recovered panic, tagged with the
// platform the binary runs on so reports remain attributable even when no
// asset context is available (e.g. panics outside a scan).
func panicEvent(product, version, build string, r any, stacktrace []byte, tags map[string]string) *SendErrorReq {
	allTags := make(map[string]string, len(tags)+2)
	for k, v := range tags {
		allTags[k] = v
	}
	// Platform tags are written last so caller-supplied tags cannot
	// overwrite them.
	allTags["os"] = runtime.GOOS
	allTags["arch"] = runtime.GOARCH
	return &SendErrorReq{
		Product: &ProductInfo{
			Name:    product,
			Version: version,
			Build:   build,
		},
		Error: &ErrorInfo{
			Message:    "panic: " + fmt.Sprintf("%v", r),
			Stacktrace: string(stacktrace),
		},
		Tags: allTags,
	}
}

func ReportError(product, version, build, err string, opts ...ReportOption) {
	reportError(product, version, build, err, applyOptions(opts))
}

// reportError sends an error to the mondoo platform for further analysis if the
// service account is configured.
// This function does not return an error as it is not critical to send the error to the platform.
func reportError(product, version, build string, errMsg string, ro reportOptions) {
	// 1. read config
	opts, err := config.Read()
	if err != nil {
		log.Error().Err(err).Msg("failed to read config")
		return
	}

	serviceAccount := opts.GetServiceCredential()
	if serviceAccount == nil {
		log.Error().Msg("no service account configured")
		return
	}

	// 2. create local support bundle
	event := &SendErrorReq{
		ServiceAccountMrn: opts.ServiceAccountMrn,
		AgentMrn:          opts.AgentMrn,
		Product: &ProductInfo{
			Name:    product,
			Version: version,
			Build:   build,
		},
		Error: &ErrorInfo{
			Message: errMsg,
		},
		Tags: ro.tags,
	}

	// 3. send error to mondoo platform
	sendErrorToMondooPlatform(serviceAccount, event)

	log.Info().Msg("reported error to Mondoo Platform")
}

type SlowQueryInfo struct {
	CodeID   string
	Query    string
	Duration time.Duration
}

func ReportSlowQuery(product, version, build string, q SlowQueryInfo, opts ...ReportOption) {
	sendSlowQuery(product, version, build, q, applyOptions(opts))
}

// sendSlowQuery sends queries that have been deemed excessively slow to
// the platform for further analysis.
func sendSlowQuery(product, version, build string, q SlowQueryInfo, ro reportOptions) {
	// 1. read config
	opts, err := config.Read()
	if err != nil {
		log.Error().Err(err).Msg("failed to read config")
		return
	}

	serviceAccount := opts.GetServiceCredential()
	if serviceAccount == nil {
		log.Error().Msg("no service account configured")
		return
	}

	msg := "slow query: " + fmt.Sprintf("%s took %s", q.CodeID, q.Duration.String())
	if q.Query != "" {
		msg = "slow query: " + fmt.Sprintf("%s (%s) took %s", q.Query, q.CodeID, q.Duration.String())
	}
	// 2. create local support bundle
	event := &SendErrorReq{
		ServiceAccountMrn: opts.ServiceAccountMrn,
		AgentMrn:          opts.AgentMrn,
		Product: &ProductInfo{
			Name:    product,
			Version: version,
			Build:   build,
		},
		Error: &ErrorInfo{
			Message: msg,
		},
		Tags: ro.tags,
	}

	// 3. send error to mondoo platform
	sendErrorToMondooPlatform(serviceAccount, event)

	log.Debug().Msg("reported slow query to Mondoo Platform")
}

func sendErrorToMondooPlatform(serviceAccount *upstream.ServiceAccountCredentials, event *SendErrorReq) {
	// 3. send error to mondoo platform
	httpClient, err := config.NewHttpClient()
	if err != nil {
		log.Error().Err(err).Msg("failed to parse proxy setting")
		return
	}

	plugins := []ranger.ClientPlugin{}
	certAuth, err := upstream.NewServiceAccountRangerPlugin(serviceAccount)
	if err != nil {
		return
	}
	plugins = append(plugins, certAuth)

	cl, err := NewErrorReportingClient(serviceAccount.ApiEndpoint, httpClient, plugins...)
	if err != nil {
		log.Error().Err(err).Msg("failed to create error reporting client")
		return
	}

	_, err = cl.SendError(context.Background(), event)
	if err != nil {
		log.Error().Err(err).Msg("failed to send error to mondoo platform")
		return
	}
}

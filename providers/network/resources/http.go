// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
)

type mqlHttpGetInternal struct {
	lock sync.Mutex
	resp plugin.TValue[*http.Response]
}

func initHttpGet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if rawUrl, ok := args["rawUrl"]; ok {
		// We add a default prefix if it is missing. Otherwise the URL parser
		// will return unintuitive results. For example: "mondoo.com" would
		// return a host="" with path="mondoo.com", correctly following the spec.
		if !strings.Contains(rawUrl.Value.(string), "://") {
			rawUrl.Value = "http://" + rawUrl.Value.(string)
		}

		url, err := NewResource(runtime, "url", map[string]*llx.RawData{
			"raw": rawUrl,
			// Additional arguments for this resource are used only if parsing
			// of the raw url doesn't overwrite them. They are defaults.
			"scheme": llx.StringData("http"),
		})
		if err != nil {
			return nil, nil, err
		}

		delete(args, "rawUrl")
		args["url"] = llx.ResourceData(url, "url")
	}

	if _, ok := args["url"]; !ok {
		conn := runtime.Connection.(*connection.HostConnection)
		if conn.Conf == nil {
			return nil, nil, errors.New("missing URL for http.get")
		}

		scheme := conn.Conf.Runtime
		if scheme == "" {
			scheme = defaultHTTPScheme(conn.Conf.Port)
		}
		url, err := NewResource(runtime, "url", map[string]*llx.RawData{
			"host":   llx.StringData(conn.Conf.Host),
			"port":   llx.IntData(int64(conn.Conf.Port)),
			"scheme": llx.StringData(scheme),
		})
		if err != nil {
			return nil, nil, err
		}
		args["url"] = llx.ResourceData(url, "url")
		args["followRedirects"] = llx.BoolData(conn.FollowRedirects)
	}

	if _, ok := args["followRedirects"]; !ok {
		args["followRedirects"] = llx.BoolData(false)
	}

	return args, nil, nil
}

// defaultHTTPScheme picks the URL scheme for http.get when the target carried no
// explicit scheme (a bare `host <domain>`). It defaults to HTTPS — the modern
// web default and consistent with the tls resource, which assumes 443 for a bare
// target — so scanning a bare domain exercises the HTTPS endpoint, where the
// hardening headers policies check (HSTS, CSP, cookie flags) actually live,
// instead of plain :80. Only an explicit non-TLS port falls back to HTTP, so
// `http.get` on `example.com:8080` still speaks HTTP. Users can always prefix a
// scheme to be prescriptive.
func defaultHTTPScheme(port int32) string {
	switch port {
	case 0, 443:
		return "https"
	default:
		return "http"
	}
}

func (x *mqlHttpGet) id() (string, error) {
	return strings.Join([]string{x.Url.Data.__id, strconv.FormatBool(x.FollowRedirects.Data)}, ";"), nil
}

func (x *mqlHttpGet) do() error {
	x.lock.Lock()
	defer x.lock.Unlock()

	if x.resp.State&plugin.StateIsSet != 0 {
		return x.resp.Error
	}

	if x.Url.Data == nil {
		return errors.New("missing URL for http.get")
	}

	conn := x.MqlRuntime.Connection.(*connection.HostConnection)
	resp, err := conn.Client(x.FollowRedirects.Data).Get(x.Url.Data.String.Data)
	x.resp.State = plugin.StateIsSet
	x.resp.Data = resp
	x.resp.Error = err
	if err != nil {
		return err
	}

	x.StatusCode.Data = int64(resp.StatusCode)
	x.StatusCode.State = plugin.StateIsSet

	x.Version.Data = strconv.Itoa(resp.ProtoMajor) + "." + strconv.Itoa(resp.ProtoMinor)
	x.Version.State = plugin.StateIsSet
	return nil
}

// httpNotReachable reports whether err means the target did not speak HTTP on
// this endpoint — nothing was listening, the connection was refused/reset, the
// dial timed out, or the name did not resolve — as opposed to an unexpected
// internal error. In that case the http.get fields (header, statusCode, version,
// body) all resolve to null (like the tls resource's params when TLS is not
// enabled), so policies can gate on `http.get.header != empty` and skip instead
// of erroring on non-HTTP hosts (mail/DNS/infra servers commonly surfaced by
// attack-surface enumeration).
func httpNotReachable(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// dial/read/write at the socket level: connection refused, reset, no route
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func (x *mqlHttpGet) header() (*mqlHttpHeader, error) {
	if err := x.do(); err != nil {
		if httpNotReachable(err) {
			x.Header.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	header := x.resp.Data.Header
	params := make(map[string]any, len(header))
	for key := range header {
		mkey := textproto.CanonicalMIMEHeaderKey(key)
		vals := header[mkey]
		ivals := make([]any, len(vals))
		for j := range vals {
			ivals[j] = vals[j]
		}
		params[normalizeHeaderKey(mkey)] = ivals
	}

	o, err := CreateResource(x.MqlRuntime, "http.header", map[string]*llx.RawData{
		"__id":   llx.StringData(x.__id),
		"params": llx.MapData(params, types.Array(types.String)),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlHttpHeader), nil
}

var normHeaderKeys = map[string]string{
	"X-Xss-Protection": "X-XSS-Protection",
}

// adds a few more key normalizations
func normalizeHeaderKey(key string) string {
	if res, ok := normHeaderKeys[key]; ok {
		return res
	}
	return key
}

func (x *mqlHttpGet) statusCode() (int64, error) {
	if err := x.do(); err != nil {
		if httpNotReachable(err) {
			x.StatusCode.State = plugin.StateIsSet | plugin.StateIsNull
			return 0, nil
		}
		return 0, err
	}
	// do() sets StatusCode on success.
	return 0, nil
}

func (x *mqlHttpGet) version() (string, error) {
	if err := x.do(); err != nil {
		if httpNotReachable(err) {
			x.Version.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}
	// do() sets Version on success.
	return "", nil
}

func (x *mqlHttpGet) body() (string, error) {
	if err := x.do(); err != nil {
		if httpNotReachable(err) {
			x.Body.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}
	raw, err := io.ReadAll(x.resp.Data.Body)
	return string(raw), err
}

func parseHeaderFields(raw []any, f func(key string, value string)) {
	parseHeaderFieldsD(raw, f, ";", "=")
}

func parseHeaderFieldsD(raw []any, f func(key string, value string), delimFields string, delimKV string) {
	for i := range raw {
		h := raw[i].(string)
		fields := strings.Split(h, delimFields)
		for j := range fields {
			field := strings.TrimSpace(fields[j])
			s := strings.SplitN(field, delimKV, 2)
			if len(s) == 1 {
				f(s[0], "")
			} else {
				f(s[0], s[1])
			}
		}
	}
}

func parseSingleHeaderValue[T any](raw any, found bool, field *plugin.TValue[T]) (string, error) {
	if !found {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	arr := raw.([]any)
	var res strings.Builder
	for i := range arr {
		if i != 0 {
			res.WriteByte(' ')
		}
		res.WriteString(arr[i].(string))
	}
	return res.String(), nil
}

func (x *mqlHttpHeader) id() (string, error) {
	return "", errors.New("http header not initialized")
}

func parseStsDirectives(raw []any) (preload bool, includeSubDomains bool, maxAge *llx.RawData) {
	maxAge = llx.NilData
	parseHeaderFields(raw, func(key string, value string) {
		// RFC 6797 section 6.1: directive names are case-insensitive
		switch strings.ToLower(key) {
		case "preload":
			preload = true
		case "includesubdomains":
			includeSubDomains = true
		case "max-age":
			age, err := strconv.Atoi(value)
			if err != nil {
				maxAge = llx.TimeData(time.Time{})
				maxAge.Error = errors.New("maxAge is invalid: " + value)
			} else {
				maxAge = llx.TimeData(llx.DurationToTime(int64(age)))
			}
		}
	})
	return preload, includeSubDomains, maxAge
}

func (x *mqlHttpHeader) sts() (*mqlHttpHeaderSts, error) {
	raw, ok := x.Params.Data["Strict-Transport-Security"]
	if !ok {
		x.Sts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	preload, includeSubDomains, maxAge := parseStsDirectives(raw.([]any))

	o, err := CreateResource(x.MqlRuntime, "http.header.sts", map[string]*llx.RawData{
		"preload":           llx.BoolData(preload),
		"includeSubDomains": llx.BoolData(includeSubDomains),
		"maxAge":            maxAge,
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlHttpHeaderSts), nil
}

func (x *mqlHttpHeaderSts) id() (string, error) {
	id := ""
	if x.MaxAge.Data != nil {
		id += "maxAge=" + strconv.Itoa(int(x.MaxAge.Data.Unix()))
	}
	if x.Preload.Data {
		id += ";preload"
	}
	if x.IncludeSubDomains.Data {
		id += ";includeSubdomains"
	}
	return id, nil
}

func (x *mqlHttpHeader) xFrameOptions() (string, error) {
	params, ok := x.Params.Data["X-Frame-Options"]
	return parseSingleHeaderValue(params, ok, &x.XFrameOptions)
}

func parseXssProtectionDirectives(raw []any) (enabled *llx.RawData, mode *llx.RawData, report *llx.RawData) {
	enabled, mode, report = llx.NilData, llx.NilData, llx.NilData
	parseHeaderFields(raw, func(key string, value string) {
		// directive names are case-insensitive, matching the other parsers
		switch strings.ToLower(key) {
		case "0":
			enabled = llx.BoolFalse
		case "1":
			enabled = llx.BoolTrue
		case "mode":
			mode = llx.StringData(value)
		case "report":
			report = llx.StringData(value)
		}
	})
	return enabled, mode, report
}

func (x *mqlHttpHeader) xXssProtection() (*mqlHttpHeaderXssProtection, error) {
	raw, ok := x.Params.Data["X-XSS-Protection"]
	if !ok {
		x.XXssProtection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	enabled, mode, report := parseXssProtectionDirectives(raw.([]any))

	o, err := CreateResource(x.MqlRuntime, "http.header.xssProtection", map[string]*llx.RawData{
		"enabled": enabled,
		"mode":    mode,
		"report":  report,
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlHttpHeaderXssProtection), nil
}

func (x *mqlHttpHeaderXssProtection) id() (string, error) {
	var id string
	if x.Enabled.Data {
		id = "1"
	} else {
		id = "0"
	}
	if x.Mode.Data != "" {
		id += ";mode=" + x.Mode.Data
	}
	if x.Report.Data != "" {
		id += ";report=" + x.Report.Data
	}
	return id, nil
}

func (x *mqlHttpHeader) xContentTypeOptions() (string, error) {
	params, ok := x.Params.Data["X-Content-Type-Options"]
	return parseSingleHeaderValue(params, ok, &x.XContentTypeOptions)
}

func (x *mqlHttpHeader) referrerPolicy() (string, error) {
	params, ok := x.Params.Data["Referrer-Policy"]
	return parseSingleHeaderValue(params, ok, &x.ReferrerPolicy)
}

func (x *mqlHttpHeader) server() (string, error) {
	params, ok := x.Params.Data["Server"]
	return parseSingleHeaderValue(params, ok, &x.Server)
}

func parseContentTypeDirectives(raw []any) (typ *llx.RawData, params *llx.RawData) {
	typ, params = llx.NilData, llx.NilData
	parseHeaderFields(raw, func(key string, value string) {
		// RFC 9110 section 8.3.1: media types and parameter names are
		// case-insensitive; parameter values keep their casing
		if typ.Value == nil && value == "" {
			typ = llx.StringData(strings.ToLower(key))
			return
		}
		if params.Value == nil {
			params = llx.MapData(map[string]any{}, types.String)
		}
		params.Value.(map[string]any)[strings.ToLower(key)] = value
	})
	return typ, params
}

func (x *mqlHttpHeader) contentType() (*mqlHttpHeaderContentType, error) {
	raw, ok := x.Params.Data["Content-Type"]
	if !ok {
		x.ContentType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	typ, params := parseContentTypeDirectives(raw.([]any))

	o, err := CreateResource(x.MqlRuntime, "http.header.contentType", map[string]*llx.RawData{
		"type":   typ,
		"params": params,
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlHttpHeaderContentType), nil
}

func (x *mqlHttpHeaderContentType) id() (string, error) {
	var id strings.Builder
	id.WriteString(x.Type.Data)
	if x.Params.Data != nil {
		keys := sortx.Keys(x.Params.Data)
		for _, key := range keys {
			id.WriteByte(';')
			id.WriteString(key)
			id.WriteByte('=')
			id.WriteString(x.Params.Data[key].(string))
		}
	}
	return id.String(), nil
}

// parseSetCookieDirectives parses a single Set-Cookie header value. Each header
// carries exactly one cookie, so this takes one value rather than the whole
// list: parsing several at once folds the later cookies' name=value pairs into
// this cookie's attribute map.
func parseSetCookieDirectives(raw any) (name *llx.RawData, value *llx.RawData, params *llx.RawData) {
	name, value, params = llx.NilData, llx.NilData, llx.NilData

	header, ok := raw.(string)
	if !ok {
		return name, value, params
	}

	for i, field := range strings.Split(header, ";") {
		key, val, hasValue := strings.Cut(strings.TrimSpace(field), "=")

		// RFC 6265 section 5.2: the first field is the cookie's name and value,
		// and every field after it is an attribute. Position is what decides
		// this, not whether a value is present - a cookie cleared by setting it
		// to the empty string is still that cookie, and reading it as an
		// attribute shifts every following attribute onto the wrong key.
		if i == 0 {
			// No "=" at all is not a name-value pair, so the header sets no
			// cookie; a browser discards the whole thing.
			if hasValue {
				name, value = llx.StringData(key), llx.StringData(val)
			}
			continue
		}

		// Attribute names are case-insensitive; their values keep their casing.
		if params.Value == nil {
			params = llx.MapData(map[string]any{}, types.String)
		}
		params.Value.(map[string]any)[strings.ToLower(key)] = val
	}

	return name, value, params
}

// setCookieValues returns the raw Set-Cookie header values, one per cookie.
func (x *mqlHttpHeader) setCookieValues() ([]any, bool) {
	raw, ok := x.Params.Data["Set-Cookie"]
	if !ok {
		return nil, false
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, false
	}
	return values, true
}

// newSetCookie builds the resource for one Set-Cookie header value.
func (x *mqlHttpHeader) newSetCookie(raw any) (*mqlHttpHeaderSetCookie, error) {
	cname, cval, params := parseSetCookieDirectives(raw)

	o, err := CreateResource(x.MqlRuntime, "http.header.setCookie", map[string]*llx.RawData{
		"name":   cname,
		"value":  cval,
		"params": params,
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlHttpHeaderSetCookie), nil
}

// Deprecated: use setCookies, which reports every cookie the response sets.
func (x *mqlHttpHeader) setCookie() (*mqlHttpHeaderSetCookie, error) {
	values, ok := x.setCookieValues()
	if !ok {
		x.SetCookie.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return x.newSetCookie(values[0])
}

func (x *mqlHttpHeader) setCookies() ([]any, error) {
	values, ok := x.setCookieValues()
	if !ok {
		x.SetCookies.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(values))
	for i := range values {
		cookie, err := x.newSetCookie(values[i])
		if err != nil {
			return nil, err
		}
		res = append(res, cookie)
	}

	return res, nil
}

func parseCspDirectives(raw []any) map[string]any {
	m := map[string]any{}
	parseHeaderFieldsD(raw, func(key string, value string) {
		// CSP3: directive names are ASCII case-insensitive; their values
		// keep their casing
		m[strings.ToLower(key)] = value
	}, ";", " ")
	return m
}

func (x *mqlHttpHeader) csp() (map[string]any, error) {
	raw, ok := x.Params.Data["Content-Security-Policy"]
	if !ok {
		x.Csp.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return parseCspDirectives(raw.([]any)), nil
}

func (x *mqlHttpHeaderSetCookie) id() (string, error) {
	// cookies may be very long, so it's more efficient to checksum them
	res := checksums.New.Add(x.Name.Data).Add(x.Value.Data)
	if x.Params.Data != nil {
		keys := sortx.Keys(x.Params.Data)
		for _, key := range keys {
			res = res.
				Add(key).
				Add(x.Params.Data[key].(string))
		}
	}
	return res.String(), nil
}

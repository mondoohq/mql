// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// jlsCommand lists every parameter of every running jail. jls needs no
// privileges for this, and -v has no libxo output at all.
const jlsCommand = "jls -n --libxo json"

// jailRecord is one jail from the output of jlsCommand.
type jailRecord struct {
	jid           int64
	parentJid     int64
	name          string
	hostname      string
	path          string
	osRelease     string
	securelevel   *int64
	enforceStatfs *int64
	childrenMax   *int64
	devfsRuleset  *int64
	persist       bool
	vnet          *bool
	ip4           string
	ip4Addresses  []string
	ip6           string
	ip6Addresses  []string
	allow         []string
	parameters    map[string]string
}

// parseJls decodes the output of jlsCommand. A jail without a jid or a name
// is skipped.
func parseJls(r io.Reader) ([]jailRecord, error) {
	var out struct {
		Info struct {
			Jails []map[string]any `json:"jail"`
		} `json:"jail-information"`
	}
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, errors.New("could not parse jls output: " + err.Error())
	}

	res := make([]jailRecord, 0, len(out.Info.Jails))
	for _, params := range out.Info.Jails {
		jid := jlsInt(params["jid"])
		name := jlsString(params["name"])
		if jid == nil || name == "" {
			continue
		}

		rec := jailRecord{
			jid:           *jid,
			name:          name,
			hostname:      jlsString(params["host.hostname"]),
			path:          jlsString(params["path"]),
			osRelease:     jlsString(params["osrelease"]),
			securelevel:   jlsInt(params["securelevel"]),
			enforceStatfs: jlsInt(params["enforce_statfs"]),
			childrenMax:   jlsInt(params["children.max"]),
			devfsRuleset:  jlsInt(params["devfs_ruleset"]),
			persist:       params["persist"] == true,
			ip4Addresses:  jlsStrings(params["ip4.addr"]),
			ip6Addresses:  jlsStrings(params["ip6.addr"]),
			allow:         []string{},
			parameters:    make(map[string]string, len(params)),
		}
		if parent := jlsInt(params["parent"]); parent != nil {
			rec.parentJid = *parent
		}
		if v, ok := params["vnet"]; ok {
			vnet := jlsString(v) == "new"
			rec.vnet = &vnet
		}
		rec.ip4 = jailIPMode(jlsString(params["ip4"]), rec.ip4Addresses)
		rec.ip6 = jailIPMode(jlsString(params["ip6"]), rec.ip6Addresses)

		for k, v := range params {
			rec.parameters[k] = jlsString(v)
			if perm, ok := strings.CutPrefix(k, "allow."); ok && v == true {
				rec.allow = append(rec.allow, perm)
			}
		}
		slices.Sort(rec.allow)

		res = append(res, rec)
	}
	return res, nil
}

// jailIPMode returns the IPv4 or IPv6 mode of a jail. The kernel reports
// `disable` for a jail that is restricted to its own addresses, so a jail
// with addresses is reported as `new`.
func jailIPMode(mode string, addrs []string) string {
	if len(addrs) > 0 {
		return "new"
	}
	return mode
}

// jlsString renders a libxo value as jls -n prints it in text form, except
// that booleans read true or false and lists are comma-separated.
func jlsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		return strings.Join(jlsStrings(x), ",")
	default:
		return ""
	}
}

func jlsStrings(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return []string{}
	}
	res := make([]string, 0, len(list))
	for _, e := range list {
		if s := jlsString(e); s != "" {
			res = append(res, s)
		}
	}
	return res
}

// jlsInt reads a number, which jls -n prints as a string. Anything else is nil.
func jlsInt(v any) *int64 {
	var i int64
	switch x := v.(type) {
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return nil
		}
		i = n
	case float64:
		i = int64(x)
	default:
		return nil
	}
	return &i
}

func (j *mqlJails) list() ([]any, error) {
	conn := j.MqlRuntime.Connection.(shared.Connection)
	if pf := conn.Asset().GetPlatform(); pf == nil || pf.Name != "freebsd" {
		return nil, llx.NotApplicable(errors.New("jails are only available on FreeBSD"))
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("jails need a running system, and this connection cannot run commands"))
	}

	cmd, err := runSbinCommand(j.MqlRuntime, jlsCommand)
	if err != nil {
		return nil, err
	}
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return nil, exit.Error
	} else if exit.Data != 0 {
		return nil, errors.New("could not list jails: " + cmd.GetStderr().Data)
	}

	records, err := parseJls(strings.NewReader(cmd.GetStdout().Data))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for _, rec := range records {
		o, err := CreateResource(j.MqlRuntime, ResourceJail, map[string]*llx.RawData{
			"__id":          llx.StringData(rec.name),
			"jid":           llx.IntData(rec.jid),
			"name":          llx.StringData(rec.name),
			"hostname":      llx.StringData(rec.hostname),
			"path":          llx.StringData(rec.path),
			"osRelease":     llx.StringData(rec.osRelease),
			"securelevel":   llx.IntDataPtr(rec.securelevel),
			"enforceStatfs": llx.IntDataPtr(rec.enforceStatfs),
			"childrenMax":   llx.IntDataPtr(rec.childrenMax),
			"devfsRuleset":  llx.IntDataPtr(rec.devfsRuleset),
			"persist":       llx.BoolData(rec.persist),
			"vnet":          llx.BoolDataPtr(rec.vnet),
			"ip4":           llx.StringData(rec.ip4),
			"ip4Addresses":  llx.ArrayData(llx.TArr2Raw(rec.ip4Addresses), types.String),
			"ip6":           llx.StringData(rec.ip6),
			"ip6Addresses":  llx.ArrayData(llx.TArr2Raw(rec.ip6Addresses), types.String),
			"allow":         llx.ArrayData(llx.TArr2Raw(rec.allow), types.String),
			"parameters":    llx.MapData(llx.TMap2Raw(rec.parameters), types.String),
		})
		if err != nil {
			return nil, err
		}
		o.(*mqlJail).parentJid = rec.parentJid
		res = append(res, o)
	}
	return res, nil
}

type mqlJailInternal struct {
	parentJid int64
}

func initJail(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("jail requires a name")
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'name' in jail initialization, it must be a string")
	}

	match, err := findJail(runtime, func(j *mqlJail) bool { return j.Name.Data == name })
	if err != nil {
		return nil, nil, err
	}
	if match == nil {
		return nil, nil, errors.New("jail not found: " + name)
	}
	return nil, match, nil
}

func findJail(runtime *plugin.Runtime, match func(*mqlJail) bool) (*mqlJail, error) {
	obj, err := CreateResource(runtime, ResourceJails, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := obj.(*mqlJails).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		if j := x.(*mqlJail); match(j) {
			return j, nil
		}
	}
	return nil, nil
}

func (j *mqlJail) parent() (*mqlJail, error) {
	if j.parentJid == 0 {
		j.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := findJail(j.MqlRuntime, func(p *mqlJail) bool { return p.Jid.Data == j.parentJid })
	if err != nil {
		return nil, err
	}
	if parent == nil {
		j.Parent.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return parent, nil
}

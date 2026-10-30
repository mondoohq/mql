// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func initUrl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if raws, ok := args["raw"]; ok {
		s := raws.Value.(string)
		delete(args, "raw")

		u, err := url.Parse(s)
		if err != nil {
			return nil, nil, errors.New("failed to parse url: " + err.Error())
		}

		if u.Scheme != "" || args["scheme"] == nil {
			args["scheme"] = llx.StringData(u.Scheme)
		}

		name := u.User.Username()
		if name != "" || args["user"] == nil {
			args["user"] = llx.StringData(name)
		}

		pass, _ := u.User.Password()
		if pass != "" || args["pass"] == nil {
			args["password"] = llx.StringData(pass)
		}

		host := strings.SplitN(u.Host, ":", 2)
		if host[0] != "" || args["host"] == nil {
			args["host"] = llx.StringData(host[0])
		}

		var port int
		if len(host) != 1 {
			port, err = strconv.Atoi(host[1])
			if err != nil {
				return nil, nil, errors.New("invalid port for url: " + s)
			}
		}
		if port != 0 || args["port"] == nil {
			args["port"] = llx.IntData(int64(port))
		}

		if u.Path != "" || args["path"] == nil {
			args["path"] = llx.StringData(u.Path)
		}

		if u.RawQuery != "" || args["rawQuery"] == nil {
			args["rawQuery"] = llx.StringData(u.RawQuery)
		}

		// query was never populated here at all, so every read of it reached the
		// runtime unset and surfaced as a provider bug rather than as a value.
		//
		// A query string may repeat a key; the field is a map, so it cannot hold
		// both. The first occurrence wins, which is what url.Values.Get returns
		// and what most servers read.
		query := map[string]any{}
		for key, values := range u.Query() {
			if len(values) != 0 {
				query[key] = values[0]
			}
		}
		if len(query) != 0 || args["query"] == nil {
			args["query"] = llx.MapData(query, types.String)
		}

		// RawFragment is only filled in when the fragment carries escaping that
		// differs from the canonical encoding, so an ordinary "#section" left it
		// empty and the fragment was reported as absent. Fall back to the decoded
		// form, which is what the URL carried.
		rawFragment := u.RawFragment
		if rawFragment == "" {
			rawFragment = u.Fragment
		}
		if rawFragment != "" || args["rawFragment"] == nil {
			args["rawFragment"] = llx.StringData(rawFragment)
		}
	}
	return args, nil, nil
}

func (x *mqlUrl) id() (string, error) {
	s := x.GetString()
	return s.Data, s.Error
}

func (x *mqlUrl) string() (string, error) {
	var user *url.Userinfo
	if x.Password.Data != "" {
		user = url.UserPassword(x.User.Data, x.Password.Data)
	} else if x.User.Data != "" {
		user = url.User(x.User.Data)
	}

	host := x.Host.Data
	isStandardPort := x.Port.Data == 80 && x.Scheme.Data == "http" || x.Port.Data == 443 && x.Scheme.Data == "https"
	if x.Port.Data != 0 && !isStandardPort {
		host += ":" + strconv.Itoa(int(x.Port.Data))
	}

	// URL.String renders the fragment from Fragment, escaping it, and uses
	// RawFragment only when it is a valid encoding of that same value. Setting
	// RawFragment alone therefore dropped the fragment from the round trip
	// entirely. Supply both: the decoded form for the value, and the raw form so
	// a fragment that was escaped unusually comes back out as it went in.
	fragment, err := url.PathUnescape(x.RawFragment.Data)
	if err != nil {
		fragment = x.RawFragment.Data
	}

	u := url.URL{
		Scheme:      x.Scheme.Data,
		User:        user,
		Host:        host,
		Path:        x.Path.Data,
		RawQuery:    x.RawQuery.Data,
		Fragment:    fragment,
		RawFragment: x.RawFragment.Data,
	}
	return u.String(), nil
}

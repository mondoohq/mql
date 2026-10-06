// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/loginconf"
	"go.mondoo.com/mql/types"
)

const defaultLoginConfPath = "/etc/login.conf"

type mqlLoginconfInternal struct {
	lock    sync.Mutex
	db      *loginconf.Database
	classes map[*loginconf.Record]*mqlLoginconfClass
}

type mqlLoginconfClassInternal struct {
	parent *mqlLoginconf
	record *loginconf.Record
}

func initLoginconf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFileArg(runtime, "loginconf", args)
}

func (l *mqlLoginconf) id() (string, error) {
	f := l.GetFile()
	if f.Error != nil {
		return "", f.Error
	}
	if f.Data == nil {
		return "", errors.New("no file for loginconf")
	}
	return f.Data.Path.Data, nil
}

func (l *mqlLoginconf) file() (*mqlFile, error) {
	f, err := CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultLoginConfPath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (l *mqlLoginconf) list(file *mqlFile) ([]any, error) {
	content, err := readSystemFile(file, "")
	if err != nil {
		return nil, err
	}
	path := file.Path.Data
	db, err := loginconf.Parse(strings.NewReader(content))
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", path, err))
	}

	l.lock.Lock()
	defer l.lock.Unlock()
	l.db = db
	l.classes = map[*loginconf.Record]*mqlLoginconfClass{}

	res := []any{}
	for _, rec := range db.Records {
		// A record whose name an earlier record already answers to is never
		// reached by a lookup, as in getcap(3).
		if db.Lookup(rec.Name()) != rec {
			log.Warn().Str("file", path).Str("class", rec.Name()).Msg("loginconf> skipping a class that an earlier record with the same name hides")
			continue
		}
		aliases := []any{}
		for _, a := range rec.Aliases() {
			aliases = append(aliases, a)
		}
		o, err := CreateResource(l.MqlRuntime, "loginconf.class", map[string]*llx.RawData{
			"__id":         llx.StringData(path + "\x00" + rec.Name()),
			"name":         llx.StringData(rec.Name()),
			"aliases":      llx.ArrayData(aliases, types.String),
			"capabilities": llx.DictData(rec.Own()),
		})
		if err != nil {
			return nil, err
		}
		c := o.(*mqlLoginconfClass)
		c.parent = l
		c.record = rec
		l.classes[rec] = c
		res = append(res, c)
	}
	return res, nil
}

// lookup returns the class a getcap lookup of name reaches, matching aliases
// too, or nil. The list must have been loaded.
func (l *mqlLoginconf) lookup(name string) *mqlLoginconfClass {
	l.lock.Lock()
	defer l.lock.Unlock()
	rec := l.db.Lookup(name)
	if rec == nil {
		return nil
	}
	return l.classes[rec]
}

func initLoginconfClass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	rawName, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, ok := rawName.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'name' in loginconf.class initialization, it must be a string")
	}

	raw, err := CreateResource(runtime, "loginconf", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	lc := raw.(*mqlLoginconf)
	if list := lc.GetList(); list.Error != nil {
		return nil, nil, list.Error
	}
	if c := lc.lookup(name); c != nil {
		return nil, c, nil
	}
	return nil, nil, llx.NotFound(fmt.Errorf("login class %q is not defined in %s", name, defaultLoginConfPath))
}

func (c *mqlLoginconfClass) inherits() ([]any, error) {
	if c.record == nil || c.parent == nil {
		return nil, errors.New("loginconf.class has no parsed record")
	}
	res := []any{}
	for _, name := range c.record.Inherits() {
		target := c.parent.lookup(name)
		if target == nil {
			return nil, llx.MalformedData(fmt.Errorf("class %q: cannot resolve tc=%s", c.record.Name(), name))
		}
		res = append(res, target)
	}
	return res, nil
}

func (c *mqlLoginconfClass) effective() (any, error) {
	if c.record == nil || c.parent == nil {
		return nil, errors.New("loginconf.class has no parsed record")
	}
	c.parent.lock.Lock()
	db := c.parent.db
	c.parent.lock.Unlock()
	caps, err := db.Effective(c.record)
	if err != nil {
		return nil, llx.MalformedData(err)
	}
	return caps, nil
}

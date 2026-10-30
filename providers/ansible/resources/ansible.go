// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ansible/connection"
	"go.mondoo.com/mql/providers/ansible/play"
	"go.mondoo.com/mql/types"
)

func (r *mqlAnsible) id() (string, error) {
	return "ansible", nil
}

func (r *mqlAnsible) plays() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AnsibleConnection)
	return newMqlAnsiblePlays(r.MqlRuntime, "", conn.BaseDir(), conn.Playbook())
}

func newMqlAnsiblePlays(runtime *plugin.Runtime, parentID, baseDir string, playbook play.Playbook) ([]any, error) {
	plays := make([]any, 0, len(playbook))
	for i, p := range playbook {
		id := parentID + "play[" + strconv.Itoa(i) + "]"
		mqlPlay, err := newMqlAnsiblePlay(runtime, id, baseDir, p)
		if err != nil {
			return nil, err
		}
		plays = append(plays, mqlPlay)
	}
	return plays, nil
}

func newMqlAnsiblePlay(runtime *plugin.Runtime, id, baseDir string, p *play.Play) (*mqlAnsiblePlay, error) {
	res, err := CreateResource(runtime, "ansible.play", map[string]*llx.RawData{
		"__id":              llx.StringData(id),
		"name":              llx.StringData(p.Name),
		"hosts":             dictData(p.Hosts),
		"remoteUser":        llx.StringData(p.RemoteUser),
		"become":            llx.BoolData(p.Become),
		"becomeUser":        llx.StringData(p.BecomeUser),
		"becomeMethod":      llx.StringData(p.BecomeMethod),
		"becomeFlags":       llx.StringData(p.BecomeFlags),
		"serial":            dictData(p.Serial),
		"strategy":          llx.StringData(p.Strategy),
		"maxFailPercentage": llx.IntData(p.MaxFailPercentageValue()),
		"ignoreUnreachable": llx.BoolData(p.IgnoreUnreachable),
		"anyErrorsFatal":    llx.BoolData(p.AnyErrorsFatal),
		"gatherFacts":       llx.StringData(p.GatherFacts),
		"vars":              dictMapData(p.Vars),
		"tags":              llx.ArrayData(convert.SliceAnyToInterface(p.Tags), types.String),
		"roles":             llx.ArrayData(convert.SliceAnyToInterface(p.RoleNames()), types.String),
		"varsFiles":         llx.ArrayData(convert.SliceAnyToInterface(p.VarsFiles), types.String),
		"varsPrompt":        llx.ArrayData(dictSlice(p.VarsPrompt), types.Dict),
		"environment":       dictMapData(p.Environment),
		"collections":       llx.ArrayData(convert.SliceAnyToInterface(p.Collections), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlPlay := res.(*mqlAnsiblePlay)
	mqlPlay.play = p
	mqlPlay.baseDir = baseDir
	return mqlPlay, nil
}

type mqlAnsiblePlayInternal struct {
	play    *play.Play
	baseDir string
}

// roleApplications exposes how the play applies each role — the application
// directives (when, tags, vars) and the resolved role. Standalone playbook
// files resolve the role to null.
func (r *mqlAnsiblePlay) roleApplications() ([]any, error) {
	if r.play == nil {
		return []any{}, nil
	}
	apps := r.play.RoleApplications()
	out := make([]any, 0, len(apps))
	for i, app := range apps {
		id := r.MqlID() + "/roleApplication[" + strconv.Itoa(i) + "]"
		res, err := CreateResource(r.MqlRuntime, "ansible.play.roleApplication", map[string]*llx.RawData{
			"__id": llx.StringData(id),
			"name": llx.StringData(app.Name),
			"when": llx.StringData(app.When),
			"tags": llx.ArrayData(convert.SliceAnyToInterface(app.Tags), types.String),
			"vars": dictMapData(app.Vars),
		})
		if err != nil {
			return nil, err
		}
		mqlApp := res.(*mqlAnsiblePlayRoleApplication)
		mqlApp.roleName = app.Name
		out = append(out, mqlApp)
	}
	return out, nil
}

type mqlAnsiblePlayRoleApplicationInternal struct {
	roleName string
}

func (r *mqlAnsiblePlayRoleApplication) role() (*mqlAnsibleRole, error) {
	proj := ansibleProject(r.MqlRuntime)
	if proj == nil {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role := proj.RoleByName(r.roleName)
	if role == nil {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlAnsibleRole(r.MqlRuntime, role)
}

// dictSlice converts a slice of maps to a []any of normalized dicts for
// llx.ArrayData.
func dictSlice(items []map[string]any) []any {
	out := make([]any, len(items))
	for i, m := range items {
		out[i] = normalizeDict(m)
	}
	return out
}

func newMqlAnsibleHandler(runtime *plugin.Runtime, id string, handler *play.Handler) (*mqlAnsibleHandler, error) {
	res, err := CreateResource(runtime, "ansible.handler", map[string]*llx.RawData{
		"__id":   llx.StringData(id),
		"name":   llx.StringData(handler.Name),
		"action": dictData(handler.Action),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAnsibleHandler), nil
}

func newMqlAnsibleHandlers(runtime *plugin.Runtime, parentID string, handlers []*play.Handler) ([]any, error) {
	mqlHandlers := make([]any, 0, len(handlers))
	for i, h := range handlers {
		id := parentID + "/handlers[" + strconv.Itoa(i) + "]"
		mqlHandler, err := newMqlAnsibleHandler(runtime, id, h)
		if err != nil {
			return nil, err
		}
		mqlHandlers = append(mqlHandlers, mqlHandler)
	}
	return mqlHandlers, nil
}

func (r *mqlAnsiblePlay) handlers() ([]any, error) {
	if r.play == nil {
		return []any{}, nil
	}
	return newMqlAnsibleHandlers(r.MqlRuntime, r.MqlID(), r.play.Handlers)
}

func newMqlAnsibleTask(runtime *plugin.Runtime, id, baseDir string, task *play.Task) (*mqlAnsibleTask, error) {
	res, err := CreateResource(runtime, "ansible.task", map[string]*llx.RawData{
		"__id":            llx.StringData(id),
		"name":            llx.StringData(task.Name),
		"action":          dictData(task.Action),
		"vars":            dictMapData(task.Vars),
		"tags":            llx.ArrayData(convert.SliceAnyToInterface(task.Tags), types.String),
		"register":        llx.StringData(task.Register),
		"become":          llx.BoolData(task.Become),
		"becomeUser":      llx.StringData(task.BecomeUser),
		"becomeMethod":    llx.StringData(task.BecomeMethod),
		"becomeFlags":     llx.StringData(task.BecomeFlags),
		"delegateTo":      llx.StringData(task.DelegateTo),
		"environment":     dictMapData(task.Environment),
		"noLog":           dictData(task.NoLog),
		"ignoreErrors":    dictData(task.IgnoreErrors),
		"runOnce":         dictData(task.RunOnce),
		"when":            llx.StringData(task.When),
		"failedWhen":      llx.StringData(task.FailedWhen),
		"changedWhen":     llx.StringData(task.ChangedWhen),
		"notify":          llx.ArrayData(convert.SliceAnyToInterface(task.Notify), types.String),
		"loop":            dictData(task.Loop),
		"loopControl":     dictData(task.LoopControl),
		"importPlaybook":  llx.StringData(task.ImportPlaybook),
		"includePlaybook": llx.StringData(task.IncludePlaybook),
		"importTasks":     llx.StringData(task.ImportTasks),
		"includeTasks":    llx.StringData(task.IncludeTasks),
	})
	if err != nil {
		return nil, err
	}
	mqlTask := res.(*mqlAnsibleTask)
	mqlTask.task = task
	mqlTask.baseDir = baseDir
	return mqlTask, nil
}

func newMqlAnsibleTasks(runtime *plugin.Runtime, parentID, group, baseDir string, tasks []*play.Task) ([]any, error) {
	mqlTasks := make([]any, 0, len(tasks))
	for i, t := range tasks {
		id := parentID + "/" + group + "[" + strconv.Itoa(i) + "]"
		mqlTask, err := newMqlAnsibleTask(runtime, id, baseDir, t)
		if err != nil {
			return nil, err
		}
		mqlTasks = append(mqlTasks, mqlTask)
	}
	return mqlTasks, nil
}

type mqlAnsibleTaskInternal struct {
	task    *play.Task
	baseDir string
}

func (r *mqlAnsibleTask) module() (string, error) {
	if r.task == nil {
		return "", nil
	}
	return r.task.Module(), nil
}

func (r *mqlAnsibleTask) moduleArgs() (any, error) {
	if r.task == nil {
		return nil, nil
	}
	return normalizeDict(r.task.ModuleArgs()), nil
}

func (r *mqlAnsiblePlay) preTasks() ([]any, error) {
	if r.play == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "preTasks", r.baseDir, r.play.PreTasks)
}

func (r *mqlAnsiblePlay) tasks() ([]any, error) {
	if r.play == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "tasks", r.baseDir, r.play.Tasks)
}

func (r *mqlAnsiblePlay) postTasks() ([]any, error) {
	if r.play == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "postTasks", r.baseDir, r.play.PostTasks)
}

func (r *mqlAnsibleTask) block() ([]any, error) {
	if r.task == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "block", r.baseDir, r.task.Block)
}

func (r *mqlAnsibleTask) rescue() ([]any, error) {
	if r.task == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "rescue", r.baseDir, r.task.Rescue)
}

func (r *mqlAnsibleTask) always() ([]any, error) {
	if r.task == nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "always", r.baseDir, r.task.Always)
}

// importedTasks resolves a literal import_tasks / include_tasks reference to the
// parsed tasks of the target file. A Jinja2-templated or unresolvable path
// yields an empty list; the raw string fields remain authoritative.
func (r *mqlAnsibleTask) importedTasks() ([]any, error) {
	if r.task == nil {
		return []any{}, nil
	}
	ref := firstNonEmpty(r.task.ImportTasks, r.task.IncludeTasks)
	path := r.resolveRef(ref)
	if path == "" {
		return []any{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []any{}, nil
	}
	tasks, err := play.DecodeTaskList(data)
	if err != nil {
		return []any{}, nil
	}
	return newMqlAnsibleTasks(r.MqlRuntime, r.MqlID(), "importedTasks", filepath.Dir(path), tasks)
}

// importedPlaybook resolves a literal import_playbook / include_playbook
// reference to the parsed playbook. A Jinja2-templated or unresolvable path
// yields null.
func (r *mqlAnsibleTask) importedPlaybook() (*mqlAnsiblePlaybook, error) {
	if r.task == nil {
		r.ImportedPlaybook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref := firstNonEmpty(r.task.ImportPlaybook, r.task.IncludePlaybook)
	path := r.resolveRef(ref)
	if path == "" {
		r.ImportedPlaybook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		r.ImportedPlaybook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	playbook, err := play.DecodePlaybook(data)
	if err != nil {
		r.ImportedPlaybook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlAnsiblePlaybook(r.MqlRuntime, path, playbook)
}

// resolveRef resolves a literal include/import reference to an absolute file
// path, contained within the analysis root.
func (r *mqlAnsibleTask) resolveRef(ref string) string {
	return resolveRefPath(r.baseDir, ansibleAnalysisRoot(r.MqlRuntime), ref)
}

// ansibleAnalysisRoot is the directory that include/import resolution is
// confined to: the project root in directory mode, or the connected playbook's
// directory in file mode.
func ansibleAnalysisRoot(runtime *plugin.Runtime) string {
	conn, ok := runtime.Connection.(*connection.AnsibleConnection)
	if !ok {
		return ""
	}
	return conn.BaseDir()
}

// resolveRefPath turns a literal include/import reference into an absolute file
// path confined to root. It returns "" for a reference that is empty, a Jinja2
// expression (which a static analyzer cannot follow), an absolute path, or any
// path that escapes root via `..` — preventing a crafted playbook from reading
// arbitrary files on the host (for example `import_tasks: /etc/shadow`).
func resolveRefPath(baseDir, root, ref string) string {
	if ref == "" || root == "" || strings.Contains(ref, "{{") || filepath.IsAbs(ref) {
		return ""
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(filepath.Join(baseDir, ref))
	if err != nil {
		return ""
	}
	if abs != absRoot && !strings.HasPrefix(abs, absRoot+string(os.PathSeparator)) {
		return ""
	}
	return abs
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// dictData wraps a YAML-decoded value as a dict RawData after normalizing it.
func dictData(v any) *llx.RawData {
	return llx.DictData(normalizeDict(v))
}

// dictMapData wraps a YAML-decoded map as a map[string]dict RawData, normalizing
// each value.
func dictMapData(m map[string]any) *llx.RawData {
	if m == nil {
		return llx.MapData(map[string]any(nil), types.Dict)
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = normalizeDict(v)
	}
	return llx.MapData(out, types.Dict)
}

// normalizeDict converts a YAML-decoded value into the subset of types the llx
// dict representation accepts. yaml.v3 decodes integers as Go `int`, which the
// dict-to-primitive conversion rejects, so numeric types are widened to int64 /
// float64 and containers are normalized recursively.
func normalizeDict(v any) any {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int8:
		return int64(x)
	case int16:
		return int64(x)
	case int32:
		return int64(x)
	case uint:
		if uint64(x) > math.MaxInt64 {
			return float64(x)
		}
		return int64(x)
	case uint8:
		return int64(x)
	case uint16:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		if x > math.MaxInt64 {
			return float64(x)
		}
		return int64(x)
	case float32:
		return float64(x)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeDict(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeDict(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalizeDict(val)
		}
		return out
	default:
		return v
	}
}

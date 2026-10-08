// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/linter"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/docker"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/ssh"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

func initDockerFile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// the dockerfile connection is a wrapper around the local one
	// NOTE: we might have to extend this in the future if we start supporting docker files from other connections (e.g. tar)
	_, isDockerConn := runtime.Connection.(*docker.DockerfileConnection)
	_, isSshConn := runtime.Connection.(*ssh.Connection)
	_, isLocalConn := runtime.Connection.(*local.LocalConnection)
	// if neither, we set the file to nil.
	if !isDockerConn && !isSshConn && !isLocalConn {
		return args, nil, nil
	}

	// if users supply a file, we don't have to run any fancy initialization,
	// since most of this function deals with trying to find the dockerfile
	if _, ok := args["file"]; ok {
		return args, nil, nil
	}

	var path string

	// init from path
	if rawPath, ok := args["path"]; ok {
		delete(args, "path")
		path, ok = rawPath.Value.(string)
		if !ok {
			return nil, nil, errors.New("path must be supplied as a string")
		}
	} else if dfc, ok := runtime.Connection.(*docker.DockerfileConnection); ok {
		path = dfc.FileAbsSrc
	}

	// we assume the default name for the dockerfile if it was not provided
	if path == "" {
		path = "Dockerfile"
	}

	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, nil, err
	}
	mqlFile, _ := raw.(*mqlFile)
	args["file"] = llx.ResourceData(mqlFile, "file")
	return args, nil, nil
}

type mqlDockerFileInternal struct {
	lock sync.Mutex
}

func (p *mqlDockerFile) id() (string, error) {
	if p.File.Data == nil {
		return "", errors.New("no file provided, can't determine ID for dockerfile")
	}
	return p.File.Data.id()
}

func (p *mqlDockerFile) file() (*mqlFile, error) {
	return nil, errors.New("missing underlying file, please specify a path of file")
}

func (p *mqlDockerFile) parse(file *mqlFile) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	setError := func(err error) error {
		p.Instructions.Error = err
		p.Stages.Error = err
		p.Directives.Error = err
		p.MultiStage.Error = err
		p.HasSyntaxDirective.Error = err
		p.FinalStage.Error = err
		return err
	}

	content := file.GetContent()
	if content.Error != nil {
		return setError(content.Error)
	}

	directives := map[string]any{}
	dp := parser.DirectiveParser{}
	parsed, derr := dp.ParseAll([]byte(content.Data))
	if derr == nil {
		for _, d := range parsed {
			directives[d.Name] = d.Value
		}
	}
	p.Directives = plugin.TValue[map[string]any]{
		Data:  directives,
		State: plugin.StateIsSet,
	}

	reader := strings.NewReader(content.Data)
	ast, err := parser.Parse(reader)
	if err != nil {
		return setError(multierr.Wrap(err, "failed to parse dockerfile "+file.Path.Data))
	}

	if ast.AST != nil {
		instructions := make([]any, len(ast.AST.Children))
		for i := range ast.AST.Children {
			node := ast.AST.Children[i]
			instructions[i] = map[string]any{
				"original": node.Original,
			}
		}
		p.Instructions = plugin.TValue[any]{
			Data:  instructions,
			State: plugin.StateIsSet,
		}
	} else {
		p.Instructions = plugin.TValue[any]{
			Data:  []any{},
			State: plugin.StateIsSet,
		}
	}

	parsedStages, meta, err := instructions.Parse(ast.AST, linter.New(&linter.Config{}))
	if err != nil {
		return setError(multierr.Wrap(err, "failed to parse dockerfile instructions in "+file.Path.Data))
	}
	eval := newDockerfileEval(ast.EscapeToken, meta)

	stages := make([]any, len(parsedStages))
	var stagesErr error
	for i := range parsedStages {
		stages[i], err = p.stage2resource(parsedStages[i], i == len(parsedStages)-1, eval)
		if err != nil {
			stagesErr = multierr.Wrap(err, "failed to parse stage in dockerfile "+file.Path.Data)
			break
		}
	}
	p.Stages = plugin.TValue[[]any]{
		Data:  stages,
		Error: stagesErr,
		State: plugin.StateIsSet,
	}

	p.MultiStage = plugin.TValue[bool]{
		Data:  len(stages) > 1,
		Error: stagesErr,
		State: plugin.StateIsSet,
	}
	_, hasSyntax := directives["syntax"]
	p.HasSyntaxDirective = plugin.TValue[bool]{
		Data:  hasSyntax,
		State: plugin.StateIsSet,
	}
	if stagesErr == nil && len(stages) > 0 {
		p.FinalStage = plugin.TValue[*mqlDockerFileStage]{
			Data:  stages[len(stages)-1].(*mqlDockerFileStage),
			State: plugin.StateIsSet,
		}
	} else {
		p.FinalStage = plugin.TValue[*mqlDockerFileStage]{
			Error: stagesErr,
			State: plugin.StateIsSet | plugin.StateIsNull,
		}
	}

	return nil
}

func (p *mqlDockerFile) stage2resource(stage instructions.Stage, isFinal bool, eval *dockerfileEval) (*mqlDockerFileStage, error) {
	st, baseName, platform := eval.startStage(stage)
	image, tag, digest := splitDockerfileBaseName(baseName)

	stageID := p.locationID(stage.Location)

	fromCtx, err := p.locationContext(stage.Location)
	if err != nil {
		return nil, err
	}
	rawFrom, err := CreateResource(p.MqlRuntime, ResourceDockerFileFrom, map[string]*llx.RawData{
		"__id":     llx.StringData(stageID),
		"platform": llx.StringData(platform),
		"image":    llx.StringData(image),
		"tag":      llx.StringData(tag),
		"digest":   llx.StringData(digest),
		"name":     llx.StringData(stage.Name),
		"context":  llx.ResourceData(fromCtx, "file.context"),
	})
	if err != nil {
		return nil, err
	}

	var env []any
	var arg []any
	labels := map[string]string{}
	var expose []any
	var runs []any
	var copy []any
	var add []any
	var volumes []any
	var workdir []any
	var onbuild []any
	var unsupported []string
	var entrypointRaw *instructions.EntrypointCommand
	var cmdRaw *instructions.CmdCommand
	var userRaw *instructions.UserCommand
	var userValue, groupValue string
	var userIsRoot bool
	var exposeErr error
	var healthcheckRaw *instructions.HealthCheckCommand
	var shellRaw *instructions.ShellCommand
	var stopsignalRaw *instructions.StopSignalCommand
	for i := range stage.Commands {
		switch v := stage.Commands[i].(type) {
		case *instructions.EnvCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			for j, kv := range v.Env {
				envResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileEnv, map[string]*llx.RawData{
					"__id":    llx.StringData(p.locationID(v.Location()) + "/" + strconv.Itoa(j)),
					"name":    llx.StringData(kv.Key),
					"value":   llx.StringData(st.env(kv)),
					"context": llx.ResourceData(ctx, "file.context"),
				})
				if err != nil {
					return nil, err
				}
				env = append(env, envResource)
			}
		case *instructions.ArgCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			for j, kv := range v.Args {
				argResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileArg, map[string]*llx.RawData{
					"__id":    llx.StringData(p.locationID(v.Location()) + "/" + strconv.Itoa(j)),
					"name":    llx.StringData(kv.Key),
					"default": llx.StringDataPtr(st.arg(kv)),
					"context": llx.ResourceData(ctx, "file.context"),
				})
				if err != nil {
					return nil, err
				}
				arg = append(arg, argResource)
			}
		case *instructions.LabelCommand:
			for _, kv := range v.Labels {
				labels[st.labelKey(kv.Key)] = kv.Value
			}
		case *instructions.UserCommand:
			userRaw = v
			userValue, groupValue, userIsRoot = st.user(v.User)

		case *instructions.RunCommand:
			script, argvs := runScript(v)
			mounts, err := p.mountResources(v)
			if err != nil {
				return nil, err
			}
			mountsSecret, mountsSsh := mountTypeFlags(mounts)
			commands, err := p.runCommandResources(p.locationID(v.Location()), argvs)
			if err != nil {
				return nil, err
			}
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			runResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileRun, map[string]*llx.RawData{
				"__id":         llx.StringData(p.locationID(v.Location())),
				"script":       llx.StringData(script),
				"mounts":       llx.ArrayData(mounts, types.Resource(ResourceDockerFileRunMount)),
				"network":      llx.StringData(runFlagValue(v, "network")),
				"security":     llx.StringData(runFlagValue(v, "security")),
				"isShellForm":  llx.BoolData(v.PrependShell),
				"isExecForm":   llx.BoolData(!v.PrependShell),
				"mountsSecret": llx.BoolData(mountsSecret),
				"mountsSsh":    llx.BoolData(mountsSsh),
				"commands":     llx.ArrayData(commands, types.Resource(ResourceDockerFileRunCommand)),
				"context":      llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			runs = append(runs, runResource)

		case *instructions.EntrypointCommand:
			entrypointRaw = v

		case *instructions.CmdCommand:
			cmdRaw = v

		case *instructions.CopyCommand:
			src := make([]any, len(v.SourcePaths))
			for i := range v.SourcePaths {
				src[i] = v.SourcePaths[i]
			}
			excludes := stringsToAny(v.ExcludePatterns)
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileCopy, map[string]*llx.RawData{
				"__id":     llx.StringData(p.locationID(v.Location())),
				"src":      llx.ArrayData(src, types.String),
				"dst":      llx.StringData(v.DestPath),
				"chown":    llx.StringData(v.Chown),
				"chmod":    llx.StringData(v.Chmod),
				"from":     llx.StringData(v.From),
				"link":     llx.BoolData(v.Link),
				"excludes": llx.ArrayData(excludes, types.String),
				"parents":  llx.BoolData(v.Parents),
				"context":  llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			copy = append(copy, resource)

		case *instructions.AddCommand:
			src := make([]any, len(v.SourcePaths))
			for i := range v.SourcePaths {
				src[i] = v.SourcePaths[i]
			}
			excludes := stringsToAny(v.ExcludePatterns)
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileAdd, map[string]*llx.RawData{
				"__id":     llx.StringData(p.locationID(v.Location())),
				"src":      llx.ArrayData(src, types.String),
				"dst":      llx.StringData(v.DestPath),
				"chown":    llx.StringData(v.Chown),
				"chmod":    llx.StringData(v.Chmod),
				"link":     llx.BoolData(v.Link),
				"checksum": llx.StringData(v.Checksum),
				"excludes": llx.ArrayData(excludes, types.String),
				"context":  llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			add = append(add, resource)

		case *instructions.ExposeCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			ports, err := st.expose(v.Ports)
			if err != nil {
				if exposeErr == nil {
					exposeErr = multierr.Wrap(err, "line "+strconv.Itoa(locationLine(v.Location())))
				}
				continue
			}
			for _, port := range ports {
				portStr := strconv.FormatInt(port.port, 10)
				id := p.locationID(v.Location()) + ":" + portStr + "/" + port.protocol

				resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileExpose, map[string]*llx.RawData{
					"__id":     llx.StringData(id),
					"port":     llx.IntData(port.port),
					"protocol": llx.StringData(port.protocol),
					"context":  llx.ResourceData(ctx, "file.context"),
				})
				if err != nil {
					return nil, err
				}
				expose = append(expose, resource)

			}

		case *instructions.HealthCheckCommand:
			healthcheckRaw = v

		case *instructions.VolumeCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			for _, vol := range v.Volumes {
				resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileVolume, map[string]*llx.RawData{
					"__id":    llx.StringData(p.locationID(v.Location()) + ":" + vol),
					"path":    llx.StringData(vol),
					"context": llx.ResourceData(ctx, "file.context"),
				})
				if err != nil {
					return nil, err
				}
				volumes = append(volumes, resource)
			}

		case *instructions.ShellCommand:
			shellRaw = v

		case *instructions.WorkdirCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileWorkdir, map[string]*llx.RawData{
				"__id":    llx.StringData(p.locationID(v.Location())),
				"path":    llx.StringData(v.Path),
				"context": llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			workdir = append(workdir, resource)

		case *instructions.StopSignalCommand:
			stopsignalRaw = v

		case *instructions.OnbuildCommand:
			ctx, err := p.locationContext(v.Location())
			if err != nil {
				return nil, err
			}
			resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileOnbuild, map[string]*llx.RawData{
				"__id":       llx.StringData(p.locationID(v.Location())),
				"expression": llx.StringData(v.Expression),
				"context":    llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			onbuild = append(onbuild, resource)

		default:
			cmd := stage.Commands[i]
			unsupported = append(unsupported, cmd.Name())
		}
	}

	if len(unsupported) != 0 {
		slices.Sort(unsupported)
		log.Debug().Strs("commands", slices.Compact(unsupported)).Msg("unsupported dockerfile commands")
	}

	runsAsRoot := st.parentRunsAsRoot
	if userRaw != nil {
		runsAsRoot = userIsRoot
	}

	args := map[string]*llx.RawData{
		"__id":           llx.StringData(stageID),
		"from":           llx.ResourceData(rawFrom, ResourceDockerFileFrom),
		"file":           llx.ResourceData(p, ResourceDockerFile),
		"env":            llx.ArrayData(env, types.Resource(ResourceDockerFileEnv)),
		"arg":            llx.ArrayData(arg, types.Resource(ResourceDockerFileArg)),
		"labels":         llx.MapData(llx.TMap2Raw(labels), types.String),
		"run":            llx.ArrayData(runs, types.Resource(ResourceDockerFileRun)),
		"add":            llx.ArrayData(add, types.Resource(ResourceDockerFileAdd)),
		"copy":           llx.ArrayData(copy, types.Resource(ResourceDockerFileCopy)),
		"expose":         llx.ArrayData(expose, types.Resource(ResourceDockerFileExpose)),
		"volumes":        llx.ArrayData(volumes, types.Resource(ResourceDockerFileVolume)),
		"workdir":        llx.ArrayData(workdir, types.Resource(ResourceDockerFileWorkdir)),
		"onbuild":        llx.ArrayData(onbuild, types.Resource(ResourceDockerFileOnbuild)),
		"runsAsRoot":     llx.BoolData(runsAsRoot),
		"hasHealthcheck": llx.BoolData(healthcheckRaw != nil && !isHealthcheckNone(healthcheckRaw)),
		"final":          llx.BoolData(isFinal),
	}

	if stopsignalRaw != nil {
		ctx, err := p.locationContext(stopsignalRaw.Location())
		if err != nil {
			return nil, err
		}
		stopResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileStopsignal, map[string]*llx.RawData{
			"__id":    llx.StringData(p.locationID(stopsignalRaw.Location())),
			"signal":  llx.StringData(stopsignalRaw.Signal),
			"context": llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["stopsignal"] = llx.ResourceData(stopResource, ResourceDockerFileStopsignal)
	} else {
		args["stopsignal"] = llx.NilData
	}

	if entrypointRaw != nil {
		script := strings.Join(entrypointRaw.CmdLine, "\n")
		commands, err := p.runCommandResources(p.locationID(entrypointRaw.Location()), cmdLineArgvs(entrypointRaw.CmdLine, !entrypointRaw.PrependShell))
		if err != nil {
			return nil, err
		}
		ctx, err := p.locationContext(entrypointRaw.Location())
		if err != nil {
			return nil, err
		}
		runResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileRun, map[string]*llx.RawData{
			"__id":         llx.StringData(p.locationID(entrypointRaw.Location())),
			"script":       llx.StringData(script),
			"mounts":       llx.ArrayData(nil, types.Resource(ResourceDockerFileRunMount)),
			"network":      llx.StringData(""),
			"security":     llx.StringData(""),
			"isShellForm":  llx.BoolData(entrypointRaw.PrependShell),
			"isExecForm":   llx.BoolData(!entrypointRaw.PrependShell),
			"mountsSecret": llx.BoolData(false),
			"mountsSsh":    llx.BoolData(false),
			"commands":     llx.ArrayData(commands, types.Resource(ResourceDockerFileRunCommand)),
			"context":      llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["entrypoint"] = llx.ResourceData(runResource, ResourceDockerFileRun)
	} else {
		args["entrypoint"] = llx.NilData
	}

	if cmdRaw != nil {
		script := strings.Join(cmdRaw.CmdLine, "\n")
		commands, err := p.runCommandResources(p.locationID(cmdRaw.Location()), cmdLineArgvs(cmdRaw.CmdLine, !cmdRaw.PrependShell))
		if err != nil {
			return nil, err
		}
		ctx, err := p.locationContext(cmdRaw.Location())
		if err != nil {
			return nil, err
		}
		cmdResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileRun, map[string]*llx.RawData{
			"__id":         llx.StringData(p.locationID(cmdRaw.Location())),
			"script":       llx.StringData(script),
			"mounts":       llx.ArrayData(nil, types.Resource(ResourceDockerFileRunMount)),
			"network":      llx.StringData(""),
			"security":     llx.StringData(""),
			"isShellForm":  llx.BoolData(cmdRaw.PrependShell),
			"isExecForm":   llx.BoolData(!cmdRaw.PrependShell),
			"mountsSecret": llx.BoolData(false),
			"mountsSsh":    llx.BoolData(false),
			"commands":     llx.ArrayData(commands, types.Resource(ResourceDockerFileRunCommand)),
			"context":      llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["cmd"] = llx.ResourceData(cmdResource, ResourceDockerFileRun)
	} else {
		args["cmd"] = llx.NilData
	}

	if userRaw != nil {
		ctx, err := p.locationContext(userRaw.Location())
		if err != nil {
			return nil, err
		}
		userResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileUser, map[string]*llx.RawData{
			"__id":    llx.StringData(p.locationID(userRaw.Location())),
			"user":    llx.StringData(userValue),
			"group":   llx.StringData(groupValue),
			"isRoot":  llx.BoolData(userIsRoot),
			"context": llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["user"] = llx.ResourceData(userResource, ResourceDockerFileUser)
	} else {
		args["user"] = llx.NilData
	}

	if healthcheckRaw != nil && healthcheckRaw.Health != nil {
		h := healthcheckRaw.Health
		isNone := isHealthcheckNone(healthcheckRaw)
		test := make([]any, len(h.Test))
		for i, t := range h.Test {
			test[i] = t
		}
		ctx, err := p.locationContext(healthcheckRaw.Location())
		if err != nil {
			return nil, err
		}
		hcResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileHealthcheck, map[string]*llx.RawData{
			"__id":          llx.StringData(p.locationID(healthcheckRaw.Location())),
			"test":          llx.ArrayData(test, types.String),
			"interval":      llx.IntData(int64(h.Interval)),
			"timeout":       llx.IntData(int64(h.Timeout)),
			"startPeriod":   llx.IntData(int64(h.StartPeriod)),
			"startInterval": llx.IntData(int64(h.StartInterval)),
			"retries":       llx.IntData(int64(h.Retries)),
			"none":          llx.BoolData(isNone),
			"context":       llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["healthcheck"] = llx.ResourceData(hcResource, ResourceDockerFileHealthcheck)
	} else {
		args["healthcheck"] = llx.NilData
	}

	if shellRaw != nil {
		shell := make([]any, len(shellRaw.Shell))
		for i, s := range shellRaw.Shell {
			shell[i] = s
		}
		ctx, err := p.locationContext(shellRaw.Location())
		if err != nil {
			return nil, err
		}
		shellResource, err := CreateResource(p.MqlRuntime, ResourceDockerFileShell, map[string]*llx.RawData{
			"__id":    llx.StringData(p.locationID(shellRaw.Location())),
			"command": llx.ArrayData(shell, types.String),
			"context": llx.ResourceData(ctx, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		args["shell"] = llx.ResourceData(shellResource, ResourceDockerFileShell)
	} else {
		args["shell"] = llx.NilData
	}

	ociResource, err := p.ociResource(stageID, labels)
	if err != nil {
		return nil, err
	}
	args["oci"] = llx.ResourceData(ociResource, ResourceDockerFileOci)

	rawStage, err := CreateResource(p.MqlRuntime, ResourceDockerFileStage, args)
	if err != nil {
		return nil, err
	}
	mqlStage := rawStage.(*mqlDockerFileStage)
	if exposeErr != nil {
		mqlStage.Expose = plugin.TValue[[]any]{Error: exposeErr, State: plugin.StateIsSet}
	}
	eval.finishStage(stage, st, runsAsRoot)

	return mqlStage, nil
}

// ociAnnotationFields maps a docker.file.oci field to its OpenContainer image
// annotation key (https://github.com/opencontainers/image-spec/blob/main/annotations.md).
var ociAnnotationFields = map[string]string{
	"created":       "org.opencontainers.image.created",
	"authors":       "org.opencontainers.image.authors",
	"url":           "org.opencontainers.image.url",
	"documentation": "org.opencontainers.image.documentation",
	"source":        "org.opencontainers.image.source",
	"version":       "org.opencontainers.image.version",
	"revision":      "org.opencontainers.image.revision",
	"vendor":        "org.opencontainers.image.vendor",
	"licenses":      "org.opencontainers.image.licenses",
	"refName":       "org.opencontainers.image.ref.name",
	"title":         "org.opencontainers.image.title",
	"description":   "org.opencontainers.image.description",
	"baseName":      "org.opencontainers.image.base.name",
	"baseDigest":    "org.opencontainers.image.base.digest",
}

// ociResource builds a docker.file.oci from a stage's LABEL map, surfacing the
// standard OpenContainer image annotations as named fields and collecting every
// org.opencontainers.* label into `all`. Values are unquoted for convenient
// consumption, unlike the verbatim stage `labels` map.
func (p *mqlDockerFile) ociResource(stageID string, labels map[string]string) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"__id": llx.StringData(stageID + "/oci"),
	}
	for field, annotation := range ociAnnotationFields {
		args[field] = llx.StringData(trimMatchingQuotes(labels[annotation]))
	}

	all := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, "org.opencontainers.") {
			all[k] = trimMatchingQuotes(v)
		}
	}
	args["all"] = llx.MapData(llx.TMap2Raw(all), types.String)

	return CreateResource(p.MqlRuntime, ResourceDockerFileOci, args)
}

// trimMatchingQuotes removes a single pair of matched surrounding double or
// single quotes from a LABEL value (e.g. `"mql"` -> `mql`). Values without a
// matched pair are returned unchanged.
func trimMatchingQuotes(s string) string {
	if len(s) >= 2 {
		if c := s[0]; (c == '"' || c == '\'') && s[len(s)-1] == c {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitDockerfileBaseName splits a FROM reference into image, tag and digest.
// The tag is what follows the last colon after the last slash: a colon before
// that belongs to a registry port (`localhost:5000/base` has no tag).
func splitDockerfileBaseName(baseName string) (image string, tag string, digest string) {
	image = baseName
	if before, after, ok := strings.Cut(image, "@"); ok {
		image = before
		digest = after
	}
	if idx := strings.LastIndex(image, ":"); idx > strings.LastIndex(image, "/") {
		tag = image[idx+1:]
		image = image[:idx]
	}
	return image, tag, digest
}

func (p *mqlDockerFile) locationID(location []parser.Range) string {
	var line int
	var char int
	if len(location) != 0 {
		line = location[0].Start.Line
		char = location[0].Start.Character
	}
	return "dockerfile/" + p.File.Data.Path.Data + "/" + strconv.FormatInt(int64(line), 10) + ":" + strconv.FormatInt(int64(char), 10)
}

// locationContext builds a file.context pointing at the source lines an
// instruction spans in the Dockerfile. The buildkit parser records line
// numbers only (no columns), so the range covers whole lines from the first
// to the last range reported for the instruction.
func (p *mqlDockerFile) locationContext(location []parser.Range) (*mqlFileContext, error) {
	rnge := llx.NewRange()
	if len(location) != 0 {
		start := uint32(location[0].Start.Line)
		end := uint32(location[len(location)-1].End.Line)
		rnge = rnge.AddLineRange(start, end)
	}

	cobj, err := CreateResource(p.MqlRuntime, "file.context", map[string]*llx.RawData{
		"file":  llx.ResourceData(p.File.Data, "file"),
		"range": llx.RangeData(rnge),
	})
	if err != nil {
		return nil, err
	}
	return cobj.(*mqlFileContext), nil
}

func (p *mqlDockerFile) instructions(file *mqlFile) (any, error) {
	return nil, p.parse(file)
}

func (p *mqlDockerFile) stages(file *mqlFile) ([]any, error) {
	return nil, p.parse(file)
}

func (p *mqlDockerFile) directives(file *mqlFile) (map[string]any, error) {
	return nil, p.parse(file)
}

func (p *mqlDockerFile) multiStage(file *mqlFile) (bool, error) {
	return false, p.parse(file)
}

func (p *mqlDockerFile) hasSyntaxDirective(file *mqlFile) (bool, error) {
	return false, p.parse(file)
}

func (p *mqlDockerFile) finalStage(file *mqlFile) (*mqlDockerFileStage, error) {
	return nil, p.parse(file)
}

// isRootUser reports whether the user part of a USER value is root. An empty
// user is root as well: it is what a USER set from an empty variable builds.
//
// It resolves the user the way the runtime does (moby/sys/user GetExecUser,
// used by runc and the engines): a value strconv.Atoi accepts is a UID, so
// `00`, `+0` and `-0` are root, and anything else is a name, matched exactly.
func isRootUser(user string) bool {
	if user == "" {
		return true
	}
	if uid, err := strconv.Atoi(user); err == nil {
		return uid == 0
	}
	return user == "root"
}

func locationLine(location []parser.Range) int {
	if len(location) == 0 {
		return 0
	}
	return location[0].Start.Line
}

// mountTypeFlags scans the parsed `--mount=...` entries on a RUN and reports
// whether any of them expose a build-time secret or ssh socket.
func mountTypeFlags(mounts []any) (secret bool, ssh bool) {
	for _, m := range mounts {
		rm, ok := m.(*mqlDockerFileRunMount)
		if !ok {
			continue
		}
		switch rm.Type.Data {
		case "secret":
			secret = true
		case "ssh":
			ssh = true
		}
	}
	return
}

// runFlagValue returns the parsed BuildKit value for `--network=...` or
// `--security=...`. Both default to a non-empty string when set explicitly;
// we surface them as empty strings when the flag wasn't used so audits can
// distinguish "default" (empty) from an explicit pin.
func runFlagValue(cmd *instructions.RunCommand, name string) string {
	for _, f := range cmd.FlagsUsed {
		if f != name {
			continue
		}
		switch name {
		case "network":
			return string(instructions.GetNetwork(cmd))
		case "security":
			return instructions.GetSecurity(cmd)
		}
	}
	return ""
}

// runCommandResources builds the parsed docker.file.run.command list for a
// RUN/CMD/ENTRYPOINT instruction from the argv of each of its commands.
func (p *mqlDockerFile) runCommandResources(parentID string, argvs [][]string) ([]any, error) {
	out := make([]any, 0, len(argvs))
	for i, argv := range argvs {
		if len(argv) == 0 {
			continue
		}
		cmdArgs := argv[1:]

		flags := []any{}
		subcommand := ""
		args := make([]any, len(cmdArgs))
		for j, a := range cmdArgs {
			args[j] = a
			if strings.HasPrefix(a, "-") {
				flags = append(flags, a)
			} else if subcommand == "" {
				subcommand = a
			}
		}

		resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileRunCommand, map[string]*llx.RawData{
			"__id":       llx.StringData(parentID + "/command/" + strconv.Itoa(i)),
			"binary":     llx.StringData(argv[0]),
			"subcommand": llx.StringData(subcommand),
			"flags":      llx.ArrayData(flags, types.String),
			"args":       llx.ArrayData(args, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, resource)
	}
	return out, nil
}

func (p *mqlDockerFile) mountResources(cmd *instructions.RunCommand) ([]any, error) {
	hasMount := false
	for _, f := range cmd.FlagsUsed {
		if f == "mount" {
			hasMount = true
			break
		}
	}
	if !hasMount {
		return nil, nil
	}
	// instructions.Parse defers mount field resolution until a variable
	// expander is supplied. We don't expand build args during static analysis,
	// so feed an identity expander to populate Type/Target/Source/etc.
	if err := cmd.Expand(func(s string) (string, error) { return s, nil }); err != nil {
		return nil, err
	}
	mounts := instructions.GetMounts(cmd)
	out := make([]any, 0, len(mounts))
	for i, m := range mounts {
		id := p.locationID(cmd.Location()) + "/mount/" + strconv.Itoa(i)
		var mode, uid, gid int64
		if m.Mode != nil {
			mode = int64(*m.Mode)
		}
		if m.UID != nil {
			uid = int64(*m.UID)
		}
		if m.GID != nil {
			gid = int64(*m.GID)
		}
		var env string
		if m.Env != nil {
			env = *m.Env
		}
		resource, err := CreateResource(p.MqlRuntime, ResourceDockerFileRunMount, map[string]*llx.RawData{
			"__id":      llx.StringData(id),
			"type":      llx.StringData(string(m.Type)),
			"target":    llx.StringData(m.Target),
			"source":    llx.StringData(m.Source),
			"from":      llx.StringData(m.From),
			"id":        llx.StringData(m.CacheID),
			"sharing":   llx.StringData(string(m.CacheSharing)),
			"readOnly":  llx.BoolData(m.ReadOnly),
			"required":  llx.BoolData(m.Required),
			"sizeLimit": llx.IntData(m.SizeLimit),
			"mode":      llx.IntData(mode),
			"uid":       llx.IntData(uid),
			"gid":       llx.IntData(gid),
			"env":       llx.StringData(env),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, resource)
	}
	return out, nil
}

// The context field is populated when each instruction resource is created in
// stage2resource, so these fallback resolvers only run if a resource was built
// without one (e.g. loaded from a recording that predates the field).
func (p *mqlDockerFileFrom) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.from")
}

func (p *mqlDockerFileEnv) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.env")
}

func (p *mqlDockerFileArg) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.arg")
}

func (p *mqlDockerFileRun) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.run")
}

func (p *mqlDockerFileCopy) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.copy")
}

func (p *mqlDockerFileAdd) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.add")
}

func (p *mqlDockerFileExpose) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.expose")
}

func (p *mqlDockerFileVolume) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.volume")
}

func (p *mqlDockerFileWorkdir) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.workdir")
}

func (p *mqlDockerFileOnbuild) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.onbuild")
}

func (p *mqlDockerFileUser) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.user")
}

func (p *mqlDockerFileHealthcheck) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.healthcheck")
}

// isHealthcheckNone reports whether a HEALTHCHECK instruction is the
// `HEALTHCHECK NONE` form, which disables any check inherited from the base
// image instead of defining one.
func isHealthcheckNone(hc *instructions.HealthCheckCommand) bool {
	return hc.Health != nil && len(hc.Health.Test) > 0 && hc.Health.Test[0] == "NONE"
}

func (p *mqlDockerFileShell) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.shell")
}

func (p *mqlDockerFileStopsignal) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for docker.file.stopsignal")
}

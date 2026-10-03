// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseDockerfile(t *testing.T) {
	cases := []struct {
		purpose           string
		subjectDockerFile string

		expectedLabels           map[string]any
		expectedEnv              func(r *plugin.Runtime) []any
		expectedArg              func(r *plugin.Runtime) []any
		expectedFromImage        string
		expectedFromTag          string
		expectedUser             plugin.TValue[*mqlDockerFileUser]
		expectedCmd              plugin.TValue[*mqlDockerFileRun]
		expectedEntrypoint       plugin.TValue[*mqlDockerFileRun]
		expectedRunStruct        []plugin.TValue[*mqlDockerFileRun]
		expectedCopyStruct       []plugin.TValue[*mqlDockerFileCopy]
		expectedAddStruct        []plugin.TValue[*mqlDockerFileAdd]
		expectedExposeStructArr  []plugin.TValue[*mqlDockerFileExpose]
		expectedHealthcheck      plugin.TValue[*mqlDockerFileHealthcheck]
		expectedVolumeStructArr  []plugin.TValue[*mqlDockerFileVolume]
		expectedShell            plugin.TValue[*mqlDockerFileShell]
		expectedWorkdirStructArr []plugin.TValue[*mqlDockerFileWorkdir]
	}{
		{
			purpose: "minimal instructions with CMD",
			subjectDockerFile: `
FROM alpine
CMD ["/bin/sh", "-c", "echo 'Hola'"]
`,
			expectedLabels:    map[string]any{},
			expectedEnv:       nil,
			expectedArg:       nil,
			expectedFromImage: "alpine",
			expectedCmd: plugin.TValue[*mqlDockerFileRun]{
				Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{Data: "/bin/sh\n-c\necho 'Hola'"},
				},
			},
		},
		{
			purpose: "without CMD but with ENTRYPOINT",
			subjectDockerFile: `
FROM debian:stable
ENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
`,
			expectedLabels:    map[string]any{},
			expectedEnv:       nil,
			expectedArg:       nil,
			expectedFromImage: "debian",
			expectedFromTag:   "stable",
			expectedEntrypoint: plugin.TValue[*mqlDockerFileRun]{
				Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{Data: "/usr/sbin/apache2ctl\n-D\nFOREGROUND"},
				},
			},
		},
		{
			purpose: "with all instructions",
			subjectDockerFile: `
FROM alpine:3.14
ARG foo=baz
ENV foo=bar
LABEL a=b
RUN apk add --no-cache curl
LABEL c=d
USER 1001:1001
CMD ["curl", "http://example.com"]
ENTRYPOINT ["sh"]
EXPOSE 80/udp
EXPOSE 8080
COPY /foo /bar
ADD /foo-add /bar-add
`,
			expectedLabels: map[string]any{
				"a": "b",
				"c": "d",
			},
			expectedEnv: func(r *plugin.Runtime) []any {
				return []any{
					&mqlDockerFileEnv{
						MqlRuntime: r,
						Name:       plugin.TValue[string]{Data: "foo", State: plugin.StateIsSet},
						Value:      plugin.TValue[string]{Data: "bar", State: plugin.StateIsSet},
					},
				}
			},
			expectedArg: func(r *plugin.Runtime) []any {
				return []any{
					&mqlDockerFileArg{
						MqlRuntime: r,
						Name:       plugin.TValue[string]{Data: "foo", State: plugin.StateIsSet},
						Default:    plugin.TValue[string]{Data: "baz", State: plugin.StateIsSet},
					},
				}
			},
			expectedFromImage: "alpine",
			expectedFromTag:   "3.14",
			expectedUser: plugin.TValue[*mqlDockerFileUser]{
				Data: &mqlDockerFileUser{
					User:  plugin.TValue[string]{Data: "1001"},
					Group: plugin.TValue[string]{Data: "1001"},
				},
			},
			expectedEntrypoint: plugin.TValue[*mqlDockerFileRun]{
				Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{Data: "sh"},
				},
			},
			expectedCmd: plugin.TValue[*mqlDockerFileRun]{
				Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{Data: "curl\nhttp://example.com"},
				},
			},
			expectedCopyStruct: []plugin.TValue[*mqlDockerFileCopy]{
				{Data: &mqlDockerFileCopy{
					Src: plugin.TValue[[]any]{
						Data: []any{"/foo"},
					},
					Dst: plugin.TValue[string]{
						Data: "/bar",
					},
				}},
			},
			expectedRunStruct: []plugin.TValue[*mqlDockerFileRun]{
				{Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{
						Data: "apk add --no-cache curl",
					},
				}},
			},
			expectedAddStruct: []plugin.TValue[*mqlDockerFileAdd]{
				{Data: &mqlDockerFileAdd{
					Src: plugin.TValue[[]any]{
						Data: []any{"/foo-add"},
					},
					Dst: plugin.TValue[string]{
						Data: "/bar-add",
					},
				}},
			},
			expectedExposeStructArr: []plugin.TValue[*mqlDockerFileExpose]{
				{Data: &mqlDockerFileExpose{
					Port:     plugin.TValue[int64]{Data: int64(80)},
					Protocol: plugin.TValue[string]{Data: "udp"},
				}},
				{Data: &mqlDockerFileExpose{
					Port:     plugin.TValue[int64]{Data: int64(8080)},
					Protocol: plugin.TValue[string]{Data: "tcp"}, // this is the default
				}},
			},
		},
		{
			purpose: "with HEALTHCHECK and VOLUME",
			subjectDockerFile: `
FROM alpine
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost/ || exit 1
VOLUME /data
VOLUME /var/log /tmp
`,
			expectedLabels:    map[string]any{},
			expectedFromImage: "alpine",
			expectedHealthcheck: plugin.TValue[*mqlDockerFileHealthcheck]{
				Data: &mqlDockerFileHealthcheck{
					Test:     plugin.TValue[[]any]{Data: []any{"CMD-SHELL", "curl -f http://localhost/ || exit 1"}},
					Interval: plugin.TValue[int64]{Data: int64(30000000000)},
					Timeout:  plugin.TValue[int64]{Data: int64(10000000000)},
					Retries:  plugin.TValue[int64]{Data: int64(3)},
					None:     plugin.TValue[bool]{Data: false},
				},
			},
			expectedVolumeStructArr: []plugin.TValue[*mqlDockerFileVolume]{
				{Data: &mqlDockerFileVolume{
					Path: plugin.TValue[string]{Data: "/data"},
				}},
				{Data: &mqlDockerFileVolume{
					Path: plugin.TValue[string]{Data: "/var/log"},
				}},
				{Data: &mqlDockerFileVolume{
					Path: plugin.TValue[string]{Data: "/tmp"},
				}},
			},
		},
		{
			purpose: "with HEALTHCHECK NONE",
			subjectDockerFile: `
FROM alpine
HEALTHCHECK NONE
`,
			expectedLabels:    map[string]any{},
			expectedFromImage: "alpine",
			expectedHealthcheck: plugin.TValue[*mqlDockerFileHealthcheck]{
				Data: &mqlDockerFileHealthcheck{
					Test: plugin.TValue[[]any]{Data: []any{"NONE"}},
					None: plugin.TValue[bool]{Data: true},
				},
			},
		},
		{
			purpose: "with SHELL and WORKDIR",
			subjectDockerFile: `
FROM alpine
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /app
WORKDIR /app/src
RUN echo hello | cat
`,
			expectedLabels:    map[string]any{},
			expectedFromImage: "alpine",
			expectedShell: plugin.TValue[*mqlDockerFileShell]{
				Data: &mqlDockerFileShell{
					Command: plugin.TValue[[]any]{Data: []any{"/bin/bash", "-o", "pipefail", "-c"}},
				},
			},
			expectedWorkdirStructArr: []plugin.TValue[*mqlDockerFileWorkdir]{
				{Data: &mqlDockerFileWorkdir{
					Path: plugin.TValue[string]{Data: "/app"},
				}},
				{Data: &mqlDockerFileWorkdir{
					Path: plugin.TValue[string]{Data: "/app/src"},
				}},
			},
			expectedRunStruct: []plugin.TValue[*mqlDockerFileRun]{
				{Data: &mqlDockerFileRun{
					Script: plugin.TValue[string]{Data: "echo hello | cat"},
				}},
			},
		},
	}

	for _, kase := range cases {
		t.Run(kase.purpose, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

			file := &mqlFile{
				Content:    plugin.TValue[string]{Data: kase.subjectDockerFile, State: plugin.StateIsSet},
				Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			dockerFile := mqlDockerFile{
				File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
				MqlRuntime: r,
			}

			require.NoError(t, dockerFile.parse(file))
			require.NoError(t, dockerFile.Stages.Error, "stage parse error")

			actualMqlDockerFileStage := dockerFile.Stages.Data[0].(*mqlDockerFileStage)

			require.Equal(t, kase.expectedLabels, actualMqlDockerFileStage.Labels.Data)
			if kase.expectedEnv != nil {
				expectedEnv := kase.expectedEnv(r)
				require.Equal(t, len(expectedEnv), len(actualMqlDockerFileStage.Env.Data))
				for i, raw := range actualMqlDockerFileStage.Env.Data {
					actualEnv := raw.(*mqlDockerFileEnv)
					expected := expectedEnv[i].(*mqlDockerFileEnv)
					require.Equal(t, expected.Name.Data, actualEnv.Name.Data)
					require.Equal(t, expected.Value.Data, actualEnv.Value.Data)
					// context is populated at creation with the instruction's source range
					require.Equal(t, plugin.StateIsSet, actualEnv.Context.State&plugin.StateIsSet)
				}
			}
			if kase.expectedArg != nil {
				expectedArg := kase.expectedArg(r)
				require.Equal(t, len(expectedArg), len(actualMqlDockerFileStage.Arg.Data))
				for i, raw := range actualMqlDockerFileStage.Arg.Data {
					actualArg := raw.(*mqlDockerFileArg)
					expected := expectedArg[i].(*mqlDockerFileArg)
					require.Equal(t, expected.Name.Data, actualArg.Name.Data)
					require.Equal(t, expected.Default.Data, actualArg.Default.Data)
					require.Equal(t, plugin.StateIsSet, actualArg.Context.State&plugin.StateIsSet)
				}
			}
			require.Equal(t, kase.expectedFromImage, actualMqlDockerFileStage.From.Data.Image.Data)
			require.Equal(t, kase.expectedFromTag, actualMqlDockerFileStage.From.Data.Tag.Data)

			if kase.expectedCmd.Data == nil {
				require.Nil(t, actualMqlDockerFileStage.Cmd.Data)
			} else {
				require.Equal(t, kase.expectedCmd.Data.Script.Data, actualMqlDockerFileStage.Cmd.Data.Script.Data)
				// CMD has no --mount/--network/--security flags, but the fields
				// must be initialized so queries return empty rather than unset.
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Cmd.Data.Mounts.State&plugin.StateIsSet)
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Cmd.Data.Network.State&plugin.StateIsSet)
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Cmd.Data.Security.State&plugin.StateIsSet)
			}

			if kase.expectedUser.Data == nil {
				require.Nil(t, actualMqlDockerFileStage.User.Data)
			} else {
				require.Equal(t, kase.expectedUser.Data.User.Data, actualMqlDockerFileStage.User.Data.User.Data)
				require.Equal(t, kase.expectedUser.Data.Group.Data, actualMqlDockerFileStage.User.Data.Group.Data)
			}

			if kase.expectedEntrypoint.Data == nil {
				require.Nil(t, actualMqlDockerFileStage.Entrypoint.Data)
			} else {
				require.Equal(t, kase.expectedEntrypoint.Data.Script.Data, actualMqlDockerFileStage.Entrypoint.Data.Script.Data)
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Entrypoint.Data.Mounts.State&plugin.StateIsSet)
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Entrypoint.Data.Network.State&plugin.StateIsSet)
				require.Equal(t, plugin.StateIsSet, actualMqlDockerFileStage.Entrypoint.Data.Security.State&plugin.StateIsSet)
			}

			require.Equal(t, len(kase.expectedCopyStruct), len(actualMqlDockerFileStage.Copy.Data))
			for i, cpy := range actualMqlDockerFileStage.Copy.Data {
				actualCopy := cpy.(*mqlDockerFileCopy)
				require.Equal(t, kase.expectedCopyStruct[i].Data.Src.Data, actualCopy.Src.Data)
				require.Equal(t, kase.expectedCopyStruct[i].Data.Dst.Data, actualCopy.Dst.Data)
			}

			require.Equal(t, len(kase.expectedRunStruct), len(actualMqlDockerFileStage.Run.Data))
			for i, run := range actualMqlDockerFileStage.Run.Data {
				actualRun := run.(*mqlDockerFileRun)
				require.Equal(t, kase.expectedRunStruct[i].Data.Script.Data, actualRun.Script.Data)
			}

			require.Equal(t, len(kase.expectedAddStruct), len(actualMqlDockerFileStage.Add.Data))
			for i, cpy := range actualMqlDockerFileStage.Add.Data {
				actualAdd := cpy.(*mqlDockerFileAdd)
				require.Equal(t, kase.expectedAddStruct[i].Data.Src.Data, actualAdd.Src.Data)
				require.Equal(t, kase.expectedAddStruct[i].Data.Dst.Data, actualAdd.Dst.Data)
			}

			require.Equal(t, len(kase.expectedExposeStructArr), len(actualMqlDockerFileStage.Expose.Data))
			for i, expose := range actualMqlDockerFileStage.Expose.Data {
				actualExpose := expose.(*mqlDockerFileExpose)
				require.Equal(t, kase.expectedExposeStructArr[i].Data.Port.Data, actualExpose.Port.Data)
				require.Equal(t, kase.expectedExposeStructArr[i].Data.Protocol.Data, actualExpose.Protocol.Data)
			}

			if kase.expectedHealthcheck.Data == nil {
				require.Nil(t, actualMqlDockerFileStage.Healthcheck.Data)
			} else {
				require.NotNil(t, actualMqlDockerFileStage.Healthcheck.Data)
				actualHC := actualMqlDockerFileStage.Healthcheck.Data
				require.Equal(t, kase.expectedHealthcheck.Data.Test.Data, actualHC.Test.Data)
				require.Equal(t, kase.expectedHealthcheck.Data.Interval.Data, actualHC.Interval.Data)
				require.Equal(t, kase.expectedHealthcheck.Data.Timeout.Data, actualHC.Timeout.Data)
				require.Equal(t, kase.expectedHealthcheck.Data.Retries.Data, actualHC.Retries.Data)
				require.Equal(t, kase.expectedHealthcheck.Data.None.Data, actualHC.None.Data)
			}

			require.Equal(t, len(kase.expectedVolumeStructArr), len(actualMqlDockerFileStage.Volumes.Data))
			for i, vol := range actualMqlDockerFileStage.Volumes.Data {
				actualVol := vol.(*mqlDockerFileVolume)
				require.Equal(t, kase.expectedVolumeStructArr[i].Data.Path.Data, actualVol.Path.Data)
			}

			if kase.expectedShell.Data == nil {
				require.Nil(t, actualMqlDockerFileStage.Shell.Data)
			} else {
				require.NotNil(t, actualMqlDockerFileStage.Shell.Data)
				require.Equal(t, kase.expectedShell.Data.Command.Data, actualMqlDockerFileStage.Shell.Data.Command.Data)
			}

			require.Equal(t, len(kase.expectedWorkdirStructArr), len(actualMqlDockerFileStage.Workdir.Data))
			for i, wd := range actualMqlDockerFileStage.Workdir.Data {
				actualWd := wd.(*mqlDockerFileWorkdir)
				require.Equal(t, kase.expectedWorkdirStructArr[i].Data.Path.Data, actualWd.Path.Data)
			}
		})
	}
}

func TestParseDockerfile_StopsignalAndOnbuild(t *testing.T) {
	src := `
FROM alpine
STOPSIGNAL SIGTERM
ONBUILD COPY . /app/src
ONBUILD RUN make
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[0].(*mqlDockerFileStage)
	require.NotNil(t, stage.Stopsignal.Data)
	require.Equal(t, "SIGTERM", stage.Stopsignal.Data.Signal.Data)

	require.Equal(t, 2, len(stage.Onbuild.Data))
	first := stage.Onbuild.Data[0].(*mqlDockerFileOnbuild)
	second := stage.Onbuild.Data[1].(*mqlDockerFileOnbuild)
	require.Equal(t, "COPY . /app/src", first.Expression.Data)
	require.Equal(t, "RUN make", second.Expression.Data)
}

func TestParseDockerfile_OCILabels(t *testing.T) {
	// Mixes unquoted, double-quoted, and single-quoted LABEL values to verify
	// the oci.* accessors strip a matched surrounding quote pair.
	src := `
FROM alpine
LABEL org.opencontainers.image.source=https://github.com/example/repo
LABEL org.opencontainers.image.version="1.2.3"
LABEL org.opencontainers.image.revision=abc123
LABEL org.opencontainers.image.licenses='Apache-2.0'
LABEL org.opencontainers.image.title="My App"
LABEL org.opencontainers.image.base.name=docker.io/library/alpine:3.20
LABEL org.opencontainers.artifact.created="2026-01-01T00:00:00Z"
LABEL com.example.team=platform
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[0].(*mqlDockerFileStage)
	require.NotNil(t, stage.Oci.Data)
	oci := stage.Oci.Data

	// standard annotations surface as named fields, with surrounding quotes removed
	require.Equal(t, "https://github.com/example/repo", oci.Source.Data) // unquoted
	require.Equal(t, "1.2.3", oci.Version.Data)                          // double-quoted
	require.Equal(t, "abc123", oci.Revision.Data)                        // unquoted
	require.Equal(t, "Apache-2.0", oci.Licenses.Data)                    // single-quoted
	require.Equal(t, "My App", oci.Title.Data)                           // double-quoted, with a space
	require.Equal(t, "docker.io/library/alpine:3.20", oci.BaseName.Data)

	// the verbatim labels map keeps the quotes that oci.* strips
	require.Equal(t, "\"1.2.3\"", stage.Labels.Data["org.opencontainers.image.version"])
	require.Equal(t, "'Apache-2.0'", stage.Labels.Data["org.opencontainers.image.licenses"])

	// undeclared annotations are empty, not unset
	require.Equal(t, "", oci.Authors.Data)
	require.Equal(t, "", oci.Created.Data) // image.created not set; artifact.created is unrelated

	// `all` holds every org.opencontainers.* label (unquoted), excluding non-OCI labels
	require.Equal(t, map[string]any{
		"org.opencontainers.image.source":     "https://github.com/example/repo",
		"org.opencontainers.image.version":    "1.2.3",
		"org.opencontainers.image.revision":   "abc123",
		"org.opencontainers.image.licenses":   "Apache-2.0",
		"org.opencontainers.image.title":      "My App",
		"org.opencontainers.image.base.name":  "docker.io/library/alpine:3.20",
		"org.opencontainers.artifact.created": "2026-01-01T00:00:00Z",
	}, oci.All.Data)
}

func TestTrimMatchingQuotes(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{``, ``},
		{`x`, `x`},
		{`"`, `"`},                 // single char, no pair
		{`""`, ``},                 // empty quoted
		{`"abc"`, `abc`},           // double quotes
		{`'abc'`, `abc`},           // single quotes
		{`abc`, `abc`},             // no quotes
		{`"abc`, `"abc`},           // unmatched leading
		{`abc"`, `abc"`},           // unmatched trailing
		{`"abc'`, `"abc'`},         // mismatched pair
		{`"a"b"`, `a"b`},           // strips only the outer pair
		{`https://x`, `https://x`}, // realistic unquoted url
		{`"My App"`, `My App`},     // value with a space
	}
	for _, kase := range cases {
		require.Equal(t, kase.out, trimMatchingQuotes(kase.in), "input %q", kase.in)
	}
}

func TestParseDockerfile_Directives(t *testing.T) {
	src := `# syntax=docker/dockerfile:1.7
# escape=` + "`" + `
FROM alpine
RUN echo hi
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	require.Equal(t, "docker/dockerfile:1.7", df.Directives.Data["syntax"])
	require.Equal(t, "`", df.Directives.Data["escape"])
}

func TestParseDockerfile_RunFlagsAndMounts(t *testing.T) {
	src := `
FROM alpine
RUN --network=none --security=insecure --mount=type=secret,id=npm_token,target=/run/secrets/npm,required=true --mount=type=cache,target=/root/.cache,sharing=locked echo build
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[0].(*mqlDockerFileStage)
	require.Equal(t, 1, len(stage.Run.Data))
	run := stage.Run.Data[0].(*mqlDockerFileRun)
	require.Equal(t, "none", run.Network.Data)
	require.Equal(t, "insecure", run.Security.Data)

	require.Equal(t, 2, len(run.Mounts.Data))
	mountTypes := map[string]*mqlDockerFileRunMount{}
	for _, m := range run.Mounts.Data {
		mm := m.(*mqlDockerFileRunMount)
		mountTypes[mm.Type.Data] = mm
	}

	secret := mountTypes["secret"]
	require.NotNil(t, secret)
	require.Equal(t, "/run/secrets/npm", secret.Target.Data)
	require.Equal(t, "npm_token", secret.Id.Data)
	require.True(t, secret.Required.Data)

	cache := mountTypes["cache"]
	require.NotNil(t, cache)
	require.Equal(t, "/root/.cache", cache.Target.Data)
	require.Equal(t, "locked", cache.Sharing.Data)
}

func TestParseDockerfile_AddCopyFlags(t *testing.T) {
	src := `
FROM scratch AS base
RUN echo build

FROM alpine
ADD --link --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d https://example.com/blob.bin /blob.bin
COPY --from=base --link --chown=1001:1001 /app /app
COPY --parents --exclude=*.log src/ /dest/
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[1].(*mqlDockerFileStage)

	require.Equal(t, 1, len(stage.Add.Data))
	add := stage.Add.Data[0].(*mqlDockerFileAdd)
	require.True(t, add.Link.Data)
	require.Equal(t, "sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d", add.Checksum.Data)

	require.Equal(t, 2, len(stage.Copy.Data))
	cp0 := stage.Copy.Data[0].(*mqlDockerFileCopy)
	require.Equal(t, "base", cp0.From.Data)
	require.True(t, cp0.Link.Data)
	require.Equal(t, "1001:1001", cp0.Chown.Data)

	cp1 := stage.Copy.Data[1].(*mqlDockerFileCopy)
	require.True(t, cp1.Parents.Data)
	require.Equal(t, []any{"*.log"}, cp1.Excludes.Data)
}

func TestParseDockerfile_FromDigest(t *testing.T) {
	cases := []struct {
		baseName       string
		expectedImage  string
		expectedTag    string
		expectedDigest string
	}{
		{"alpine", "alpine", "", ""},
		{"alpine:3.18", "alpine", "3.18", ""},
		{"alpine@sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d", "alpine", "", "sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d"},
		{"alpine:3.18@sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d", "alpine", "3.18", "sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc04d"},
	}
	for _, kase := range cases {
		t.Run(kase.baseName, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			src := "FROM " + kase.baseName + "\n"
			file := &mqlFile{
				Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
				Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			df := mqlDockerFile{
				File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			require.NoError(t, df.parse(file))

			from := df.Stages.Data[0].(*mqlDockerFileStage).From.Data
			require.Equal(t, kase.expectedImage, from.Image.Data, "image")
			require.Equal(t, kase.expectedTag, from.Tag.Data, "tag")
			require.Equal(t, kase.expectedDigest, from.Digest.Data, "digest")
		})
	}
}

func TestParseDockerfile_FilePredicates(t *testing.T) {
	cases := []struct {
		purpose                    string
		src                        string
		expectedMultiStage         bool
		expectedHasSyntaxDirective bool
		expectedFinalImage         string
	}{
		{
			purpose:                    "single stage without syntax directive",
			src:                        "FROM alpine\nRUN echo hi\n",
			expectedMultiStage:         false,
			expectedHasSyntaxDirective: false,
			expectedFinalImage:         "alpine",
		},
		{
			purpose: "multi-stage with syntax directive",
			src: `# syntax=docker/dockerfile:1.7
FROM golang AS builder
RUN go build
FROM scratch
COPY --from=builder /out /out
`,
			expectedMultiStage:         true,
			expectedHasSyntaxDirective: true,
			expectedFinalImage:         "scratch",
		},
	}
	for _, kase := range cases {
		t.Run(kase.purpose, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			file := &mqlFile{
				Content:    plugin.TValue[string]{Data: kase.src, State: plugin.StateIsSet},
				Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			df := mqlDockerFile{
				File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			require.NoError(t, df.parse(file))

			require.Equal(t, kase.expectedMultiStage, df.MultiStage.Data, "multiStage")
			require.Equal(t, kase.expectedHasSyntaxDirective, df.HasSyntaxDirective.Data, "hasSyntaxDirective")
			require.NotNil(t, df.FinalStage.Data, "finalStage populated")
			require.Equal(t, kase.expectedFinalImage, df.FinalStage.Data.From.Data.Image.Data, "finalStage.from.image")
		})
	}
}

func TestParseDockerfile_StagePredicates(t *testing.T) {
	src := `
FROM alpine AS builder
RUN echo build

FROM alpine
USER 1001
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))
	require.Equal(t, 2, len(df.Stages.Data))

	builder := df.Stages.Data[0].(*mqlDockerFileStage)
	require.True(t, builder.RunsAsRoot.Data, "builder has no USER → assumed root")
	require.False(t, builder.HasHealthcheck.Data, "builder has no HEALTHCHECK")
	require.False(t, builder.Final.Data, "builder is not final")

	finalStage := df.Stages.Data[1].(*mqlDockerFileStage)
	require.False(t, finalStage.RunsAsRoot.Data, "final stage USER=1001 is non-root")
	require.True(t, finalStage.HasHealthcheck.Data, "final stage declares HEALTHCHECK")
	require.True(t, finalStage.Final.Data, "last stage is final")
}

func TestParseDockerfile_SingleStageFinal(t *testing.T) {
	src := "FROM alpine\nRUN echo hi\n"
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	require.False(t, df.MultiStage.Data, "single stage → multiStage false")
	require.Equal(t, 1, len(df.Stages.Data))
	stage := df.Stages.Data[0].(*mqlDockerFileStage)
	require.True(t, stage.Final.Data, "the only stage is also the final stage")
	require.Equal(t, stage, df.FinalStage.Data, "finalStage points at the single stage")
}

func TestParseDockerfile_HealthcheckNone(t *testing.T) {
	cases := []struct {
		name           string
		src            string
		hasHealthcheck bool
		none           bool
	}{
		{
			name:           "HEALTHCHECK NONE disables the check",
			src:            "FROM alpine\nRUN apk add --no-cache curl\nHEALTHCHECK NONE\nUSER root\nCMD [\"sh\"]\n",
			hasHealthcheck: false,
			none:           true,
		},
		{
			name:           "a later NONE overrides an earlier CMD",
			src:            "FROM alpine\nHEALTHCHECK CMD true\nHEALTHCHECK NONE\n",
			hasHealthcheck: false,
			none:           true,
		},
		{
			name:           "a later CMD overrides an earlier NONE",
			src:            "FROM alpine\nHEALTHCHECK NONE\nHEALTHCHECK CMD true\n",
			hasHealthcheck: true,
			none:           false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			file := &mqlFile{
				Content:    plugin.TValue[string]{Data: c.src, State: plugin.StateIsSet},
				Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			df := mqlDockerFile{
				File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			require.NoError(t, df.parse(file))

			stage := df.Stages.Data[0].(*mqlDockerFileStage)
			require.Equal(t, c.hasHealthcheck, stage.HasHealthcheck.Data)
			require.NotNil(t, stage.Healthcheck.Data, "the instruction itself is still reported")
			require.Equal(t, c.none, stage.Healthcheck.Data.None.Data)
		})
	}
}

func TestParseDockerfile_StageRunsAsRoot(t *testing.T) {
	cases := []struct {
		user     string
		expected bool
	}{
		{"", true},      // no USER
		{"0", true},     // root by UID
		{"root", true},  // root by name
		{"0:0", true},   // root with group
		{"1001", false}, // non-root UID
		{"app", false},  // non-root name
	}
	for _, kase := range cases {
		name := kase.user
		if name == "" {
			name = "(no USER)"
		}
		t.Run(name, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			src := "FROM alpine\n"
			if kase.user != "" {
				src += "USER " + kase.user + "\n"
			}
			file := &mqlFile{
				Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
				Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			df := mqlDockerFile{
				File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
				MqlRuntime: r,
			}
			require.NoError(t, df.parse(file))

			stage := df.Stages.Data[0].(*mqlDockerFileStage)
			require.Equal(t, kase.expected, stage.RunsAsRoot.Data)
			if kase.user != "" {
				require.NotNil(t, stage.User.Data)
				require.Equal(t, kase.expected, stage.User.Data.IsRoot.Data)
			}
		})
	}
}

func TestParseDockerfile_RunFormAndMountPredicates(t *testing.T) {
	src := `
FROM alpine
RUN echo shell-form
RUN ["echo", "exec-form"]
RUN --mount=type=secret,id=npm_token,target=/run/secrets/npm npm install
RUN --mount=type=ssh ssh-add -l
CMD ["echo", "hello"]
ENTRYPOINT /entry.sh
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[0].(*mqlDockerFileStage)
	require.Equal(t, 4, len(stage.Run.Data))

	shellRun := stage.Run.Data[0].(*mqlDockerFileRun)
	require.True(t, shellRun.IsShellForm.Data, "RUN echo ... is shell form")
	require.False(t, shellRun.IsExecForm.Data)
	require.False(t, shellRun.MountsSecret.Data)
	require.False(t, shellRun.MountsSsh.Data)

	execRun := stage.Run.Data[1].(*mqlDockerFileRun)
	require.False(t, execRun.IsShellForm.Data)
	require.True(t, execRun.IsExecForm.Data, `RUN ["echo", ...] is exec form`)

	secretRun := stage.Run.Data[2].(*mqlDockerFileRun)
	require.True(t, secretRun.MountsSecret.Data, "RUN with --mount=type=secret")
	require.False(t, secretRun.MountsSsh.Data)

	sshRun := stage.Run.Data[3].(*mqlDockerFileRun)
	require.True(t, sshRun.MountsSsh.Data, "RUN with --mount=type=ssh")
	require.False(t, sshRun.MountsSecret.Data)

	require.NotNil(t, stage.Cmd.Data)
	require.True(t, stage.Cmd.Data.IsExecForm.Data, `CMD ["echo", ...] is exec form`)
	require.False(t, stage.Cmd.Data.IsShellForm.Data)

	require.NotNil(t, stage.Entrypoint.Data)
	require.True(t, stage.Entrypoint.Data.IsShellForm.Data, `ENTRYPOINT /entry.sh is shell form`)
	require.False(t, stage.Entrypoint.Data.IsExecForm.Data)
}

// cmdFields is a test helper that flattens a docker.file.run.command resource
// into plain Go values for easy assertions.
func cmdFields(t *testing.T, raw any) (binary, subcommand string, flags, args []string) {
	t.Helper()
	c := raw.(*mqlDockerFileRunCommand)
	binary = c.Binary.Data
	subcommand = c.Subcommand.Data
	for _, f := range c.Flags.Data {
		flags = append(flags, f.(string))
	}
	for _, a := range c.Args.Data {
		args = append(args, a.(string))
	}
	return
}

func TestParseDockerfile_RunCommands(t *testing.T) {
	src := `
FROM alpine
RUN apt-get update && apt-get install -y --no-install-recommends nginx
RUN ["/bin/sh", "-c", "echo hi"]
CMD ["nginx", "-g", "daemon off;"]
ENTRYPOINT ["docker-entrypoint.sh"]
`
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: "Dockerfile", State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))

	stage := df.Stages.Data[0].(*mqlDockerFileStage)

	t.Run("shell-form RUN splits the && chain into two commands", func(t *testing.T) {
		run := stage.Run.Data[0].(*mqlDockerFileRun)
		require.Equal(t, 2, len(run.Commands.Data))

		binary, sub, flags, args := cmdFields(t, run.Commands.Data[0])
		require.Equal(t, "apt-get", binary)
		require.Equal(t, "update", sub)
		require.Empty(t, flags)
		require.Equal(t, []string{"update"}, args)

		binary, sub, flags, args = cmdFields(t, run.Commands.Data[1])
		require.Equal(t, "apt-get", binary)
		require.Equal(t, "install", sub)
		require.Equal(t, []string{"-y", "--no-install-recommends"}, flags)
		require.Equal(t, []string{"install", "-y", "--no-install-recommends", "nginx"}, args)
	})

	t.Run("exec-form RUN yields a single command from the argv", func(t *testing.T) {
		run := stage.Run.Data[1].(*mqlDockerFileRun)
		require.Equal(t, 1, len(run.Commands.Data))
		binary, sub, flags, args := cmdFields(t, run.Commands.Data[0])
		require.Equal(t, "/bin/sh", binary)
		require.Equal(t, []string{"-c"}, flags)
		require.Equal(t, "echo hi", sub) // first non-flag arg
		require.Equal(t, []string{"-c", "echo hi"}, args)
	})

	t.Run("CMD exposes commands", func(t *testing.T) {
		require.NotNil(t, stage.Cmd.Data)
		require.Equal(t, 1, len(stage.Cmd.Data.Commands.Data))
		binary, _, flags, args := cmdFields(t, stage.Cmd.Data.Commands.Data[0])
		require.Equal(t, "nginx", binary)
		require.Equal(t, []string{"-g"}, flags)
		require.Equal(t, []string{"-g", "daemon off;"}, args)
	})

	t.Run("ENTRYPOINT exposes commands", func(t *testing.T) {
		require.NotNil(t, stage.Entrypoint.Data)
		require.Equal(t, 1, len(stage.Entrypoint.Data.Commands.Data))
		binary, sub, flags, args := cmdFields(t, stage.Entrypoint.Data.Commands.Data[0])
		require.Equal(t, "docker-entrypoint.sh", binary)
		require.Empty(t, flags)
		require.Empty(t, args)
		require.Equal(t, "", sub)
	})
}

func parseTestDockerfile(t *testing.T, r *plugin.Runtime, path string, src string) *mqlDockerFile {
	t.Helper()
	file := &mqlFile{
		Content:    plugin.TValue[string]{Data: src, State: plugin.StateIsSet},
		Path:       plugin.TValue[string]{Data: path, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	df := &mqlDockerFile{
		File:       plugin.TValue[*mqlFile]{Data: file, State: plugin.StateIsSet},
		MqlRuntime: r,
	}
	require.NoError(t, df.parse(file))
	return df
}

// A registry port is not a tag: `FROM localhost:5000/base` has no tag at all.
func TestParseDockerfile_FromRegistryPort(t *testing.T) {
	cases := []struct {
		baseName       string
		expectedImage  string
		expectedTag    string
		expectedDigest string
	}{
		{"localhost:5000/base", "localhost:5000/base", "", ""},
		{"localhost:5000/base:1.2", "localhost:5000/base", "1.2", ""},
		{"registry.example.com:5000/team/app:2.0@sha256:0000000000000000000000000000000000000000000000000000000000000000", "registry.example.com:5000/team/app", "2.0", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"registry.example.com:5000/team/app@sha256:0000000000000000000000000000000000000000000000000000000000000000", "registry.example.com:5000/team/app", "", "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		{"docker.io/library/alpine:3.19", "docker.io/library/alpine", "3.19", ""},
	}
	for _, kase := range cases {
		t.Run(kase.baseName, func(t *testing.T) {
			r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			df := parseTestDockerfile(t, r, "Dockerfile", "FROM "+kase.baseName+"\n")
			from := df.Stages.Data[0].(*mqlDockerFileStage).From.Data
			require.Equal(t, kase.expectedImage, from.Image.Data, "image")
			require.Equal(t, kase.expectedTag, from.Tag.Data, "tag")
			require.Equal(t, kase.expectedDigest, from.Digest.Data, "digest")
		})
	}
}

// Every pair of a multi-pair ENV or ARG line is its own entry, not the first
// pair repeated.
func TestParseDockerfile_MultiPairEnvArg(t *testing.T) {
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	df := parseTestDockerfile(t, r, "/opt/df/Dockerfile.secret", `FROM alpine:3.19
ENV APP_ENV=prod AWS_SECRET_ACCESS_KEY=abc123
ARG HTTP_PROXY GITHUB_TOKEN
`)
	stage := df.Stages.Data[0].(*mqlDockerFileStage)

	env := map[string]string{}
	for _, e := range stage.Env.Data {
		v := e.(*mqlDockerFileEnv)
		env[v.Name.Data] = v.Value.Data
	}
	require.Equal(t, map[string]string{"APP_ENV": "prod", "AWS_SECRET_ACCESS_KEY": "abc123"}, env)

	args := []string{}
	for _, a := range stage.Arg.Data {
		args = append(args, a.(*mqlDockerFileArg).Name.Data)
	}
	require.Equal(t, []string{"HTTP_PROXY", "GITHUB_TOKEN"}, args)
}

// The same port exposed in two stages, or in two Dockerfiles, is a separate
// entry each time, pointing at its own file and line.
func TestParseDockerfile_ExposeIsPerInstruction(t *testing.T) {
	r := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	multi := parseTestDockerfile(t, r, "/opt/df/Dockerfile.multi", `FROM alpine:3.19 AS builder
EXPOSE 80 443/tcp 53/udp
FROM alpine:3.19
EXPOSE 80
`)
	hcnone := parseTestDockerfile(t, r, "/opt/df/Dockerfile.hcnone", `FROM nginx:1.27
EXPOSE 80
`)

	stage1 := multi.Stages.Data[0].(*mqlDockerFileStage)
	stage2 := multi.Stages.Data[1].(*mqlDockerFileStage)
	require.Len(t, stage1.Expose.Data, 3)
	require.Len(t, stage2.Expose.Data, 1)

	e1 := stage1.Expose.Data[0].(*mqlDockerFileExpose)
	e2 := stage2.Expose.Data[0].(*mqlDockerFileExpose)
	e3 := hcnone.Stages.Data[0].(*mqlDockerFileStage).Expose.Data[0].(*mqlDockerFileExpose)
	require.Equal(t, int64(80), e3.Port.Data)
	require.NotEqual(t, e1.MqlID(), e2.MqlID(), "same port in two stages")
	require.NotEqual(t, e1.MqlID(), e3.MqlID(), "same port in two files")

	ctxPath := func(e *mqlDockerFileExpose) string { return e.Context.Data.File.Data.Path.Data }
	require.Equal(t, "/opt/df/Dockerfile.multi", ctxPath(e2))
	require.Equal(t, "/opt/df/Dockerfile.hcnone", ctxPath(e3))
}

func newDockerfileTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func dockerfileStage(t *testing.T, df *mqlDockerFile, i int) *mqlDockerFileStage {
	t.Helper()
	require.NoError(t, df.Stages.Error)
	require.Greater(t, len(df.Stages.Data), i)
	return df.Stages.Data[i].(*mqlDockerFileStage)
}

// USER is expanded with the ARG and ENV values in scope, the way the build
// does. A value the Dockerfile cannot resolve counts as root.
func TestParseDockerfile_UserFromVariable(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		user      string
		group     string
		root      bool
		finalOnly bool
	}{
		{
			// docker build + inspect: Config.User = "root"
			name: "ARG default root",
			src:  "FROM alpine:3.20\nARG RUNAS=root\nUSER $RUNAS\n",
			user: "root", root: true,
		},
		{
			// docker build + inspect: Config.User = "0:0"
			name: "ENV uid 0 with group",
			src:  "FROM alpine:3.20\nENV APPUID=0\nUSER ${APPUID}:${APPUID}\n",
			user: "0", group: "0", root: true,
		},
		{
			name: "ARG default non-root",
			src:  "FROM alpine:3.20\nARG RUNAS=app\nUSER $RUNAS\n",
			user: "app", root: false,
		},
		{
			// A global ARG is not visible inside a stage unless redeclared there,
			// so this builds with an empty USER, which is root.
			name: "global ARG not redeclared in the stage",
			src:  "ARG BASE=alpine:3.20\nARG RUNUSER=root\nFROM ${BASE}\nUSER ${RUNUSER}\n",
			user: "${RUNUSER}", root: true,
		},
		{
			name: "global ARG redeclared without a value takes the global default",
			src:  "ARG RUNUSER=app\nFROM alpine:3.20\nARG RUNUSER\nUSER ${RUNUSER}\n",
			user: "app", root: false,
		},
		{
			// FOO has no value in the Dockerfile at all: only a build argument
			// can set it, so the user is unknown
			name: "global ARG without a default redeclared in the stage",
			src:  "ARG FOO\nFROM alpine:3.20\nARG FOO\nUSER $FOO\n",
			user: "$FOO", root: true,
		},
		{
			name: "a later bare global ARG keeps the earlier default",
			src:  "ARG FOO=app\nARG FOO\nFROM alpine:3.20\nARG FOO\nUSER $FOO\n",
			user: "app", root: false,
		},
		{
			name: "ARG without a default is set only at build time",
			src:  "FROM alpine:3.20\nARG UID\nUSER $UID\n",
			user: "$UID", root: true,
		},
		{
			name: "ENV built from an unknown value",
			src:  "FROM alpine:3.20\nENV U=${NOPE}\nUSER $U\n",
			user: "${NOPE}", root: true,
		},
		{
			name: "default modifier resolves to root",
			src:  "FROM alpine:3.20\nUSER ${NOPE:-root}\n",
			user: "${NOPE:-root}", root: true,
		},
		{
			name: "ENV wins over ARG of the same name",
			src:  "FROM alpine:3.20\nENV RUNAS=app\nARG RUNAS=root\nUSER $RUNAS\n",
			user: "app", root: false,
		},
		{
			name: "expansion uses the values at the USER instruction",
			src:  "FROM alpine:3.20\nARG RUNAS=app\nUSER $RUNAS\nARG RUNAS2=root\n",
			user: "app", root: false,
		},
	}
	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile", kase.src)
			stage := dockerfileStage(t, df, len(df.Stages.Data)-1)
			require.Equal(t, kase.root, stage.RunsAsRoot.Data, "runsAsRoot")
			require.NotNil(t, stage.User.Data)
			require.Equal(t, kase.user, stage.User.Data.User.Data, "user")
			require.Equal(t, kase.group, stage.User.Data.Group.Data, "group")
			require.Equal(t, kase.root, stage.User.Data.IsRoot.Data, "isRoot")
		})
	}
}

// FROM is expanded with the global ARGs declared before the first stage.
func TestParseDockerfile_FromGlobalArgs(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		image string
		tag   string
	}{
		{
			// docker build used quay.io/libpod/alpine:latest
			name:  "registry and tag from global ARGs",
			src:   "ARG TAG=latest\nARG REG=quay.io\nFROM ${REG}/libpod/alpine:${TAG}\nRUN true\n",
			image: "quay.io/libpod/alpine", tag: "latest",
		},
		{
			name:  "whole reference from a global ARG",
			src:   "ARG BASE=alpine:3.20\nARG RUNUSER=root\nFROM ${BASE}\nUSER ${RUNUSER}\n",
			image: "alpine", tag: "3.20",
		},
		{
			name:  "a global ARG that refers to an earlier one",
			src:   "ARG V=3.20\nARG BASE=alpine:$V\nFROM $BASE\n",
			image: "alpine", tag: "3.20",
		},
		{
			name:  "an ARG without a default stays as written",
			src:   "ARG TAG\nFROM alpine:${TAG}\n",
			image: "alpine", tag: "${TAG}",
		},
	}
	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile", kase.src)
			from := dockerfileStage(t, df, 0).From.Data
			require.Equal(t, kase.image, from.Image.Data, "image")
			require.Equal(t, kase.tag, from.Tag.Data, "tag")
		})
	}
}

func exposedPorts(t *testing.T, stage *mqlDockerFileStage) []string {
	t.Helper()
	require.NoError(t, stage.Expose.Error)
	out := []string{}
	for _, e := range stage.Expose.Data {
		x := e.(*mqlDockerFileExpose)
		out = append(out, strconv.FormatInt(x.Port.Data, 10)+"/"+x.Protocol.Data)
	}
	return out
}

// EXPOSE ranges list every port, variables are expanded, and a port that
// cannot be parsed is an error rather than port 0.
func TestParseDockerfile_ExposeRangesAndVariables(t *testing.T) {
	t.Run("ranges", func(t *testing.T) {
		// docker build + inspect: ExposedPorts holds 20/tcp..30/tcp, 8000/tcp..8010/tcp, 443/tcp
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile.range",
			"FROM alpine:3.20\nEXPOSE 20-30/tcp 8000-8010\nEXPOSE 443\n")
		ports := exposedPorts(t, dockerfileStage(t, df, 0))
		require.Len(t, ports, 23)
		require.Equal(t, "20/tcp", ports[0])
		require.Equal(t, "22/tcp", ports[2])
		require.Equal(t, "30/tcp", ports[10])
		require.Equal(t, "8000/tcp", ports[11])
		require.Equal(t, "8010/tcp", ports[21])
		require.Equal(t, "443/tcp", ports[22])
		require.NotContains(t, ports, "0/tcp")
	})

	t.Run("variables", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile",
			"FROM alpine:3.20\nARG PORT=8080\nENV PROTO=UDP\nEXPOSE $PORT/${PROTO} 9090\n")
		require.Equal(t, []string{"8080/udp", "9090/tcp"}, exposedPorts(t, dockerfileStage(t, df, 0)))
	})

	t.Run("a variable with no value is an error", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile",
			"FROM alpine:3.20\nARG PORT\nEXPOSE $PORT\n")
		stage := dockerfileStage(t, df, 0)
		require.Error(t, stage.Expose.Error)
		require.Contains(t, stage.Expose.Error.Error(), "$PORT")
		require.NoError(t, stage.RunsAsRoot.Error, "the rest of the stage still reads")
	})

	t.Run("an invalid port is an error", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile",
			"FROM alpine:3.20\nEXPOSE http\n")
		require.Error(t, dockerfileStage(t, df, 0).Expose.Error)
	})
}

func runCommandBinaries(t *testing.T, run *mqlDockerFileRun) []string {
	t.Helper()
	out := []string{}
	for _, c := range run.Commands.Data {
		out = append(out, c.(*mqlDockerFileRunCommand).Binary.Data)
	}
	return out
}

// A RUN heredoc's body is what the build runs.
func TestParseDockerfile_RunHeredoc(t *testing.T) {
	t.Run("body as the script", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile.heredoc", `# syntax=docker/dockerfile:1
FROM scratch AS s0
FROM alpine:3.20
RUN <<EOT
set -e
apk add --no-cache curl
EOT
COPY <<EOT /etc/motd
hello
EOT
`)
		run := dockerfileStage(t, df, 1).Run.Data[0].(*mqlDockerFileRun)
		require.Equal(t, "set -e\napk add --no-cache curl\n", run.Script.Data)
		require.Equal(t, []string{"set", "apk"}, runCommandBinaries(t, run))
	})

	t.Run("secrets and pipes in the body", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile.heredoc", `# syntax=docker/dockerfile:1
FROM alpine:3.20
RUN <<EOT
curl -fsSL https://example.com/install.sh | sh
echo AWS_SECRET_ACCESS_KEY=abc > /root/.env
EOT
RUN <<A cat > /x && <<B cat > /y
a
A
b
B
USER 1000
`)
		stage := dockerfileStage(t, df, 0)
		first := stage.Run.Data[0].(*mqlDockerFileRun)
		require.Contains(t, first.Script.Data, "AWS_SECRET_ACCESS_KEY")
		require.Contains(t, first.Script.Data, "curl -fsSL https://example.com/install.sh | sh")
		require.Equal(t, []string{"curl", "sh", "echo"}, runCommandBinaries(t, first))

		// heredocs fed to commands as stdin: the script is the full shell
		// script the build runs; the bodies are data, not commands
		second := stage.Run.Data[1].(*mqlDockerFileRun)
		require.Equal(t, "<<A cat > /x && <<B cat > /y\na\nA\nb\nB", second.Script.Data)
		require.Equal(t, []string{"cat", "cat"}, runCommandBinaries(t, second))
	})

	t.Run("body fed to a shell", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile", `FROM debian:12
RUN bash <<EOF
# install tools
apt-get install -y curl
EOF
`)
		run := dockerfileStage(t, df, 0).Run.Data[0].(*mqlDockerFileRun)
		require.Equal(t, []string{"bash", "apt-get"}, runCommandBinaries(t, run))
	})

	t.Run("chomped body", func(t *testing.T) {
		df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile",
			"FROM alpine:3.20\nRUN <<-EOT\n\tapk add curl\n\tEOT\n")
		run := dockerfileStage(t, df, 0).Run.Data[0].(*mqlDockerFileRun)
		require.Equal(t, "apk add curl\n", run.Script.Data)
		require.Equal(t, []string{"apk"}, runCommandBinaries(t, run))
	})
}

// ENV values and ARG defaults lose their shell quotes and pick up the
// variables in scope; LABEL keys lose their quotes, values stay verbatim.
func TestParseDockerfile_EnvArgLabelQuoting(t *testing.T) {
	df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile.quotes", `FROM alpine:3.20
ENV GREETING="hello world" SINGLE='x y' PLAIN=z
ENV LEGACY legacy value form
ARG TOKEN="abc"
ARG V=1.2
ENV VERSION=v$V PATH=/app/bin:$PATH
LABEL maintainer="Sweep Team" org.opencontainers.image.title='Quoted Title'
LABEL "uni"="ünïcödé ✓"
USER 1000
`)
	stage := dockerfileStage(t, df, 0)

	env := map[string]string{}
	for _, e := range stage.Env.Data {
		x := e.(*mqlDockerFileEnv)
		env[x.Name.Data] = x.Value.Data
	}
	require.Equal(t, map[string]string{
		"GREETING": "hello world",
		"SINGLE":   "x y",
		"PLAIN":    "z",
		"LEGACY":   "legacy value form",
		"VERSION":  "v1.2",
		"PATH":     "/app/bin:$PATH",
	}, env)

	args := map[string]string{}
	for _, a := range stage.Arg.Data {
		x := a.(*mqlDockerFileArg)
		args[x.Name.Data] = x.Default.Data
	}
	require.Equal(t, map[string]string{"TOKEN": "abc", "V": "1.2"}, args)

	require.Equal(t, "\"ünïcödé ✓\"", stage.Labels.Data["uni"])
	require.Equal(t, "\"Sweep Team\"", stage.Labels.Data["maintainer"])
	require.NotContains(t, stage.Labels.Data, "\"uni\"")
	require.Equal(t, "Quoted Title", stage.Oci.Data.Title.Data)
}

// A stage built FROM an earlier stage starts with that stage's USER and ENV.
func TestParseDockerfile_StageInheritance(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		root  bool
		stage int // index of the stage to check, -1 for the last
	}{
		{
			// docker build --target final + inspect: Config.User = "app"
			name: "USER from the parent stage",
			src:  "FROM alpine:3.20 AS base\nRUN adduser -D app\nUSER app\nFROM base AS final\nRUN echo hi\n",
			root: false, stage: -1,
		},
		{
			name: "parent stage named in mixed case",
			src:  "FROM alpine:3.20 AS Base\nUSER app\nFROM base\n",
			root: false, stage: -1,
		},
		{
			name: "parent stage without USER",
			src:  "FROM alpine:3.20 AS base\nRUN true\nFROM base AS final\n",
			root: true, stage: -1,
		},
		{
			name: "parent stage runs as root",
			src:  "FROM alpine:3.20 AS base\nUSER app\nUSER root\nFROM base\n",
			root: true, stage: -1,
		},
		{
			name: "grandparent USER",
			src:  "FROM alpine:3.20 AS a\nUSER app\nFROM a AS b\nRUN true\nFROM b\n",
			root: false, stage: -1,
		},
		{
			name: "ENV from the parent stage",
			src:  "FROM alpine:3.20 AS base\nENV U=app\nFROM base\nUSER $U\n",
			root: false, stage: -1,
		},
		{
			name: "an image named like a later stage is not a stage",
			src:  "FROM base\nFROM alpine:3.20 AS base\nUSER app\n",
			root: true, stage: 0,
		},
	}
	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			df := parseTestDockerfile(t, newDockerfileTestRuntime(), "/opt/df/Dockerfile.inherit", kase.src)
			idx := kase.stage
			if idx < 0 {
				idx = len(df.Stages.Data) - 1
			}
			require.Equal(t, kase.root, dockerfileStage(t, df, idx).RunsAsRoot.Data)
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
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

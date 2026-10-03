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

func TestParseExposePort(t *testing.T) {
	cases := []struct {
		spec  string
		ports []dockerfilePort
	}{
		{"80", []dockerfilePort{{80, "tcp"}}},
		{"53/UDP", []dockerfilePort{{53, "udp"}}},
		{"8080:80/tcp", []dockerfilePort{{80, "tcp"}}},
		{"127.0.0.1:8080:80", []dockerfilePort{{80, "tcp"}}},
		{"[::1]:8080:81/sctp", []dockerfilePort{{81, "sctp"}}},
		{"7-9", []dockerfilePort{{7, "tcp"}, {8, "tcp"}, {9, "tcp"}}},
		{"5-5", []dockerfilePort{{5, "tcp"}}},
	}
	for _, kase := range cases {
		t.Run(kase.spec, func(t *testing.T) {
			ports, err := parseExposePort(kase.spec)
			require.NoError(t, err)
			require.Equal(t, kase.ports, ports)
		})
	}
	for _, bad := range []string{"", "/tcp", "http", "70000", "9-7", "80/icmp", "80-x"} {
		t.Run("invalid "+bad, func(t *testing.T) {
			_, err := parseExposePort(bad)
			require.Error(t, err)
		})
	}
}

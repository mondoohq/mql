// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package serverlaunch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitCmdline(t *testing.T) {
	// /proc/1/cmdline in the official haproxy image, started with
	// `docker run haproxy haproxy -f /opt/alt.cfg`
	raw := []byte("haproxy\x00-W\x00-db\x00-f\x00/opt/alt.cfg\x00")
	assert.Equal(t, []string{"haproxy", "-W", "-db", "-f", "/opt/alt.cfg"}, SplitCmdline(raw))
	assert.Nil(t, SplitCmdline(nil), "a kernel thread has an empty cmdline")
}

func TestParseStatPPid(t *testing.T) {
	ppid, ok := ParseStatPPid([]byte("7 (haproxy) S 1 1 1 0 -1 4194560 2263 0 0 0 1 0 0 0 20 0 9 0 312 0"))
	assert.True(t, ok)
	assert.Equal(t, 1, ppid)

	// a program name holding a space and a ")" must not shift the fields
	ppid, ok = ParseStatPPid([]byte("42 (a) b (c) R 17 42 42 0 -1"))
	assert.True(t, ok)
	assert.Equal(t, 17, ppid)

	_, ok = ParseStatPPid([]byte("garbage"))
	assert.False(t, ok)
	_, ok = ParseStatPPid([]byte("1 (init) S"))
	assert.False(t, ok)
}

func TestParseEnviron(t *testing.T) {
	// /proc/1/environ of ollama/ollama started with -e OLLAMA_ORIGINS=*
	raw := []byte("PATH=/usr/local/sbin:/usr/local/bin\x00HOSTNAME=4f0c\x00OLLAMA_ORIGINS=*\x00OLLAMA_HOST=0.0.0.0:11434\x00NOEQUALS\x00OLLAMA_HOST=127.0.0.1\x00")
	env := ParseEnviron(raw)
	assert.Equal(t, "*", env["OLLAMA_ORIGINS"])
	assert.Equal(t, "0.0.0.0:11434", env["OLLAMA_HOST"], "the first assignment is what getenv returns")
	assert.NotContains(t, env, "NOEQUALS")
	assert.Equal(t, "/usr/local/sbin:/usr/local/bin", env["PATH"], "a value holding = and : is kept whole")
}

func TestEnvList(t *testing.T) {
	env := EnvList([]string{"PGDATA=/var/lib/postgresql/data", "EMPTY=", "=x", "DOCKER_PG_LLVM_DEPS=llvm19-dev \t\tclang19"})
	assert.Equal(t, "/var/lib/postgresql/data", env["PGDATA"])
	v, ok := env["EMPTY"]
	assert.True(t, ok)
	assert.Equal(t, "", v)
	assert.NotContains(t, env, "")
	assert.Equal(t, "llvm19-dev \t\tclang19", env["DOCKER_PG_LLVM_DEPS"])
}

func TestMasters(t *testing.T) {
	isHttpd := IsProgram("httpd")
	procs := []Process{
		// httpd image: the master is pid 1, its workers are its children
		{Pid: 9, PPid: 1, Argv: []string{"httpd", "-DFOREGROUND", "-f", "/opt/alt/httpd.conf"}},
		{Pid: 1, PPid: 0, Argv: []string{"httpd", "-DFOREGROUND", "-f", "/opt/alt/httpd.conf"}},
		{Pid: 8, PPid: 1, Argv: []string{"httpd", "-DFOREGROUND", "-f", "/opt/alt/httpd.conf"}},
		{Pid: 30, PPid: 0, Argv: []string{"sh"}},
		{Pid: 2, PPid: 0, Argv: nil},
	}
	got := Masters(procs, isHttpd)
	if assert.Len(t, got, 1) {
		assert.Equal(t, 1, got[0].Pid)
	}

	// two independent servers come back lowest pid first
	procs = append(procs, Process{Pid: 5, PPid: 30, Argv: []string{"/usr/sbin/httpd", "-f", "/etc/other.conf"}})
	got = Masters(procs, isHttpd)
	if assert.Len(t, got, 2) {
		assert.Equal(t, 1, got[0].Pid)
		assert.Equal(t, 5, got[1].Pid)
	}

	assert.Empty(t, Masters(procs, IsProgram("haproxy")))
}

func TestImageArgv(t *testing.T) {
	isHaproxy := IsProgram("haproxy")
	// haproxy official image
	assert.Equal(t,
		[]string{"haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"},
		ImageArgv([]string{"docker-entrypoint.sh"}, []string{"haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"}, isHaproxy, "haproxy"))

	// ollama/ollama
	assert.Equal(t, []string{"/bin/ollama", "serve"},
		ImageArgv([]string{"/bin/ollama"}, []string{"serve"}, IsProgram("ollama"), "ollama"))

	// ubuntu/squid passes Cmd to squid through its entrypoint script
	assert.Equal(t, []string{"squid", "-f", "/etc/squid/squid.conf", "-NYC"},
		ImageArgv([]string{"entrypoint.sh"}, []string{"-f", "/etc/squid/squid.conf", "-NYC"}, IsProgram("squid"), "squid"))

	// options behind something that is not an entrypoint script are not
	// the server's
	assert.Nil(t, ImageArgv([]string{"/usr/bin/tini", "--"}, []string{"-f", "/x"}, IsProgram("squid"), "squid"))
	// an image that starts another program
	assert.Nil(t, ImageArgv(nil, []string{"/bin/bash"}, isHaproxy, "haproxy"))
	assert.Nil(t, ImageArgv([]string{"docker-entrypoint.sh"}, []string{"postgres"}, isHaproxy, "haproxy"))
	assert.Nil(t, ImageArgv(nil, nil, isHaproxy, "haproxy"))
}

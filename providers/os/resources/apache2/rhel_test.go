// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rhelStatic is what `httpd -l` prints on RHEL 7 through 10 and Fedora 44.
var rhelStatic = []string{"core.c", "mod_so.c", "http_core.c"}

// rhel00MPM is the stock RHEL 9 /etc/httpd/conf.modules.d/00-mpm.conf with
// the comments trimmed; mpm is the one LoadModule line left uncommented.
func rhel00MPM(mpm string) string {
	return "#LoadModule mpm_prefork_module modules/mod_mpm_prefork.so\n" +
		"#LoadModule mpm_worker_module modules/mod_mpm_worker.so\n" +
		"#LoadModule mpm_event_module modules/mod_mpm_event.so\n" +
		"LoadModule " + mpm + "_module modules/mod_" + mpm + ".so\n"
}

// 01-cgi.conf as shipped by RHEL 9 and 10, Alma 9 and 10, and Fedora 44
const rhel9CGIConf = `# This configuration file loads a CGI module appropriate to the MPM
# which has been configured in 00-mpm.conf.  mod_cgid should be used
# with a threaded MPM; mod_cgi with the prefork MPM.

<IfModule !mpm_prefork_module>
   LoadModule cgid_module modules/mod_cgid.so
</IfModule>
<IfModule mpm_prefork_module>
   LoadModule cgi_module modules/mod_cgi.so
</IfModule>
`

// 01-cgi.conf as shipped by RHEL 7 and 8 and Alma 8
const rhel7CGIConf = `# This configuration file loads a CGI module appropriate to the MPM
# which has been configured in 00-mpm.conf.  mod_cgid should be used
# with a threaded MPM; mod_cgi with the prefork MPM.

<IfModule mpm_worker_module>
   LoadModule cgid_module modules/mod_cgid.so
</IfModule>
<IfModule mpm_event_module>
   LoadModule cgid_module modules/mod_cgid.so
</IfModule>
<IfModule mpm_prefork_module>
   LoadModule cgi_module modules/mod_cgi.so
</IfModule>
`

func rhelTree(mpm, cgiConf string, extra map[string]string) map[string]string {
	files := map[string]string{
		"/etc/httpd/conf/httpd.conf": `ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
IncludeOptional conf.d/*.conf
`,
		"/etc/httpd/conf.modules.d/00-base.conf": "LoadModule alias_module modules/mod_alias.so\nLoadModule headers_module modules/mod_headers.so\n",
		"/etc/httpd/conf.modules.d/00-mpm.conf":  rhel00MPM(mpm),
		"/etc/httpd/conf.modules.d/01-cgi.conf":  cgiConf,
	}
	for k, v := range extra {
		files[k] = v
	}
	return files
}

func parseRHELTree(t *testing.T, files map[string]string, vars map[string]string, opts ParseOptions) *Config {
	t.Helper()
	fileContent := func(p string) (string, error) {
		c, ok := files[p]
		if !ok {
			return "", fmt.Errorf("not found: %s", p)
		}
		return c, nil
	}
	globExpand := func(pattern string) ([]string, error) {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join("/etc/httpd", pattern)
		}
		var out []string
		for p := range files {
			if ok, _ := filepath.Match(pattern, p); ok {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	cfg, err := ParseWithGlobOptions("/etc/httpd/conf/httpd.conf", fileContent, globExpand, vars, opts)
	require.NoError(t, err)
	return cfg
}

func moduleCount(cfg *Config) map[string]int {
	n := map[string]int{}
	for _, m := range cfg.Modules {
		n[m.Name]++
	}
	return n
}

// 01-cgi.conf picks the CGI module from the MPM 00-mpm.conf loaded earlier.
// `httpd -M` on the sweep hosts lists cgid_module once under event (RHEL 8,
// 9, 10, Alma, Fedora) and cgi_module once under prefork (RHEL 7).
func TestConditional_RHELCGIModuleFollowsMPM(t *testing.T) {
	for _, tc := range []struct {
		name, mpm, conf string
		want, notWant   string
	}{
		{"RHEL 9 event", "mpm_event", rhel9CGIConf, "cgid_module", "cgi_module"},
		{"RHEL 9 prefork", "mpm_prefork", rhel9CGIConf, "cgi_module", "cgid_module"},
		{"RHEL 8 event", "mpm_event", rhel7CGIConf, "cgid_module", "cgi_module"},
		{"RHEL 7 prefork", "mpm_prefork", rhel7CGIConf, "cgi_module", "cgid_module"},
		{"RHEL 7 worker", "mpm_worker", rhel7CGIConf, "cgid_module", "cgi_module"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := parseRHELTree(t, rhelTree(tc.mpm, tc.conf, nil), nil, ParseOptions{StaticModules: rhelStatic})
			n := moduleCount(cfg)
			assert.Equal(t, 1, n[tc.want])
			assert.Equal(t, 0, n[tc.notWant])
			assert.Equal(t, 1, n[tc.mpm+"_module"])
		})
	}
}

// RHEL 7's httpd.service reads /etc/sysconfig/httpd, so a ${VAR} set there
// resolves the way httpd sees it.
func TestConditional_RHELSysconfigVariable(t *testing.T) {
	files := rhelTree("mpm_prefork", rhel7CGIConf, map[string]string{
		"/etc/httpd/conf.d/zz-flip.conf": "ServerTokens ${SWEEPTOK}\n",
	})
	vars := ParseEnvironmentFile("#OPTIONS=\nLANG=C\nSWEEPTOK=Full\n")
	cfg := parseRHELTree(t, files, vars, ParseOptions{StaticModules: rhelStatic})
	v, ok := ParamValue(cfg.Params, "ServerTokens")
	require.True(t, ok)
	assert.Equal(t, "Full", v)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/config"
	"github.com/siderolabs/talos/pkg/machinery/config/generate"
	"github.com/siderolabs/talos/pkg/machinery/config/generate/secrets"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/talos/connection"
)

func TestNormalizeKey(t *testing.T) {
	for in, want := range map[string]string{
		"net.ipv4.tcp_syncookies":                "net.ipv4.tcp_syncookies",
		"proc.sys.net.ipv4.tcp_syncookies":       "net.ipv4.tcp_syncookies",
		"/proc/sys/net/ipv4/tcp_syncookies":      "net.ipv4.tcp_syncookies",
		"proc/sys/net/ipv4/conf/all/rp_filter":   "net.ipv4.conf.all.rp_filter",
		"net/ipv6/conf/default/accept_redirects": "net.ipv6.conf.default.accept_redirects",
		"proc.sys.kernel.kptr_restrict":          "kernel.kptr_restrict",
	} {
		if got := normalizeKey(in); got != want {
			t.Errorf("normalizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToDict(t *testing.T) {
	got, err := toDict(map[string]any{
		"port":    50000,
		"enabled": true,
		"nested":  map[string]any{"list": []any{"a", 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["port"] != float64(50000) {
		t.Errorf("port = %#v, want float64 50000", m["port"])
	}
	if m["enabled"] != true {
		t.Errorf("enabled = %#v, want true", m["enabled"])
	}
	list := m["nested"].(map[string]any)["list"].([]any)
	if list[0] != "a" || list[1] != float64(1) {
		t.Errorf("nested.list = %#v", list)
	}
}

// TestMachineConfigDocsRedacts generates a control plane configuration with
// fresh secrets and checks that none of them survives, while the
// configuration itself does.
func TestMachineConfigDocsRedacts(t *testing.T) {
	contract := config.TalosVersionCurrent
	bundle, err := secrets.NewBundle(secrets.NewFixedClock(time.Now()), contract)
	if err != nil {
		t.Fatal(err)
	}
	input, err := generate.NewInput("test", "https://10.5.0.2:6443", "1.37.1",
		generate.WithVersionContract(contract),
		generate.WithSecretsBundle(bundle),
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := input.Config(machine.TypeControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cfg.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	docs, err := machineConfigDocs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) < 2 {
		t.Fatalf("got %d documents, want the v1alpha1 config and the others", len(docs))
	}
	out, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}

	secretValues := map[string]string{
		"cluster secret":               bundle.Cluster.Secret,
		"bootstrap token":              bundle.Secrets.BootstrapToken,
		"secretbox encryption secret":  bundle.Secrets.SecretboxEncryptionSecret,
		"trustd token":                 bundle.TrustdInfo.Token,
		"OS CA key":                    string(bundle.Certs.OS.Key),
		"Kubernetes CA key":            string(bundle.Certs.K8s.Key),
		"etcd CA key":                  string(bundle.Certs.Etcd.Key),
		"Kubernetes aggregator CA key": string(bundle.Certs.K8sAggregator.Key),
		"service account key":          string(bundle.Certs.K8sServiceAccount.Key),
	}
	// Only the secrets the configuration holds can leak; it holds keys
	// base64-encoded, so look for both forms.
	checked := 0
	for name, v := range secretValues {
		if v == "" {
			continue
		}
		for _, needle := range []string{v, b64(v)} {
			if !strings.Contains(string(data), needle) {
				continue
			}
			checked++
			if strings.Contains(string(out), needle) {
				t.Errorf("the %s is in the redacted configuration", name)
			}
		}
	}
	if checked < 6 {
		t.Fatalf("only %d secrets are in the generated configuration, want at least 6", checked)
	}

	v1alpha1, ok := docs[0].(map[string]any)
	if !ok || v1alpha1["machine"] == nil || v1alpha1["cluster"] == nil {
		t.Fatalf("the first document is not the v1alpha1 config: %v", docs[0])
	}
	if typ := v1alpha1["machine"].(map[string]any)["type"]; typ != "controlplane" {
		t.Errorf("machine.type = %v, want controlplane", typ)
	}
}

func b64(s string) string {
	data, _ := json.Marshal([]byte(s))
	return strings.Trim(string(data), `"`)
}

func TestRefused(t *testing.T) {
	err := refused(fmt.Errorf("%w: not authorized", connection.ErrNeedsAdmin))
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refused(ErrNeedsAdmin) = %v, want Forbidden", err)
	}
	var lerr *llx.Error
	if !errors.As(err, &lerr) || len(lerr.Permissions) != 1 || lerr.Permissions[0] != "os:admin" {
		t.Errorf("refused(ErrNeedsAdmin) permissions = %+v, want [os:admin]", lerr)
	}

	other := errors.New("talos: connection refused")
	if got := refused(other); got != other {
		t.Errorf("refused(%v) = %v, want it unchanged", other, got)
	}
}

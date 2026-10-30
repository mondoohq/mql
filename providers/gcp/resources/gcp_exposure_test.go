// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestIsOpenCIDR(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{" 0.0.0.0/0 ", true},
		{"10.0.0.0/8", false},
		{"192.168.1.0/24", false},
		{"0.0.0.0/32", false},
		{"", false},
		{"2001:db8::/32", false},
	}
	for _, tt := range tests {
		if got := isOpenCIDR(tt.cidr); got != tt.want {
			t.Errorf("isOpenCIDR(%q) = %v, want %v", tt.cidr, got, tt.want)
		}
	}
}

func TestGkeControlPlaneInternetReachable(t *testing.T) {
	tests := []struct {
		name           string
		publicEndpoint bool
		manEnforced    bool
		cidrs          []string
		want           bool
	}{
		{
			name:           "private endpoint is never reachable",
			publicEndpoint: false,
			manEnforced:    false,
			cidrs:          nil,
			want:           false,
		},
		{
			name:           "private endpoint with open authorized cidr still not reachable",
			publicEndpoint: false,
			manEnforced:    true,
			cidrs:          []string{"0.0.0.0/0"},
			want:           false,
		},
		{
			name:           "public endpoint without authorized networks is reachable",
			publicEndpoint: true,
			manEnforced:    false,
			cidrs:          nil,
			want:           true,
		},
		{
			name:           "public endpoint restricted to specific cidrs is not reachable",
			publicEndpoint: true,
			manEnforced:    true,
			cidrs:          []string{"203.0.113.0/24", "10.0.0.0/8"},
			want:           false,
		},
		{
			name:           "public endpoint with open ipv4 cidr in allowlist is reachable",
			publicEndpoint: true,
			manEnforced:    true,
			cidrs:          []string{"203.0.113.0/24", "0.0.0.0/0"},
			want:           true,
		},
		{
			name:           "public endpoint with open ipv6 cidr in allowlist is reachable",
			publicEndpoint: true,
			manEnforced:    true,
			cidrs:          []string{"::/0"},
			want:           true,
		},
		{
			name:           "public endpoint with empty enforced allowlist is not reachable",
			publicEndpoint: true,
			manEnforced:    true,
			cidrs:          nil,
			want:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gkeControlPlaneInternetReachable(tt.publicEndpoint, tt.manEnforced, tt.cidrs)
			if got != tt.want {
				t.Errorf("gkeControlPlaneInternetReachable(%v, %v, %v) = %v, want %v",
					tt.publicEndpoint, tt.manEnforced, tt.cidrs, got, tt.want)
			}
		})
	}
}

func TestFirewallRuleOpenIngress(t *testing.T) {
	cases := []struct {
		name      string
		isAllow   bool
		direction string
		disabled  bool
		sources   []any
		want      bool
	}{
		{"allow ingress any v4", true, "INGRESS", false, []any{"0.0.0.0/0"}, true},
		{"allow ingress any v6", true, "INGRESS", false, []any{"::/0"}, true},
		{"allow ingress lowercase", true, "ingress", false, []any{"0.0.0.0/0"}, true},
		{"deny ingress any v4 is not open", false, "INGRESS", false, []any{"0.0.0.0/0"}, false},
		{"deny ingress any v6 is not open", false, "INGRESS", false, []any{"::/0"}, false},
		{"allow disabled", true, "INGRESS", true, []any{"0.0.0.0/0"}, false},
		{"allow egress", true, "EGRESS", false, []any{"0.0.0.0/0"}, false},
		{"allow scoped source", true, "INGRESS", false, []any{"10.0.0.0/8"}, false},
		{"allow no sources", true, "INGRESS", false, []any{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firewallRuleOpenIngress(c.isAllow, c.direction, c.disabled, c.sources); got != c.want {
				t.Errorf("firewallRuleOpenIngress(%v,%q,%v,%v) = %v, want %v", c.isAllow, c.direction, c.disabled, c.sources, got, c.want)
			}
		})
	}
}

func TestNetworkNameFromUrl(t *testing.T) {
	cases := map[string]string{
		"https://www.googleapis.com/compute/v1/projects/p/global/networks/default": "default",
		"projects/p/global/networks/my-vpc":                                        "my-vpc",
		"default":                                                                  "default",
		"":                                                                         "",
	}
	for in, want := range cases {
		if got := networkNameFromUrl(in); got != want {
			t.Errorf("networkNameFromUrl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirewallTargetsInstance(t *testing.T) {
	tags := map[string]bool{"web": true}
	sas := map[string]bool{"sa@project.iam.gserviceaccount.com": true}

	cases := []struct {
		name       string
		targetTags []any
		targetSAs  []any
		want       bool
	}{
		{"no targets applies to all", []any{}, []any{}, true},
		{"matching tag", []any{"web"}, []any{}, true},
		{"non-matching tag", []any{"db"}, []any{}, false},
		{"matching service account", []any{}, []any{"sa@project.iam.gserviceaccount.com"}, true},
		{"non-matching service account", []any{}, []any{"other@project.iam.gserviceaccount.com"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firewallTargetsInstance(c.targetTags, c.targetSAs, tags, sas); got != c.want {
				t.Errorf("firewallTargetsInstance(%v,%v) = %v, want %v", c.targetTags, c.targetSAs, got, c.want)
			}
		})
	}
}

// expoNetwork is the network URL every rule in the shadowing tests sits on, and
// expoInstance* are the instance's identity within it.
const expoNetwork = "projects/p/global/networks/vpc-a"

var (
	expoInstanceNetworks = map[string]bool{"vpc-a": true}
	expoInstanceTags     = map[string]bool{"expo-denied": true}
	expoInstanceSAs      = map[string]bool{}
)

// fwPorts builds the []any port list a firewall rule's protocol map carries.
func fwPorts(ports ...string) []any {
	out := make([]any, 0, len(ports))
	for _, p := range ports {
		out = append(out, p)
	}
	return out
}

// fwProtocols builds a single-protocol layer 4 match. No ports means every port.
func fwProtocols(protocol string, ports ...string) map[string]any {
	return map[string]any{protocol: fwPorts(ports...)}
}

func fwSources(cidrs ...string) []any {
	out := make([]any, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, c)
	}
	return out
}

// expoRule builds an INGRESS rule on the instance's network targeting the
// instance's tag, which is the shape every shadowing case varies from.
func expoRule(priority int64, allow bool, protocols map[string]any, sources []any) firewallIngressRule {
	return firewallIngressRule{
		priority:     priority,
		direction:    "INGRESS",
		allow:        allow,
		network:      expoNetwork,
		sourceRanges: sources,
		protocols:    protocols,
		targetTags:   []any{"expo-denied"},
	}
}

func TestParseFirewallPortSpec(t *testing.T) {
	cases := []struct {
		spec     string
		wantFrom int64
		wantTo   int64
		wantOk   bool
	}{
		{"22", 22, 22, true},
		{"20-25", 20, 25, true},
		{" 8000-8080 ", 8000, 8080, true},
		{"25-20", 20, 25, true},
		{"0-65535", 0, 65535, true},
		{"", 0, 0, false},
		{"ssh", 0, 0, false},
		{"20-", 0, 0, false},
		{"-25", 0, 0, false},
		{"20-25-30", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got, ok := parseFirewallPortSpec(c.spec)
			if ok != c.wantOk {
				t.Fatalf("parseFirewallPortSpec(%q) ok = %v, want %v", c.spec, ok, c.wantOk)
			}
			if !ok {
				return
			}
			if got.all {
				t.Fatalf("parseFirewallPortSpec(%q) returned an all-ports span", c.spec)
			}
			if got.from != c.wantFrom || got.to != c.wantTo {
				t.Errorf("parseFirewallPortSpec(%q) = %d-%d, want %d-%d", c.spec, got.from, got.to, c.wantFrom, c.wantTo)
			}
		})
	}
}

func TestFirewallProtocolCovers(t *testing.T) {
	cases := []struct {
		outer string
		inner string
		want  bool
	}{
		{"all", "tcp", true},
		{"all", "all", true},
		{"", "tcp", true},
		{"tcp", "tcp", true},
		{"TCP", "tcp", true},
		{"6", "tcp", true},
		{"tcp", "6", true},
		{"58", "ipv6-icmp", true},
		{"icmpv6", "ipv6-icmp", true},
		{"tcp", "udp", false},
		{"tcp", "all", false},
		{"icmp", "ipv6-icmp", false},
		{"6", "17", false},
	}
	for _, c := range cases {
		if got := firewallProtocolCovers(c.outer, c.inner); got != c.want {
			t.Errorf("firewallProtocolCovers(%q, %q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}

func TestFirewallPortRangeCovers(t *testing.T) {
	all := firewallPortRange{all: true}
	ssh := firewallPortRange{from: 22, to: 22}
	low := firewallPortRange{from: 1, to: 1024}
	high := firewallPortRange{from: 8000, to: 8080}

	cases := []struct {
		name  string
		outer firewallPortRange
		inner firewallPortRange
		want  bool
	}{
		{"all covers a single port", all, ssh, true},
		{"all covers all", all, all, true},
		{"bounded does not cover all", low, all, false},
		{"range covers a port inside it", low, ssh, true},
		{"port does not cover the enclosing range", ssh, low, false},
		{"disjoint ranges do not cover", low, high, false},
		{"range covers itself", high, high, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.outer.covers(c.inner); got != c.want {
				t.Errorf("covers() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestFirewallTrafficCovers(t *testing.T) {
	v4ssh := firewallTraffic{protocol: "tcp", ports: firewallPortRange{from: 22, to: 22}}
	v6ssh := firewallTraffic{ipv6: true, protocol: "tcp", ports: firewallPortRange{from: 22, to: 22}}
	v4all := firewallTraffic{protocol: "all", ports: firewallPortRange{all: true}}
	v6all := firewallTraffic{ipv6: true, protocol: "all", ports: firewallPortRange{all: true}}
	v4https := firewallTraffic{protocol: "tcp", ports: firewallPortRange{from: 443, to: 443}}
	v4udpSsh := firewallTraffic{protocol: "udp", ports: firewallPortRange{from: 22, to: 22}}

	cases := []struct {
		name  string
		outer firewallTraffic
		inner firewallTraffic
		want  bool
	}{
		{"v4 all covers v4 ssh", v4all, v4ssh, true},
		{"v4 all does not cover v6 ssh", v4all, v6ssh, false},
		{"v6 all does not cover v4 ssh", v6all, v4ssh, false},
		{"v6 all covers v6 ssh", v6all, v6ssh, true},
		{"tcp 22 does not cover tcp 443", v4ssh, v4https, false},
		{"tcp 22 does not cover udp 22", v4ssh, v4udpSsh, false},
		{"tcp 22 covers itself", v4ssh, v4ssh, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.outer.covers(c.inner); got != c.want {
				t.Errorf("covers() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestOpenSourceFamilies(t *testing.T) {
	cases := []struct {
		name    string
		sources []any
		wantV4  bool
		wantV6  bool
	}{
		{"any v4", fwSources("0.0.0.0/0"), true, false},
		{"any v6", fwSources("::/0"), false, true},
		{"both", fwSources("0.0.0.0/0", "::/0"), true, true},
		{"whitespace tolerated", fwSources(" 0.0.0.0/0 "), true, false},
		{"scoped range", fwSources("10.0.0.0/8"), false, false},
		{"empty", nil, false, false},
		{"non-string entries", []any{42, nil}, false, false},
		{"halves of the v4 internet are not recognized", fwSources("0.0.0.0/1", "128.0.0.0/1"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v4, v6 := openSourceFamilies(c.sources)
			if v4 != c.wantV4 || v6 != c.wantV6 {
				t.Errorf("openSourceFamilies(%v) = (%v, %v), want (%v, %v)", c.sources, v4, v6, c.wantV4, c.wantV6)
			}
		})
	}
}

// TestIngressTrafficUnreadableBias pins the asymmetry that keeps an input that
// could not be read from reporting an instance as protected: an allow rule with
// an unreadable layer 4 match widens to all traffic and stays exposed, while a
// deny rule with an unreadable match yields nothing and shadows nothing.
func TestIngressTrafficUnreadableBias(t *testing.T) {
	sources := fwSources("0.0.0.0/0")

	if got := allowIngressTraffic(sources, nil); len(got) != 1 ||
		got[0].protocol != firewallProtocolAll || !got[0].ports.all || got[0].ipv6 {
		t.Errorf("allowIngressTraffic with no protocols = %+v, want one v4 all/all entry", got)
	}
	if got := denyIngressTraffic(sources, nil); len(got) != 0 {
		t.Errorf("denyIngressTraffic with no protocols = %+v, want none", got)
	}

	unreadablePorts := fwProtocols("tcp", "ssh")
	got := allowIngressTraffic(sources, unreadablePorts)
	if len(got) != 1 || got[0].protocol != "tcp" || !got[0].ports.all {
		t.Errorf("allowIngressTraffic with an unparseable port = %+v, want one tcp all-ports entry", got)
	}
	if got := denyIngressTraffic(sources, unreadablePorts); len(got) != 0 {
		t.Errorf("denyIngressTraffic with an unparseable port = %+v, want none", got)
	}
}

// TestAllowIngressTrafficFansOutFamilies pins that a dual-stack open source
// produces one entry per address family, which is what stops an IPv4 deny from
// shadowing the IPv6 half.
func TestAllowIngressTrafficFansOutFamilies(t *testing.T) {
	got := allowIngressTraffic(fwSources("0.0.0.0/0", "::/0"), fwProtocols("tcp", "22"))
	if len(got) != 2 {
		t.Fatalf("allowIngressTraffic = %+v, want 2 entries", got)
	}
	v4, v6 := false, false
	for _, tr := range got {
		if tr.protocol != "tcp" || tr.ports.from != 22 || tr.ports.to != 22 {
			t.Errorf("entry %+v does not describe tcp/22", tr)
		}
		if tr.ipv6 {
			v6 = true
		} else {
			v4 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("allowIngressTraffic = %+v, want one IPv4 and one IPv6 entry", got)
	}
}

func TestUnshadowedOpenIngressFirewalls(t *testing.T) {
	cases := []struct {
		name  string
		rules []firewallIngressRule
		want  []int
	}{
		{
			// The live case: a DENY on tcp/22 at priority 500 in front of an
			// ALLOW on tcp/22 at priority 1000. Before priority was read, the
			// allow was reported open and the instance internetReachable.
			name: "lower-numbered deny shadows the allow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{},
		},
		{
			name: "allow survives a higher-numbered deny",
			rules: []firewallIngressRule{
				expoRule(2000, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			// GCP: "A rule with a deny action overrides another with an allow
			// action only if the two rules have the same priority."
			name: "deny wins at equal priority",
			rules: []firewallIngressRule{
				expoRule(1000, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{},
		},
		{
			name: "deny on a different port does not shadow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "443"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny on a different protocol does not shadow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("udp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "ipv4 deny does not shadow an ipv6 allow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("::/0")),
			},
			want: []int{1},
		},
		{
			name: "ipv6 deny does not shadow an ipv4 allow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("::/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "ipv4 deny leaves the ipv6 half of a dual-stack allow open",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0", "::/0")),
			},
			want: []int{1},
		},
		{
			name: "disabled deny does not shadow",
			rules: []firewallIngressRule{
				func() firewallIngressRule {
					r := expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0"))
					r.disabled = true
					return r
				}(),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny targeting a different tag does not shadow",
			rules: []firewallIngressRule{
				func() firewallIngressRule {
					r := expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0"))
					r.targetTags = []any{"other-tag"}
					return r
				}(),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny on another network does not shadow",
			rules: []firewallIngressRule{
				func() firewallIngressRule {
					r := expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0"))
					r.network = "projects/p/global/networks/vpc-b"
					return r
				}(),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "egress deny does not shadow",
			rules: []firewallIngressRule{
				func() firewallIngressRule {
					r := expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0"))
					r.direction = "EGRESS"
					return r
				}(),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny with a scoped source does not shadow an internet allow",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("10.0.0.0/8")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny on all protocols shadows every allow below it",
			rules: []firewallIngressRule{
				expoRule(100, false, fwProtocols("all"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1100, true, fwProtocols("udp", "53"), fwSources("0.0.0.0/0")),
			},
			want: []int{},
		},
		{
			name: "narrow deny in front of a broad allow leaves the rest open",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "1-1024"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "deny range covering the allow port shadows it",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "20-25"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{},
		},
		{
			name: "allow with a second unshadowed protocol survives",
			rules: []firewallIngressRule{
				expoRule(500, false, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
				expoRule(1000, true, map[string]any{
					"tcp": fwPorts("22"),
					"udp": fwPorts("53"),
				}, fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			// A deny whose layer 4 match could not be read must not be treated
			// as blocking traffic nobody proved was blocked.
			name: "deny with an unreadable protocol match does not shadow",
			rules: []firewallIngressRule{
				expoRule(500, false, nil, fwSources("0.0.0.0/0")),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{1},
		},
		{
			name: "untargeted deny shadows every instance in the network",
			rules: []firewallIngressRule{
				func() firewallIngressRule {
					r := expoRule(500, false, fwProtocols("all"), fwSources("0.0.0.0/0"))
					r.targetTags = nil
					return r
				}(),
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{},
		},
		{
			name: "allow with no deny in front stays open",
			rules: []firewallIngressRule{
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("0.0.0.0/0")),
			},
			want: []int{0},
		},
		{
			name: "scoped allow is never open",
			rules: []firewallIngressRule{
				expoRule(1000, true, fwProtocols("tcp", "22"), fwSources("10.0.0.0/8")),
			},
			want: []int{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := unshadowedOpenIngressFirewalls(c.rules, expoInstanceNetworks, expoInstanceTags, expoInstanceSAs)
			if len(got) != len(c.want) {
				t.Fatalf("unshadowedOpenIngressFirewalls() = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("unshadowedOpenIngressFirewalls() = %v, want %v", got, c.want)
				}
			}
		})
	}
}

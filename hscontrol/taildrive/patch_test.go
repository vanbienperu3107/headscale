package taildrive

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func TestConfigNodeCaps(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want []tailcfg.NodeCapability
	}{
		{"nil", nil, nil},
		{"none", &Config{}, nil},
		{"share only", &Config{Self: SelfCaps{Share: true}}, []tailcfg.NodeCapability{tailcfg.NodeAttrsTaildriveShare}},
		{"access only", &Config{Self: SelfCaps{Access: true}}, []tailcfg.NodeCapability{tailcfg.NodeAttrsTaildriveAccess}},
		{"both", &Config{Self: SelfCaps{Share: true, Access: true}}, []tailcfg.NodeCapability{tailcfg.NodeAttrsTaildriveShare, tailcfg.NodeAttrsTaildriveAccess}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.NodeCaps()
			if len(got) != len(tt.want) {
				t.Fatalf("NodeCaps() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("NodeCaps()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestConfigFilterRules(t *testing.T) {
	self := []netip.Prefix{netip.MustParsePrefix("100.64.0.11/32")}
	cfg := &Config{
		Grants: []Grant{
			{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Shares: []string{"dulieu"}, Access: "rw"},
			{SrcIPs: []string{"100.64.0.41/32"}, Cap: "drive-sharer"},
			{SrcIPs: []string{"100.64.0.99/32"}, Cap: "bogus"}, // unknown cap -> ignored
			{SrcIPs: nil, Cap: "drive"},                        // no src -> ignored
		},
	}

	rules := cfg.FilterRules(self)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}

	// Grant 0: owner side, cap/drive with {shares,access}.
	cg := rules[0].CapGrant[0]
	if len(rules[0].SrcIPs) != 1 || rules[0].SrcIPs[0] != "100.64.0.23/32" {
		t.Errorf("rule0 SrcIPs = %v", rules[0].SrcIPs)
	}
	if len(cg.Dsts) != 1 || cg.Dsts[0] != self[0] {
		t.Errorf("rule0 Dsts = %v, want %v", cg.Dsts, self)
	}
	vals, ok := cg.CapMap[tailcfg.PeerCapabilityTaildrive]
	if !ok || len(vals) != 1 {
		t.Fatalf("rule0 missing drive cap: %v", cg.CapMap)
	}
	var g struct {
		Shares []string `json:"shares"`
		Access string   `json:"access"`
	}
	if err := json.Unmarshal([]byte(vals[0]), &g); err != nil {
		t.Fatalf("unmarshal drive value: %v", err)
	}
	if g.Access != "rw" || len(g.Shares) != 1 || g.Shares[0] != "dulieu" {
		t.Errorf("drive value = %+v, want shares=[dulieu] access=rw", g)
	}

	// Grant 1: grantee side, cap/drive-sharer present.
	if _, ok := rules[1].CapGrant[0].CapMap[tailcfg.PeerCapabilityTaildriveSharer]; !ok {
		t.Errorf("rule1 missing drive-sharer cap: %v", rules[1].CapGrant[0].CapMap)
	}
}

func TestConfigFilterRulesEmpty(t *testing.T) {
	self := []netip.Prefix{netip.MustParsePrefix("100.64.0.11/32")}
	if r := (*Config)(nil).FilterRules(self); r != nil {
		t.Errorf("nil config should yield no rules, got %v", r)
	}
	if r := (&Config{}).FilterRules(self); r != nil {
		t.Errorf("empty config should yield no rules, got %v", r)
	}
	// No self prefixes -> no rules (CapGrant needs a destination).
	c := &Config{Grants: []Grant{{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Access: "rw"}}}
	if r := c.FilterRules(nil); r != nil {
		t.Errorf("no self prefixes should yield no rules, got %v", r)
	}
}

func TestConfigAccessDefaultsReadOnly(t *testing.T) {
	self := []netip.Prefix{netip.MustParsePrefix("100.64.0.11/32")}
	var g struct {
		Access string `json:"access"`
	}
	decode := func(cfg *Config) string {
		vals := cfg.FilterRules(self)[0].CapGrant[0].CapMap[tailcfg.PeerCapabilityTaildrive]
		if err := json.Unmarshal([]byte(vals[0]), &g); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return g.Access
	}

	// Missing/garbage access on a drive grant fails CLOSED to "ro" — a
	// dashboard bug must never silently escalate to write access.
	for _, bad := range []string{"", "RW", "rw ", "garbage"} {
		c := &Config{Grants: []Grant{{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Shares: []string{"s"}, Access: bad}}}
		if got := decode(c); got != "ro" {
			t.Errorf("access %q -> default %q, want ro", bad, got)
		}
	}
	// Only the exact literal "rw" grants write access.
	c := &Config{Grants: []Grant{{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Shares: []string{"s"}, Access: "rw"}}}
	if got := decode(c); got != "rw" {
		t.Errorf("explicit access = %q, want rw", got)
	}
}

func TestValidSingleHostIPs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"single ipv4 host kept", []string{"100.64.0.23/32"}, []string{"100.64.0.23/32"}},
		{"single ipv6 host kept", []string{"fd7a:115c:a1e0::1/128"}, []string{"fd7a:115c:a1e0::1/128"}},
		{"wildcard rejected", []string{"*"}, nil},
		{"broad ipv4 subnet rejected", []string{"100.64.0.0/24"}, nil},
		{"default route rejected", []string{"0.0.0.0/0"}, nil},
		{"ipv6 default route rejected", []string{"::/0"}, nil},
		{"garbage rejected", []string{"not-an-ip"}, nil},
		{"mixed: valid kept, invalid dropped", []string{"100.64.0.23/32", "100.64.0.0/24", "*"}, []string{"100.64.0.23/32"}},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validSingleHostIPs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("validSingleHostIPs(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("validSingleHostIPs(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestConfigFilterRulesRejectsWildcardSrc(t *testing.T) {
	self := []netip.Prefix{netip.MustParsePrefix("100.64.0.11/32")}
	// A grant whose ONLY src is a wildcard/broad CIDR must produce no rule at
	// all (not a rule with an empty SrcIPs, which tailcfg could interpret
	// differently) — this is the scenario a buggy/compromised dashboard could
	// trigger to try to widen a single-grantee share tailnet-wide.
	c := &Config{Grants: []Grant{{SrcIPs: []string{"*"}, Cap: "drive", Shares: []string{"s"}, Access: "rw"}}}
	if r := c.FilterRules(self); len(r) != 0 {
		t.Errorf("wildcard-only grant produced %d rules, want 0: %+v", len(r), r)
	}
	// A grant with one wildcard and one valid single-host src keeps only the
	// valid one.
	c2 := &Config{Grants: []Grant{{SrcIPs: []string{"*", "100.64.0.23/32"}, Cap: "drive", Shares: []string{"s"}, Access: "rw"}}}
	r2 := c2.FilterRules(self)
	if len(r2) != 1 || len(r2[0].SrcIPs) != 1 || r2[0].SrcIPs[0] != "100.64.0.23/32" {
		t.Errorf("mixed grant = %+v, want exactly [100.64.0.23/32]", r2)
	}
}

func TestConfigJSONParse(t *testing.T) {
	body := `{"self":{"share":true,"access":false},"grants":[{"src_ips":["100.64.0.23/32"],"cap":"drive","shares":["dulieu"],"access":"rw"}]}`
	var c Config
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !c.Self.Share || c.Self.Access {
		t.Errorf("self = %+v, want share=true access=false", c.Self)
	}
	if len(c.Grants) != 1 || c.Grants[0].Cap != "drive" || c.Grants[0].Shares[0] != "dulieu" {
		t.Errorf("grants = %+v", c.Grants)
	}
}

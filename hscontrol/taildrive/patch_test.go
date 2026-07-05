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

func TestConfigAccessDefaultsReadWrite(t *testing.T) {
	self := []netip.Prefix{netip.MustParsePrefix("100.64.0.11/32")}
	// Missing access on a drive grant defaults to "rw" (feature ships full RW).
	c := &Config{Grants: []Grant{{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Shares: []string{"s"}}}}
	vals := c.FilterRules(self)[0].CapGrant[0].CapMap[tailcfg.PeerCapabilityTaildrive]
	var g struct {
		Access string `json:"access"`
	}
	if err := json.Unmarshal([]byte(vals[0]), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.Access != "rw" {
		t.Errorf("default access = %q, want rw", g.Access)
	}
	// Explicit "ro" is preserved.
	c2 := &Config{Grants: []Grant{{SrcIPs: []string{"100.64.0.23/32"}, Cap: "drive", Shares: []string{"s"}, Access: "ro"}}}
	vals2 := c2.FilterRules(self)[0].CapGrant[0].CapMap[tailcfg.PeerCapabilityTaildrive]
	_ = json.Unmarshal([]byte(vals2[0]), &g)
	if g.Access != "ro" {
		t.Errorf("explicit access = %q, want ro", g.Access)
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

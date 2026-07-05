// Package taildrive fetches per-node Taildrive (folder share) configuration
// from the dashboard (CMS) and turns it into the netmap primitives the
// Tailscale client needs:
//
//   - self node attributes  "drive:share" / "drive:access"  (NodeCaps)
//   - packet-filter CapGrants carrying "tailscale.com/cap/drive" (owner side,
//     authorises a grantee) and "tailscale.com/cap/drive-sharer" (grantee side,
//     marks an owner as a mountable remote) (FilterRules)
//
// This mirrors the existing dashboard-patch pattern used by derp/patch.go
// (per-node DERPMap override) and dns/patch.go (split-DNS): one dashboard, one
// X-Headscale-Secret, fail-open with a short per-node cache. It deliberately
// avoids touching the policy engine — the dashboard is the source of truth and
// this module only augments each node's map response at build time.
package taildrive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// cache holds per-node Taildrive config fetched from the dashboard.
// Entry expires after 30s so CMS changes propagate within a minute, matching
// the DERPMap/split-DNS TTL. Reload pokes call Invalidate to apply sooner.
var cache sync.Map // key: nodeKey string -> cacheEntry

type cacheEntry struct {
	cfg       *Config // nil = no config for this node (404)
	expiresAt time.Time
}

// Config is the dashboard's answer for a single node ("what does THIS node need
// in its netmap for folder sharing"). All grants are expressed with the node as
// the CapGrant destination (dst), so they slot straight into the node's own
// packet filter.
type Config struct {
	Self   SelfCaps `json:"self"`
	Grants []Grant  `json:"grants"`
}

// SelfCaps are the node attributes to place in the node's own CapMap.
type SelfCaps struct {
	Share  bool `json:"share"`  // node hosts >=1 enabled share  -> drive:share
	Access bool `json:"access"` // node is a grantee somewhere    -> drive:access
}

// Grant is one capability grant destined for this node.
//
//	cap "drive":        this node is an OWNER; SrcIPs are grantees allowed to
//	                    access Shares with Access ("rw"|"ro").
//	cap "drive-sharer": this node is a GRANTEE; SrcIPs are the owners it may
//	                    mount (Shares/Access unused).
type Grant struct {
	SrcIPs []string `json:"src_ips"`
	Cap    string   `json:"cap"`
	Shares []string `json:"shares,omitempty"`
	Access string   `json:"access,omitempty"`
}

const (
	capDrive       = "drive"
	capDriveSharer = "drive-sharer"
)

// Get returns the per-node Taildrive config from the dashboard, or nil when the
// dashboard is disabled/unreachable or has nothing for this node (fail-open,
// exactly like derp.PatchDERPMap).
func Get(cfg types.DERPConfig, nodeKey string) *Config {
	if !cfg.DashboardEnabled || cfg.DashboardURL == "" || nodeKey == "" {
		return nil
	}

	if v, ok := cache.Load(nodeKey); ok {
		e := v.(cacheEntry)
		if time.Now().Before(e.expiresAt) {
			return e.cfg
		}
	}

	got, err := fetch(cfg, nodeKey)
	if err != nil {
		// fail-open: keep the tailnet working, retry on next map build.
		log.Warn().Err(err).Str("nodeKey", nodeKey).Msg("taildrive/patch: dashboard call failed, no folder-share caps this round")
		return nil
	}

	cache.Store(nodeKey, cacheEntry{cfg: got, expiresAt: time.Now().Add(30 * time.Second)})
	return got
}

// Invalidate drops the cached config for nodeKey so the next Get re-fetches
// immediately. Used by the dashboard "reload" poke.
func Invalidate(nodeKey string) {
	if nodeKey == "" {
		return
	}
	cache.Delete(nodeKey)
}

// InvalidateAll drops every cached config (poke-all).
func InvalidateAll() {
	cache.Range(func(k, _ any) bool {
		cache.Delete(k)
		return true
	})
}

func fetch(cfg types.DERPConfig, nodeKey string) (*Config, error) {
	timeoutMs := cfg.DashboardTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	url := fmt.Sprintf("%s/api/internal/taildrive/%s", cfg.DashboardURL, nodeKey)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if cfg.DashboardSecret != "" {
		req.Header.Set("X-Headscale-Secret", cfg.DashboardSecret)
	}

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no folder-share config for this node
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var out Config
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse taildrive config: %w", err)
	}
	return &out, nil
}

// NodeCaps returns the self node attributes to merge into this node's CapMap.
func (c *Config) NodeCaps() []tailcfg.NodeCapability {
	if c == nil {
		return nil
	}
	var caps []tailcfg.NodeCapability
	if c.Self.Share {
		caps = append(caps, tailcfg.NodeAttrsTaildriveShare)
	}
	if c.Self.Access {
		caps = append(caps, tailcfg.NodeAttrsTaildriveAccess)
	}
	return caps
}

// FilterRules returns extra packet-filter rules to append to this node's base
// filter. selfPrefixes are the node's own addresses (CapGrant destinations).
func (c *Config) FilterRules(selfPrefixes []netip.Prefix) []tailcfg.FilterRule {
	if c == nil || len(c.Grants) == 0 || len(selfPrefixes) == 0 {
		return nil
	}

	dsts := make([]netip.Prefix, len(selfPrefixes))
	copy(dsts, selfPrefixes)

	rules := make([]tailcfg.FilterRule, 0, len(c.Grants))
	for _, g := range c.Grants {
		if len(g.SrcIPs) == 0 {
			continue
		}
		capName, value, ok := g.capValue()
		if !ok {
			continue
		}
		rules = append(rules, tailcfg.FilterRule{
			SrcIPs: g.SrcIPs,
			CapGrant: []tailcfg.CapGrant{
				{
					Dsts:   dsts,
					CapMap: tailcfg.PeerCapMap{capName: value},
				},
			},
		})
	}
	return rules
}

// capValue maps a grant to its tailcfg capability name and raw JSON value.
func (g Grant) capValue() (tailcfg.PeerCapability, []tailcfg.RawMessage, bool) {
	switch g.Cap {
	case capDrive:
		access := g.Access
		if access != "ro" {
			access = "rw"
		}
		val, err := json.Marshal(struct {
			Shares []string `json:"shares"`
			Access string   `json:"access"`
		}{Shares: g.Shares, Access: access})
		if err != nil {
			return "", nil, false
		}
		return tailcfg.PeerCapabilityTaildrive, []tailcfg.RawMessage{tailcfg.RawMessage(val)}, true
	case capDriveSharer:
		// Value is unused by the client (presence-only check), but the cap key
		// must carry at least one entry to register.
		return tailcfg.PeerCapabilityTaildriveSharer, []tailcfg.RawMessage{tailcfg.RawMessage("{}")}, true
	default:
		return "", nil, false
	}
}

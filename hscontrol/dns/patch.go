package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// splitCache holds the dashboard-managed split-DNS rules (domain -> resolvers).
// This is GLOBAL, not per-node (unlike derp/patch.go's per-nodeKey cache) — the
// split-DNS routing table is the same for every node. Entry expires after 30s
// so CMS changes propagate within a minute, matching Feature B's DERPMap TTL.
var splitCache struct {
	sync.RWMutex
	routes    map[string][]*dnstype.Resolver
	expiresAt time.Time
	loaded    bool
}

// PatchSplitDNS merges dashboard-managed split-DNS rules into base.Routes.
// Reuses the same dashboard connection settings as Feature B (derp/patch.go) —
// one dashboard, one secret, no new config block needed.
//
// Behavior (same fail-open shape as derp.PatchDERPMap):
//   - dashboardURL empty or base nil -> base unchanged, no HTTP call
//   - Cache hit (< 30s) -> merge cached rules into base.Routes
//   - Dashboard call times out / errors -> log warning, reuse last known-good
//     rules (or none, if never fetched successfully) — never blocks or clears
//     existing rules on a transient error
//   - Dashboard returns valid JSON -> merge into base.Routes, refresh cache
//
// Static rules from config.yaml's dns.nameservers.split (if any) are preserved:
// this only ADDS/OVERWRITES entries from the dashboard, it never removes a
// domain that base.Routes already had from static config.
func PatchSplitDNS(dashboardURL, dashboardSecret string, timeoutMs int, base *tailcfg.DNSConfig) *tailcfg.DNSConfig {
	if base == nil || dashboardURL == "" {
		return base
	}

	routes := getCachedOrFetch(dashboardURL, dashboardSecret, timeoutMs)
	if len(routes) == 0 {
		return base
	}

	if base.Routes == nil {
		base.Routes = make(map[string][]*dnstype.Resolver, len(routes))
	}
	for domain, resolvers := range routes {
		base.Routes[domain] = resolvers
	}

	return base
}

func getCachedOrFetch(dashboardURL, dashboardSecret string, timeoutMs int) map[string][]*dnstype.Resolver {
	splitCache.RLock()
	if splitCache.loaded && time.Now().Before(splitCache.expiresAt) {
		routes := splitCache.routes
		splitCache.RUnlock()
		return routes
	}
	splitCache.RUnlock()

	routes, err := fetchSplitDNS(dashboardURL, dashboardSecret, timeoutMs)
	if err != nil {
		log.Warn().Err(err).Msg("dns/patch: dashboard call failed, keeping previous split-DNS rules")
		splitCache.RLock()
		prev := splitCache.routes
		splitCache.RUnlock()
		return prev
	}

	splitCache.Lock()
	splitCache.routes = routes
	splitCache.expiresAt = time.Now().Add(30 * time.Second)
	splitCache.loaded = true
	splitCache.Unlock()

	return routes
}

func fetchSplitDNS(dashboardURL, dashboardSecret string, timeoutMs int) (map[string][]*dnstype.Resolver, error) {
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	url := fmt.Sprintf("%s/api/internal/dns-split", dashboardURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if dashboardSecret != "" {
		req.Header.Set("X-Headscale-Secret", dashboardSecret)
	}

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Response shape: {"domain.": ["1.2.3.4", "https://doh.example/dns-query"], ...}
	var raw map[string][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse split-dns response: %w", err)
	}

	routes := make(map[string][]*dnstype.Resolver, len(raw))
	for domain, nameservers := range raw {
		resolvers := make([]*dnstype.Resolver, 0, len(nameservers))
		for _, ns := range nameservers {
			resolvers = append(resolvers, &dnstype.Resolver{Addr: ns})
		}
		routes[domain] = resolvers
	}

	return routes, nil
}

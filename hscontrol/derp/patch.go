package derp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// patchCache holds per-node DERPMap overrides fetched from the dashboard.
// Entry expires after 30s so config changes propagate within a minute.
var patchCache sync.Map // key: nodeKey string -> patchEntry

type patchEntry struct {
	derpMap   *tailcfg.DERPMap // nil = no override (404 or error)
	expiresAt time.Time
}

// PatchDERPMap fetches a per-node DERPMap override from the dashboard.
// Returns the override map if one exists, or base if not configured/unavailable.
//
// Behavior:
//   - Dashboard disabled or URL empty → return base unchanged
//   - Cache hit (< 30s) → return cached result
//   - Dashboard returns 404 → no override, cache nil for 30s
//   - Dashboard call times out / errors → log warning, return base (fail-open)
//   - Dashboard returns valid JSON → use as the node's DERPMap
func PatchDERPMap(cfg types.DERPConfig, nodeKey string, base *tailcfg.DERPMap) *tailcfg.DERPMap {
	if !cfg.DashboardEnabled || cfg.DashboardURL == "" || nodeKey == "" {
		return base
	}

	// Check cache
	if v, ok := patchCache.Load(nodeKey); ok {
		e := v.(patchEntry)
		if time.Now().Before(e.expiresAt) {
			if e.derpMap == nil {
				return base
			}
			return e.derpMap
		}
	}

	// Fetch from dashboard
	override, err := fetchDERPMapOverride(cfg, nodeKey)
	ttl := 30 * time.Second

	if err != nil {
		// fail-open: log and return base without caching (retry next call)
		log.Warn().Err(err).Str("nodeKey", nodeKey).Msg("derp/patch: dashboard call failed, using base DERPMap")
		return base
	}

	patchCache.Store(nodeKey, patchEntry{
		derpMap:   override, // nil if 404
		expiresAt: time.Now().Add(ttl),
	})

	if override == nil {
		return base
	}
	return override
}

func fetchDERPMapOverride(cfg types.DERPConfig, nodeKey string) (*tailcfg.DERPMap, error) {
	timeoutMs := cfg.DashboardTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	url := fmt.Sprintf("%s/api/internal/derp-map/%s", cfg.DashboardURL, nodeKey)
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
		return nil, nil // no override for this node
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var derpMap tailcfg.DERPMap
	if err := json.Unmarshal(body, &derpMap); err != nil {
		return nil, fmt.Errorf("parse DERPMap: %w", err)
	}
	return &derpMap, nil
}

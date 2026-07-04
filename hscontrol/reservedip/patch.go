// Package reservedip looks up a MAC-based static/historical IPv4 reservation
// from the CMS dashboard at node-registration time. Groundwork: the client
// (tailscale_mod fork only — see cmd/tailscaled/nodemode.go) reports its
// primary MAC via Hostinfo.WoLMACs[0], a real upstream tailcfg field that
// headscale otherwise never reads; reusing it avoids forking tailcfg.Hostinfo
// itself, which would force this repo's go.mod to replace its pinned
// upstream tailscale.com dependency — far riskier than reusing an existing
// field. A stock/default tailscaled build never sets WoLMACs, so this whole
// path is a no-op for it.
package reservedip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/rs/zerolog/log"
)

// FetchReservedIP asks the CMS dashboard (GET /api/internal/reserved-ip) for
// a static (admin-set) or historical (last-known) IPv4 for mac. Called once
// per new-node registration — no local caching needed, registration is rare
// compared to the 30s-cache map-poll patches in derp/patch.go and
// dns/patch.go. Fail-open: any error, non-200, empty body, or unparsable
// address returns (netip.Addr{}, false) so the caller falls back to normal
// IPAllocator.Next() — this must never block registration.
func FetchReservedIP(dashboardURL, dashboardSecret, mac string, timeoutMs int) (netip.Addr, bool) {
	if dashboardURL == "" || mac == "" {
		return netip.Addr{}, false
	}
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	url := fmt.Sprintf("%s/api/internal/reserved-ip?mac=%s", dashboardURL, mac)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, false
	}
	if dashboardSecret != "" {
		req.Header.Set("X-Headscale-Secret", dashboardSecret)
	}

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("mac", mac).Msg("reservedip: dashboard call failed, using normal IP allocation")
		return netip.Addr{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return netip.Addr{}, false
	}

	var out struct {
		IPv4 *string `json:"ipv4"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.IPv4 == nil || *out.IPv4 == "" {
		return netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(*out.IPv4)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr, true
}

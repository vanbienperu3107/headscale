package reservedip

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchReservedIP_PinParam verifies the pin-reconcile dashboard contract
// (docs/plan-ip-pin-consistency.md §10 B1/B2): pin=true appends "&pin=1" to
// the request so the dashboard suppresses its async stale-node reap and
// returns only the admin-set static_ipv4; pin=false (every pre-existing
// caller, and this package's own opportunistic new-node-creation caller in
// [github.com/juanfont/headscale/hscontrol/state]) leaves the request
// unchanged from before this parameter was added, preserving the legacy
// static||last_ipv4 + async-reap contract.
func TestFetchReservedIP_PinParam(t *testing.T) {
	// No colons in the MAC: the caller does not URL-encode it (see
	// patch.go), so a colon-free value keeps this assertion independent of
	// how net/http happens to (not) escape ":" in a query string.
	const mac = "aabbccddeeff"

	tests := []struct {
		name      string
		pin       bool
		wantQuery string
	}{
		{
			name:      "pin=false: query unchanged (legacy contract)",
			pin:       false,
			wantQuery: "mac=" + mac,
		},
		{
			name:      "pin=true: &pin=1 appended (reconcile contract)",
			pin:       true,
			wantQuery: "mac=" + mac + "&pin=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				gotQuery  string
				gotHeader string
			)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.RawQuery
				gotHeader = r.Header.Get("X-Headscale-Secret")

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"ipv4": "100.64.0.1"})
			}))
			defer srv.Close()

			addr, ok := FetchReservedIP(srv.URL, "s3cr3t", mac, 1000, tt.pin)
			if !ok {
				t.Fatalf("FetchReservedIP: got ok=false, want true")
			}

			if got := addr.String(); got != "100.64.0.1" {
				t.Fatalf("FetchReservedIP: got addr %s, want 100.64.0.1", got)
			}

			if gotQuery != tt.wantQuery {
				t.Fatalf("request query = %q, want %q", gotQuery, tt.wantQuery)
			}

			if gotHeader != "s3cr3t" {
				t.Fatalf("X-Headscale-Secret header = %q, want %q", gotHeader, "s3cr3t")
			}
		})
	}
}

// TestFetchReservedIP_FailOpen verifies the fail-open contract (unaffected
// by the pin param): no dashboardURL/mac, a non-200 response, or an
// unparsable body all return ok=false rather than an error, for both pin
// values.
func TestFetchReservedIP_FailOpen(t *testing.T) {
	t.Run("empty dashboardURL", func(t *testing.T) {
		_, ok := FetchReservedIP("", "", "aabbccddeeff", 500, true)
		if ok {
			t.Fatal("expected ok=false for empty dashboardURL")
		}
	})

	t.Run("empty mac", func(t *testing.T) {
		_, ok := FetchReservedIP("http://example.invalid", "", "", 500, true)
		if ok {
			t.Fatal("expected ok=false for empty mac")
		}
	})

	t.Run("non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		_, ok := FetchReservedIP(srv.URL, "", "aabbccddeeff", 1000, true)
		if ok {
			t.Fatal("expected ok=false for a non-200 response")
		}
	})

	t.Run("null ipv4 in body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ipv4": nil})
		}))
		defer srv.Close()

		// This is exactly the pin=1 "no static_ipv4 yet" response shape
		// (docs/plan-ip-pin-consistency.md §10 B2): the CHEAP branch must
		// treat it as "no pin" rather than erroring.
		_, ok := FetchReservedIP(srv.URL, "", "aabbccddeeff", 1000, true)
		if ok {
			t.Fatal("expected ok=false for a null ipv4 body")
		}
	})
}

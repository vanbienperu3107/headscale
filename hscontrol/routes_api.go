package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/types"
)

// comparePrefix orders netip.Prefix values by address then bits.
// netip.Prefix has no exported Compare method (unlike netip.Addr, which
// does) — this is the standard workaround.
func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}

	return a.Bits() - b.Bits()
}

// routeNodeJSON is the embedded node info returned in a route response.
type routeNodeJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	GivenName string `json:"givenName"`
}

// routeJSON is the route shape returned by GET /api/v1/routes.
// The ID is a synthetic "<nodeId>:<prefix_slug>" (no DB row).
type routeJSON struct {
	ID         string        `json:"id"`
	Prefix     string        `json:"prefix"`
	Advertised bool          `json:"advertised"`
	Enabled    bool          `json:"enabled"`
	IsPrimary  bool          `json:"isPrimary"`
	Node       routeNodeJSON `json:"node"`
}

// encodeSyntheticRouteID builds a URL-safe ID from a (nodeID, prefix) pair.
// "/" in the CIDR prefix is replaced with "_" to avoid path-segment issues.
// Example: node 6, "192.168.0.0/24" → "6:192.168.0.0_24"
func encodeSyntheticRouteID(nodeID types.NodeID, prefix netip.Prefix) string {
	return fmt.Sprintf("%d:%s", nodeID.Uint64(), strings.ReplaceAll(prefix.String(), "/", "_"))
}

// decodeSyntheticRouteID parses a synthetic route ID back into its components.
func decodeSyntheticRouteID(id string) (types.NodeID, netip.Prefix, error) {
	colon := strings.IndexByte(id, ':')
	if colon < 0 {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id: missing separator")
	}
	n, err := strconv.ParseUint(id[:colon], 10, 64)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id (node part): %w", err)
	}
	prefixStr := strings.ReplaceAll(id[colon+1:], "_", "/")
	prefix, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id (prefix %q): %w", prefixStr, err)
	}
	return types.NodeID(n), prefix, nil
}

func writeRouteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// RoutesListHandler implements GET /api/v1/routes.
// It builds a synthetic route list from node advertised/approved routes.
func (h *Headscale) RoutesListHandler(w http.ResponseWriter, r *http.Request) {
	nodes := h.state.ListNodes()
	routes := make([]routeJSON, 0)

	for _, node := range nodes.All() {
		nodeID := node.ID()
		announced := node.AnnouncedRoutes()
		approved := node.ApprovedRoutes().AsSlice()
		primary := h.state.GetNodePrimaryRoutes(nodeID)

		rn := routeNodeJSON{
			ID:        nodeID.String(),
			Name:      node.Hostname(),
			GivenName: node.GivenName(),
		}

		for _, prefix := range announced {
			routes = append(routes, routeJSON{
				ID:         encodeSyntheticRouteID(nodeID, prefix),
				Prefix:     prefix.String(),
				Advertised: true,
				Enabled:    slices.Contains(approved, prefix),
				IsPrimary:  slices.Contains(primary, prefix),
				Node:       rn,
			})
		}
	}

	writeRouteJSON(w, http.StatusOK, map[string]any{"routes": routes})
}

// RouteEnableHandler implements POST /api/v1/routes/{routeId}/enable.
// It adds the identified prefix to the node's approved routes.
func (h *Headscale) RouteEnableHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID, prefix, err := decodeSyntheticRouteID(vars["routeId"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, ok := h.state.GetNodeByID(nodeID)
	if !ok {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	approved := node.ApprovedRoutes().AsSlice()
	if !slices.Contains(approved, prefix) {
		approved = append(approved, prefix)
	}

	slices.SortFunc(approved, comparePrefix)
	approved = slices.Compact(approved)

	_, nodeChange, err := h.state.SetApprovedRoutes(nodeID, approved)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Change(nodeChange)

	writeRouteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RouteDeleteHandler implements DELETE /api/v1/routes/{routeId}.
// It removes the identified prefix from the node's approved routes.
func (h *Headscale) RouteDeleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID, prefix, err := decodeSyntheticRouteID(vars["routeId"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, ok := h.state.GetNodeByID(nodeID)
	if !ok {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	approved := node.ApprovedRoutes().AsSlice()
	approved = slices.DeleteFunc(approved, func(p netip.Prefix) bool {
		return p == prefix
	})

	_, nodeChange, err := h.state.SetApprovedRoutes(nodeID, approved)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Change(nodeChange)

	w.WriteHeader(http.StatusNoContent)
}

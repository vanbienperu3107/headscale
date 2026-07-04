package apiv1

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerRoutes)
}

// routeID encodes a (nodeID, prefix) pair as a URL-safe stable identifier.
// Format: "<nodeId>:<prefix-with-/-replaced-by-_>"
// Example: node 6, prefix "192.168.0.0/24" → "6:192.168.0.0_24"
func routeID(nodeID types.NodeID, prefix netip.Prefix) string {
	return fmt.Sprintf("%d:%s", nodeID.Uint64(), strings.ReplaceAll(prefix.String(), "/", "_"))
}

func parseRouteID(id string) (types.NodeID, netip.Prefix, error) {
	colon := strings.IndexByte(id, ':')
	if colon < 0 {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id: missing colon separator")
	}
	n, err := strconv.ParseUint(id[:colon], 10, 64)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id (node): %w", err)
	}
	prefixStr := strings.ReplaceAll(id[colon+1:], "_", "/")
	prefix, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return 0, netip.Prefix{}, fmt.Errorf("invalid route id (prefix %q): %w", prefixStr, err)
	}
	return types.NodeID(n), prefix, nil
}

// RouteNode is the embedded node info returned inside a Route.
type RouteNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	GivenName string `json:"givenName"`
}

// Route is the route shape returned by GET /api/v1/routes.
// The ID is a synthetic "<nodeId>:<prefix_slug>" — not a database row ID.
type Route struct {
	ID         string    `json:"id"`
	Prefix     string    `json:"prefix"`
	Advertised bool      `json:"advertised"`
	Enabled    bool      `json:"enabled"`
	IsPrimary  bool      `json:"isPrimary"`
	Node       RouteNode `json:"node"`
}

type (
	listRoutesOutput struct {
		Body struct {
			Routes []Route `json:"routes" nullable:"false"`
		}
	}

	enableRouteInput struct {
		RouteID string `path:"routeId"`
	}

	deleteRouteInput struct {
		RouteID string `path:"routeId"`
	}

	routeActionOutput struct {
		Body struct{}
	}
)

func registerRoutes(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "listRoutes",
		Method:      http.MethodGet,
		Path:        "/api/v1/routes",
		Summary:     "List advertised routes",
		Tags:        []string{"Routes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listRoutesOutput, error) {
		nodes := b.State.ListNodes()
		routes := make([]Route, 0)

		for _, node := range nodes.All() {
			nodeID := node.ID()
			announced := node.AnnouncedRoutes()
			approved := node.ApprovedRoutes().AsSlice()
			primary := b.State.GetNodePrimaryRoutes(nodeID)

			rn := RouteNode{
				ID:        nodeID.String(),
				Name:      node.Hostname(),
				GivenName: node.GivenName(),
			}

			for _, prefix := range announced {
				routes = append(routes, Route{
					ID:         routeID(nodeID, prefix),
					Prefix:     prefix.String(),
					Advertised: true,
					Enabled:    slices.Contains(approved, prefix),
					IsPrimary:  slices.Contains(primary, prefix),
					Node:       rn,
				})
			}
		}

		out := &listRoutesOutput{}
		out.Body.Routes = routes
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "enableRoute",
		Method:      http.MethodPost,
		Path:        "/api/v1/routes/{routeId}/enable",
		Summary:     "Enable (approve) a route",
		Tags:        []string{"Routes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *enableRouteInput) (*routeActionOutput, error) {
		nodeID, prefix, err := parseRouteID(in.RouteID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid route id", err)
		}

		node, ok := b.State.GetNodeByID(nodeID)
		if !ok {
			return nil, huma.Error404NotFound("node not found")
		}

		approved := node.ApprovedRoutes().AsSlice()
		if !slices.Contains(approved, prefix) {
			approved = append(approved, prefix)
		}
		slices.SortFunc(approved, netip.Prefix.Compare)
		approved = slices.Compact(approved)

		_, nodeChange, err := b.State.SetApprovedRoutes(nodeID, approved)
		if err != nil {
			return nil, huma.Error500InternalServerError("enabling route", err)
		}
		b.Change(nodeChange)

		return &routeActionOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deleteRoute",
		Method:      http.MethodDelete,
		Path:        "/api/v1/routes/{routeId}",
		Summary:     "Delete (disable) a route",
		Tags:        []string{"Routes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *deleteRouteInput) (*routeActionOutput, error) {
		nodeID, prefix, err := parseRouteID(in.RouteID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid route id", err)
		}

		node, ok := b.State.GetNodeByID(nodeID)
		if !ok {
			return nil, huma.Error404NotFound("node not found")
		}

		approved := node.ApprovedRoutes().AsSlice()
		approved = slices.DeleteFunc(approved, func(p netip.Prefix) bool {
			return p == prefix
		})

		_, nodeChange, err := b.State.SetApprovedRoutes(nodeID, approved)
		if err != nil {
			return nil, huma.Error500InternalServerError("disabling route", err)
		}
		b.Change(nodeChange)

		return &routeActionOutput{}, nil
	})
}

// Pin-reconcile: IP-pin consistency reconciler.
//
// See docs/plan-ip-pin-consistency.md for the full design (§0 code
// evidence, §1 invariant, §2 algorithm, §3 exact edit points, §9
// implement-time notes, §10 multi-system). Summary: a machine
// (machineKey, deterministic from serial on the tailscale_mod client) has
// an admin-set static IPv4 ("pin") in the CMS dashboard, keyed by MAC. This
// file makes registration converge that machine onto exactly one
// non-tagged node holding the pinned address, regardless of which
// user/variant/order it registers under — or, if the pin is genuinely
// unavailable (held by a different machine, or no pin at all), leaves the
// existing registration alone (KEEP; see the invariant in §1).
//
// Gated by cfg.DERP.PinReconcileMode ("off" default / "dryrun" / "on"); see
// [State.tryPinReconcile] for the exact per-mode contract.
package state

import (
	"fmt"
	"net/netip"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/reservedip"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// pinDecision is the outcome of the CHEAP/RE-PIN branch in
// docs/plan-ip-pin-consistency.md §2, computed by [decideRegistration].
type pinDecision int

const (
	// pinCheap: no pin, or the registering user's existing node ("me")
	// already holds it. The caller's ordinary update-in-place/create logic
	// runs unchanged; no IP move needed.
	pinCheap pinDecision = iota

	// pinKeepOtherMachine: the pin is held by a node with a different
	// MachineKey. The caller must KEEP its current registration path
	// (update-in-place, or create via the normal Next() allocator if no
	// node exists yet) — never take another machine's pinned address.
	// Audit only.
	pinKeepOtherMachine

	// pinRepinReclaim: the pin is held by a node sharing THIS machine's
	// key (a self node — possibly "me" itself under the wrong user, or a
	// different self node entirely). Under N1
	// (docs/plan-ip-pin-consistency.md §9.7) the address is already marked
	// used in ipAlloc, so recreating needs no ipAlloc.Reserve call — the
	// mark simply carries over to the new node within one transaction.
	pinRepinReclaim

	// pinRepinFree: the pin is not currently held by any node. The caller
	// must ipAlloc.Reserve(pin) before recreating; a Reserve failure means
	// a concurrent registration won the address first (TOCTOU) and the
	// caller must fall back to KEEP-style behaviour.
	pinRepinFree
)

// decideRegistration implements the CHEAP/RE-PIN branch of
// docs/plan-ip-pin-consistency.md §2. It is a pure function — no DB,
// NodeStore, or ipAlloc access — so it is fully unit-testable: all,
// registeringUID, pin/pinOK are plain values, and resolveHolder is an
// injected lookup of "which node currently holds address addr"
// ([State.ResolveNode] wired to a string query in production; a plain map
// in tests), returning ok=false when nothing holds it.
//
// all must already be restricted to the machine's own nodes, keyed by
// owning UserID, exactly as returned by
// [State.GetNodesByMachineKeyAllUsers] (tagged nodes live under
// UserID(0)). Callers MUST exclude tagged registrations before calling
// decideRegistration — reconcile never reclaims or self-heals a tagged
// node (docs/plan-ip-pin-consistency.md §4, §9.4); this function does not
// re-derive that guard, it trusts the caller.
func decideRegistration(
	all map[types.UserID]types.NodeView,
	registeringUID types.UserID,
	pin netip.Addr,
	pinOK bool,
	resolveHolder func(addr netip.Addr) (types.NodeView, bool),
) pinDecision {
	me, meOK := all[registeringUID]

	if !pinOK || (meOK && me.Valid() && me.HasIP(pin)) {
		return pinCheap
	}

	holder, holderOK := resolveHolder(pin)
	if !holderOK || !holder.Valid() {
		return pinRepinFree
	}

	// holder belongs to this machine iff it appears in `all` (which the
	// caller has already restricted to nodes sharing this machineKey).
	for _, n := range all {
		if n.Valid() && n.ID() == holder.ID() {
			return pinRepinReclaim
		}
	}

	return pinKeepOtherMachine
}

// selfNodesExcept returns every non-tagged node in all except the one
// identified by keepID. types.NodeID(0) — which no real, persisted node
// ever has (GORM auto-increment primary keys start at 1) — means "keep
// none": the recreate path uses this to select every self node for
// deletion. Tagged nodes (UserID(0) in `all`) are never included: reconcile
// never touches them (docs/plan-ip-pin-consistency.md §4/§9.4).
func selfNodesExcept(all map[types.UserID]types.NodeView, keepID types.NodeID) []types.NodeView {
	var out []types.NodeView

	for uid, n := range all {
		if uid == 0 || !n.Valid() || n.ID() == keepID {
			continue
		}

		out = append(out, n)
	}

	return out
}

// withoutAddr returns ips with pin removed (if present). Used so a deleted
// node's addresses are freed back to ipAlloc EXCEPT the pin address, which
// must stay marked "used" — now by whichever node replaced its holder(s)
// (docs/plan-ip-pin-consistency.md §2/§3: "never free the pin address").
func withoutAddr(ips []netip.Addr, pin netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))

	for _, a := range ips {
		if a != pin {
			out = append(out, a)
		}
	}

	return out
}

// pinOutcome is the result of [State.tryPinReconcile].
type pinOutcome struct {
	// handled is true when reconcile fully computed the registration
	// result (a RE-PIN recreate) and the caller must return
	// node/change/err directly, skipping its normal update-in-place/create
	// logic entirely.
	handled bool
	node    types.NodeView
	change  change.Change

	// pin/pinOK are populated whenever the dashboard was actually queried
	// (mode is "dryrun" or "on" and the client reported a MAC), regardless
	// of handled, so the caller can reuse them for
	// [State.reconcileDeleteSelf]'s neverFree instead of fetching a second
	// time.
	pin   netip.Addr
	pinOK bool
}

// tryPinReconcile is the entry point for docs/plan-ip-pin-consistency.md
// §2, called once per registration (from [State.HandleNodeFromAuthPath] or
// [State.HandleNodeFromPreAuthKey]) right after `all` (this machine's own
// nodes, from [State.GetNodesByMachineKeyAllUsers]) is known, BEFORE the
// caller's normal update-in-place/create logic runs — the RE-PIN recreate
// must happen before any client-visible response is built, or the client
// would receive a node about to be immediately superseded.
//
// mode=="off" (default; also any value other than "dryrun"/"on") is a pure
// no-op: outcome is always the zero value and nothing is queried or
// mutated, so callers behave exactly as upstream. mode=="dryrun" queries
// the dashboard (without "&pin=1", so the dashboard's own async reap is
// unaffected — docs/plan-ip-pin-consistency.md §10 B1) and logs the
// decision it would make, but outcome.handled is always false — the
// caller's normal logic runs unchanged. mode=="on" acts: pinCheap/
// pinKeepOtherMachine decisions still return handled=false (the caller's
// normal logic must still produce its own finalNode) — the caller is
// responsible for calling [State.reconcileDeleteSelf] afterward with that
// finalNode's ID, reusing outcome.pin/outcome.pinOK for neverFree.
// pinRepinReclaim/pinRepinFree decisions return handled=true with the
// complete result the caller should return directly.
//
// newNodeParamsForRecreate must be a fully-populated [newNodeParams] as the
// caller would build for an ordinary new-node creation (User, MachineKey,
// NodeKey, DiscoKey, Hostname, Hostinfo, Endpoints, Expiry,
// RegisterMethod, PreAuthKey) — tryPinReconcile fills in
// IPv4Reserved/ApprovedRoutesCarry/GivenNameCarry itself from all/the pin.
func (s *State) tryPinReconcile(
	all map[types.UserID]types.NodeView,
	registeringUID types.UserID,
	hostinfo *tailcfg.Hostinfo,
	newNodeParamsForRecreate newNodeParams,
) pinOutcome {
	mode := s.cfg.DERP.PinReconcileMode
	if mode != "dryrun" && mode != "on" {
		return pinOutcome{}
	}

	mac := primaryMACFromHostinfo(hostinfo)
	if mac == "" {
		return pinOutcome{}
	}

	// Only mode=="on" sends "&pin=1" (docs/plan-ip-pin-consistency.md §10
	// B1): dryrun must never disable the dashboard's own async reap while
	// headscale reconcile is not yet authoritative.
	pin, pinOK := reservedip.FetchReservedIP(
		s.cfg.DERP.DashboardURL, s.cfg.DERP.DashboardSecret, mac,
		s.cfg.DERP.DashboardTimeoutMs, mode == "on",
	)
	if !pinOK {
		return pinOutcome{}
	}

	kind := decideRegistration(all, registeringUID, pin, pinOK, func(addr netip.Addr) (types.NodeView, bool) {
		return s.ResolveNode(addr.String())
	})

	// newLogEvt returns a fresh event pre-loaded with the fields common to
	// every branch below. zerolog events must each get exactly one
	// terminating Msg/Msgf/Send call — a shared *zerolog.Event finished in
	// one branch and silently abandoned in another would just drop that
	// branch's log line, not fail loudly, so every branch below builds and
	// finishes its own instead of sharing one.
	newLogEvt := func() *zerolog.Event {
		return log.Info().
			Str("pin.mode", mode).
			Str("pin.ipv4", pin.String()).
			Str(zf.MachineKey, newNodeParamsForRecreate.MachineKey.ShortString())
	}

	switch kind {
	case pinCheap:
		newLogEvt().Msg("pin-reconcile: node already at pin (or no pin for this user), no action")

		return pinOutcome{pin: pin, pinOK: pinOK}
	case pinKeepOtherMachine:
		newLogEvt().Msg("pin-reconcile: pin held by another machine, keeping current node (audit)")

		return pinOutcome{pin: pin, pinOK: pinOK}
	}

	if mode != "on" {
		newLogEvt().Bool("pin.would_reclaim", kind == pinRepinReclaim).
			Msg("pin-reconcile: dryrun, would recreate at pin")

		return pinOutcome{pin: pin, pinOK: pinOK}
	}

	newLogEvt().Msg("pin-reconcile: mode=on, attempting recreate at pin")

	// Every self node is replaced by the recreate below (newest wins,
	// docs/plan-ip-pin-consistency.md §1) — this naturally includes "me"
	// (wrong IPv4) and, in the reclaim case, whichever self node currently
	// holds pin.
	deleteNodes := selfNodesExcept(all, 0)

	pinWasFree := kind == pinRepinFree
	if pinWasFree {
		if _, err := s.ipAlloc.Reserve(pin); err != nil {
			log.Warn().Err(err).Str("pin.ipv4", pin.String()).
				Msg("pin-reconcile: lost race reserving pin, keeping current node")

			return pinOutcome{pin: pin, pinOK: pinOK}
		}
	}

	params := newNodeParamsForRecreate
	params.IPv4Reserved = &pin

	if me, ok := all[registeringUID]; ok && me.Valid() {
		params.ApprovedRoutesCarry = me.ApprovedRoutes().AsSlice()
		params.GivenNameCarry = me.GivenName()
	}

	newNode, removals, err := s.reconcileRecreate(deleteNodes, params, pin, pinWasFree)
	if err != nil {
		log.Error().Err(err).Str("pin.ipv4", pin.String()).
			Msg("pin-reconcile: recreate failed, keeping existing node(s)")

		return pinOutcome{pin: pin, pinOK: pinOK}
	}

	merged := change.NodeAdded(newNode.ID())
	for _, r := range removals {
		merged = merged.Merge(r)
	}

	log.Info().
		Uint64(zf.NodeID, newNode.ID().Uint64()).
		Str("pin.ipv4", pin.String()).
		Int("nodes_removed", len(removals)).
		Msg("pin-reconcile: recreated node at pin")

	return pinOutcome{handled: true, node: newNode, change: merged, pin: pin, pinOK: pinOK}
}

// reconcileRecreate performs the RE-PIN transactional recreate: plan
// docs/plan-ip-pin-consistency.md §2 (N1 simplification — no ipAlloc
// ReserveReclaim/RollbackReclaim). deleteNodes are every self node (this
// machine's own, non-tagged) being replaced — including "me" (wrong IPv4)
// and, in the reclaim case, whichever self node currently holds pin.
// params must already carry User/MachineKey/NodeKey/DiscoKey/Hostname/
// Hostinfo/Endpoints/Expiry/RegisterMethod/PreAuthKey (built by the caller
// exactly as for an ordinary new-node creation) plus IPv4Reserved=&pin.
//
// pinWasFree indicates the caller already called ipAlloc.Reserve(pin) to
// claim it (the pin-free branch); when false (the reclaim branch), pin is
// already marked "used" in ipAlloc by one of deleteNodes, and N1 says that
// marking simply carries over to the new node within this one transaction —
// no ipAlloc mutation needed for the address itself.
//
// Delete + create run in ONE database transaction (finding F-C): if the
// create fails, the transaction rolls back — deleteNodes are NOT actually
// gone — and this function undoes only what it did OUTSIDE the transaction
// (the pin-free branch's Reserve; the reclaim branch never touched
// ipAlloc). NodeStore is only updated after a successful commit, via
// [NodeStore.SwapNode], so no snapshot ever shows both an old holder and
// the new node (finding H5).
//
// Returns the new node, one [change.NodeRemoved] per deleted node, and any
// error. A non-nil error means nothing was mutated beyond the pinWasFree
// Reserve/FreeIPs pair described above — the caller must treat this as
// KEEP.
func (s *State) reconcileRecreate(
	deleteNodes []types.NodeView,
	params newNodeParams,
	pin netip.Addr,
	pinWasFree bool,
) (types.NodeView, []change.Change, error) {
	nodeToRegister, err := s.buildNodeRow(params)
	if err != nil {
		if pinWasFree {
			s.ipAlloc.FreeIPs([]netip.Addr{pin})
		}

		return types.NodeView{}, nil, fmt.Errorf("pin-reconcile: building recreated node row: %w", err)
	}

	savedNode, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		for _, n := range deleteNodes {
			if err := hsdb.DeleteNode(tx, n.AsStruct()); err != nil {
				return nil, fmt.Errorf("deleting stale self node %d: %w", n.ID(), err)
			}
		}

		if err := tx.Save(nodeToRegister).Error; err != nil {
			return nil, fmt.Errorf("saving recreated node: %w", err)
		}

		// Finding F1: mirror the re-registration gate at
		// HandleNodeFromPreAuthKey (not the plain createAndSaveNewNode
		// gate, which lacks !Used) — a one-shot key already marked Used
		// by the FIRST registration must not be resubmitted, or the
		// atomic compare-and-set in [hsdb.UsePreAuthKey] rejects it and
		// every future re-pin for this machine would fail permanently.
		if params.PreAuthKey != nil && !params.PreAuthKey.Reusable && !params.PreAuthKey.Used {
			if err := hsdb.UsePreAuthKey(tx, params.PreAuthKey); err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return nodeToRegister, nil
	})
	if err != nil {
		// Transaction rolled back: deleteNodes are still in the database.
		// Undo only what happened OUTSIDE the transaction. The freshly
		// allocated IPv6 (inside buildNodeRow, via allocateNodeIPs) is
		// left abandoned in ipAlloc on failure, mirroring
		// createAndSaveNewNode's existing accepted behaviour for any
		// failed create (docs/plan-ip-pin-consistency.md §0).
		if pinWasFree {
			s.ipAlloc.FreeIPs([]netip.Addr{pin})
		}

		return types.NodeView{}, nil, fmt.Errorf("pin-reconcile: recreate transaction failed, keeping existing node(s): %w", err)
	}

	deleteIDs := make([]types.NodeID, 0, len(deleteNodes))
	for _, n := range deleteNodes {
		deleteIDs = append(deleteIDs, n.ID())
	}

	newNodeView := s.nodeStore.SwapNode(deleteIDs, *savedNode)

	removals := make([]change.Change, 0, len(deleteNodes))

	for _, n := range deleteNodes {
		s.ipAlloc.FreeIPs(withoutAddr(n.IPs(), pin))
		removals = append(removals, change.NodeRemoved(n.ID()))
	}

	return newNodeView, removals, nil
}

// reconcileDeleteSelf implements the "newest wins" self-node consolidation
// (docs/plan-ip-pin-consistency.md §1/§2/§3): every OTHER non-tagged node
// sharing this machine's key is deleted once keepID has been confirmed as
// the machine's one true node — the CHEAP/KEEP decisions' own
// update-in-place or create already ran and produced keepID; this function
// only runs AFTER that. Unlike [State.reconcileRecreate], each delete here
// is independent and best-effort: a failure only leaves a stale duplicate
// node behind, which self-heals on the machine's next registration, so it
// does not need to share a transaction with anything else.
//
// neverFree/neverFreeOK protect the pin address from ever being freed by
// this cleanup — defensive: in normal operation no OTHER self node can
// hold the same address ipAlloc already handed to keepID, but the guard
// costs nothing and closes finding F-D (two self nodes momentarily holding
// the same pin) if it were ever to happen.
func (s *State) reconcileDeleteSelf(
	all map[types.UserID]types.NodeView,
	keepID types.NodeID,
	neverFree netip.Addr,
	neverFreeOK bool,
) []change.Change {
	var removals []change.Change

	for _, n := range selfNodesExcept(all, keepID) {
		if err := s.db.DeleteNode(n.AsStruct()); err != nil {
			log.Error().Err(err).Uint64(zf.NodeID, n.ID().Uint64()).
				Msg("pin-reconcile: failed to delete stale self node, leaving in place for next reconcile")

			continue
		}

		s.nodeStore.DeleteNode(n.ID())

		ips := n.IPs()
		if neverFreeOK {
			ips = withoutAddr(ips, neverFree)
		}

		s.ipAlloc.FreeIPs(ips)

		removals = append(removals, change.NodeRemoved(n.ID()))
	}

	return removals
}

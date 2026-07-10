package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

// pinTestNode builds a minimal, valid [types.NodeView] for
// [decideRegistration]/[selfNodesExcept] tests: a real MachineKey/NodeKey
// pair (freshly generated; uniqueness across nodes within one test doesn't
// matter here), the given ID/UserID/IPv4.
func pinTestNode(id types.NodeID, userID uint, ipv4 string) types.NodeView {
	addr := netip.MustParseAddr(ipv4)
	n := types.Node{
		ID:         id,
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "node",
		GivenName:  "node",
		UserID:     new(userID),
		User:       &types.User{Name: "user"},
		IPv4:       &addr,
	}

	return n.View()
}

// TestDecideRegistration exercises every branch of the CHEAP/RE-PIN
// decision in docs/plan-ip-pin-consistency.md §2, matching the unit list in
// §6: me-correct -> CHEAP; me-wrong+pin-free -> RE-PIN(free);
// me-wrong+pin-held-by-self -> RE-PIN(reclaim);
// me-wrong+pin-held-by-OTHER -> KEEP; no-me+pin-free -> RE-PIN(free,
// create); no-me+pin-held-by-OTHER -> KEEP(create Next()); pin-nil ->
// CHEAP; two self holders sharing a machine key -> reclaim (the neverFree
// consequence itself, F-D, is exercised by the NodeStore/reconcile-level
// tests, not this pure function).
func TestDecideRegistration(t *testing.T) {
	const registeringUID types.UserID = 1

	pin := netip.MustParseAddr("100.64.0.5")

	noHolder := func(netip.Addr) (types.NodeView, bool) { return types.NodeView{}, false }

	otherMachineHolder := func(netip.Addr) (types.NodeView, bool) {
		// NodeID 99 never appears in `all` in these tests, so it stands in
		// for "a node on a different machine".
		return pinTestNode(99, 99, "100.64.0.5"), true
	}

	tests := []struct {
		name           string
		all            map[types.UserID]types.NodeView
		registeringUID types.UserID
		pin            netip.Addr
		pinOK          bool
		resolveHolder  func(netip.Addr) (types.NodeView, bool)
		want           pinDecision
	}{
		{
			name:           "pin not ok (nil) -> CHEAP",
			all:            map[types.UserID]types.NodeView{},
			registeringUID: registeringUID,
			pin:            netip.Addr{},
			pinOK:          false,
			resolveHolder:  noHolder,
			want:           pinCheap,
		},
		{
			name: "me already holds pin -> CHEAP",
			all: map[types.UserID]types.NodeView{
				registeringUID: pinTestNode(1, 1, "100.64.0.5"),
			},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			// The CHEAP short-circuit must fire before resolveHolder is
			// ever consulted. This closure returns a value that would
			// produce a DIFFERENT decision (pinRepinReclaim) if it were
			// mistakenly called, so a broken short-circuit fails the
			// assertion below rather than needing a separate "was it
			// called" check.
			resolveHolder: func(netip.Addr) (types.NodeView, bool) {
				return pinTestNode(1, 1, "100.64.0.5"), true
			},
			want: pinCheap,
		},
		{
			name: "me holds a different IP, pin free -> RE-PIN free",
			all: map[types.UserID]types.NodeView{
				registeringUID: pinTestNode(1, 1, "100.64.0.9"),
			},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder:  noHolder,
			want:           pinRepinFree,
		},
		{
			name: "me holds a different IP, pin held by a self node -> RE-PIN reclaim",
			all: map[types.UserID]types.NodeView{
				registeringUID:  pinTestNode(1, 1, "100.64.0.9"),
				types.UserID(2): pinTestNode(2, 2, "100.64.0.5"),
			},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder: func(netip.Addr) (types.NodeView, bool) {
				return pinTestNode(2, 2, "100.64.0.5"), true
			},
			want: pinRepinReclaim,
		},
		{
			name: "me holds a different IP, pin held by another machine -> KEEP",
			all: map[types.UserID]types.NodeView{
				registeringUID: pinTestNode(1, 1, "100.64.0.9"),
			},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder:  otherMachineHolder,
			want:           pinKeepOtherMachine,
		},
		{
			name:           "no me, pin free -> RE-PIN free (create)",
			all:            map[types.UserID]types.NodeView{},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder:  noHolder,
			want:           pinRepinFree,
		},
		{
			name:           "no me, pin held by another machine -> KEEP (create via Next())",
			all:            map[types.UserID]types.NodeView{},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder:  otherMachineHolder,
			want:           pinKeepOtherMachine,
		},
		{
			// F-D setup: two OTHER self nodes exist (neither is `me`); the
			// pin happens to be held by one of them. decideRegistration
			// must still recognise it as a self holder (present in `all`)
			// and choose reclaim, not KEEP.
			name: "two self nodes besides me, pin held by one of them -> reclaim",
			all: map[types.UserID]types.NodeView{
				registeringUID:  pinTestNode(1, 1, "100.64.0.9"),
				types.UserID(3): pinTestNode(3, 3, "100.64.0.5"),
				types.UserID(4): pinTestNode(4, 4, "100.64.0.10"),
			},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder: func(netip.Addr) (types.NodeView, bool) {
				return pinTestNode(3, 3, "100.64.0.5"), true
			},
			want: pinRepinReclaim,
		},
		{
			name:           "resolveHolder reports invalid NodeView -> RE-PIN free",
			all:            map[types.UserID]types.NodeView{},
			registeringUID: registeringUID,
			pin:            pin,
			pinOK:          true,
			resolveHolder: func(netip.Addr) (types.NodeView, bool) {
				return types.NodeView{}, true // ok=true but Valid()==false
			},
			want: pinRepinFree,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideRegistration(tt.all, tt.registeringUID, tt.pin, tt.pinOK, tt.resolveHolder)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSelfNodesExcept verifies the helper both call sites of reconcile use
// to pick delete candidates: tagged nodes (UserID(0)) are always excluded,
// keepID is excluded when present, and keepID==0 (the recreate path's "keep
// none" sentinel) selects every non-tagged self node.
func TestSelfNodesExcept(t *testing.T) {
	all := map[types.UserID]types.NodeView{
		0:               pinTestNode(1, 0, "100.64.0.1"), // tagged, must never be selected
		types.UserID(2): pinTestNode(2, 2, "100.64.0.2"),
		types.UserID(3): pinTestNode(3, 3, "100.64.0.3"),
	}

	t.Run("keep one, delete the other non-tagged node", func(t *testing.T) {
		got := selfNodesExcept(all, types.NodeID(2))
		require.Len(t, got, 1)
		assert.Equal(t, types.NodeID(3), got[0].ID())
	})

	t.Run("keepID 0 sentinel selects every non-tagged node", func(t *testing.T) {
		got := selfNodesExcept(all, types.NodeID(0))
		require.Len(t, got, 2)

		ids := map[types.NodeID]bool{got[0].ID(): true, got[1].ID(): true}
		assert.True(t, ids[types.NodeID(2)])
		assert.True(t, ids[types.NodeID(3)])
	})

	t.Run("tagged-only map selects nothing", func(t *testing.T) {
		taggedOnly := map[types.UserID]types.NodeView{
			0: pinTestNode(1, 0, "100.64.0.1"),
		}
		got := selfNodesExcept(taggedOnly, types.NodeID(0))
		assert.Empty(t, got)
	})
}

// TestWithoutAddr verifies the "never free the pin address" helper used by
// both reconcileRecreate and reconcileDeleteSelf.
func TestWithoutAddr(t *testing.T) {
	a := netip.MustParseAddr("100.64.0.1")
	b := netip.MustParseAddr("100.64.0.2")
	pin := netip.MustParseAddr("100.64.0.3")

	got := withoutAddr([]netip.Addr{a, pin, b}, pin)
	assert.Equal(t, []netip.Addr{a, b}, got)

	// pin absent: nothing removed.
	got = withoutAddr([]netip.Addr{a, b}, pin)
	assert.Equal(t, []netip.Addr{a, b}, got)
}

// TestNodeStoreSwapNode verifies the atomic delete+insert primitive
// (docs/plan-ip-pin-consistency.md §3/H5) the pin-reconcile recreate path
// relies on: one applyBatch iteration removes every deleteID and inserts
// newNode, so no intermediate snapshot can ever show both an old holder and
// its replacement (or zero nodes for the machine).
func TestNodeStoreSwapNode(t *testing.T) {
	node1 := createTestNode(1, 1, "user1", "old-node-1")
	node2 := createTestNode(2, 1, "user1", "old-node-2")
	node3 := createTestNode(3, 2, "user2", "unrelated-node")
	initialNodes := types.Nodes{&node1, &node2, &node3}

	store := NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()
	defer store.Stop()

	newNode := createTestNode(4, 1, "user1", "recreated-node")

	result := store.SwapNode([]types.NodeID{1, 2}, newNode)
	require.True(t, result.Valid())
	assert.Equal(t, types.NodeID(4), result.ID())

	snapshot := store.data.Load()

	// Old nodes are gone.
	assert.NotContains(t, snapshot.nodesByID, types.NodeID(1))
	assert.NotContains(t, snapshot.nodesByID, types.NodeID(2))

	// New node is present, unrelated node untouched.
	require.Contains(t, snapshot.nodesByID, types.NodeID(4))
	require.Contains(t, snapshot.nodesByID, types.NodeID(3))
	assert.Len(t, snapshot.nodesByID, 2)

	// GetNode must reflect the swap (exercises the public read path, not
	// just the raw snapshot map).
	view, ok := store.GetNode(4)
	require.True(t, ok)
	assert.True(t, view.Valid())

	_, ok = store.GetNode(1)
	assert.False(t, ok)
	_, ok = store.GetNode(2)
	assert.False(t, ok)
}

// TestNodeStoreSwapNode_DeleteAll verifies the recreate path's "keep none"
// case: every self node for a machine is deleted and replaced by exactly
// one new node, atomically (the machine is never observed with zero nodes
// nor with the old node(s) still present alongside the new one).
func TestNodeStoreSwapNode_DeleteAll(t *testing.T) {
	node1 := createTestNode(1, 1, "user1", "self-a")
	node2 := createTestNode(2, 2, "user2", "self-b")
	initialNodes := types.Nodes{&node1, &node2}

	store := NewNodeStore(initialNodes, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	store.Start()
	defer store.Stop()

	newNode := createTestNode(3, 1, "user1", "recreated")

	result := store.SwapNode([]types.NodeID{1, 2}, newNode)
	require.True(t, result.Valid())

	snapshot := store.data.Load()
	assert.Len(t, snapshot.nodesByID, 1)
	require.Contains(t, snapshot.nodesByID, types.NodeID(3))
}

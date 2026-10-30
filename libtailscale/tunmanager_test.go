package libtailscale

import "testing"

// The manager is selected once at backend construction. Subsequent FD installs
// and lifecycle calls must use that same object, rather than a second device.
func TestTUNManagerFactorySelectsCustomManager(t *testing.T) {
	previous := NewTUNManager
	t.Cleanup(func() { NewTUNManager = previous })
	want := &factoryTestManager{}
	calls := 0
	NewTUNManager = func() tunManager {
		calls++
		return want
	}
	if got := newTUNManager(); got != want || calls != 1 {
		t.Fatalf("newTUNManager() = %v with %d factory calls, want supplied manager with one call", got, calls)
	}
}

func TestTUNManagerFactoryDefaultsToUnmodifiedMultiTUN(t *testing.T) {
	previous := NewTUNManager
	t.Cleanup(func() { NewTUNManager = previous })
	for _, factory := range []func() tunManager{nil, func() tunManager { return nil }} {
		NewTUNManager = factory
		manager := newTUNManager()
		if _, ok := manager.(*upstreamMultiTUN); !ok {
			t.Fatalf("default manager = %T, want upstream adapter", manager)
		}
		// Original multiTUN Close is a single-use operation; do not call it
		// again through cleanup after this deliberate one-time close.
		if err := manager.Close(); err != nil {
			t.Fatalf("default manager Close: %v", err)
		}
	}
}

type factoryTestManager struct{ tunManager }

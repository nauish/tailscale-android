// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import "github.com/tailscale/wireguard-go/tun"

// tunManager owns the engine's stable TUN device and the descriptors installed
// into it. Shutdown retires current descriptors without permanently closing the
// manager; Close permanently closes the engine device.
type tunManager interface {
	tun.Device

	// InstallFD consumes fd on both success and failure. The caller must not
	// use or close fd after this method returns.
	InstallFD(fd int) error
	Up() bool
	Down() bool
	Shutdown()
}

// NewTUNManager optionally selects a platform TUN manager. Set it during package
// initialization, before starting an App. A nil factory or result preserves the
// upstream multiTUN implementation.
var NewTUNManager func() tunManager

// CustomSwapHostTUN optionally installs an application-established descriptor.
// A configured callback consumes the descriptor on success and failure.
var CustomSwapHostTUN func(fd int) error

// notifyVpnStatus reports attachment to the active platform service. The net.go
// initialization supplies it without coupling the manager to Android bindings.
var notifyVpnStatus func(bool)

func newTUNManager() tunManager {
	if NewTUNManager != nil {
		if manager := NewTUNManager(); manager != nil {
			return manager
		}
	}
	return &upstreamMultiTUN{multiTUN: newTUNDevices()}
}

// upstreamMultiTUN adapts descriptor installation without changing multitun.go.
type upstreamMultiTUN struct {
	*multiTUN
}

var _ tunManager = (*upstreamMultiTUN)(nil)

func (d *upstreamMultiTUN) InstallFD(fd int) error {
	device, err := createNativeTUNFromFD(fd)
	if err != nil {
		return err
	}
	d.add(device)
	return nil
}

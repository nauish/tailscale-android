// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import "github.com/tailscale/wireguard-go/tun"

// CreateUnmonitoredTUNFromFD consumes fd even when native device creation fails.
func createNativeTUNFromFD(fd int) (tun.Device, error) {
	device, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return device, err
}

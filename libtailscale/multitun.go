// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"log"
	"os"
	"runtime/debug"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/syncs"
)

// multiTUN implements a tun.Device that supports multiple
// underlying devices. This is necessary because Android VPN devices
// have static configurations and wgengine.NewUserspaceEngine
// assumes a single static tun.Device.
type multiTUN struct {
	// devices is for adding new devices.
	devices chan addRequest
	// event is the combined event channel from all active devices.
	events chan tun.Event

	// close is closed when the multiTUN is permanently closed.
	// It stays closed, so it doubles as the "no longer accepting work"
	// signal for add, Read, Write, MTU, Name and Shutdown.
	close     chan struct{}
	closeOnce sync.Once
	// closed is closed once run has released every device.
	closed chan struct{}
	// closeErr is set by run before closed is closed.
	closeErr error

	reads        chan readRequest
	writes       chan writeRequest
	mtus         chan chan mtuReply
	names        chan chan nameReply
	shutdowns    chan struct{}
	shutdownDone chan struct{}

	downMu sync.Mutex
	// downCh is closed when the multiTUN is brought down,
	// such as when Tailscale transitions to the Stopped state.
	// This indicates that all outgoing packets should be dropped,
	// and [multiTUN.Write] should return immediately without blocking
	// until [multiTUN.Up] is called. See [multiTUN.Down]
	// and tailscale/tailscale#18679 for more details.
	//
	// It can be read without holding downMu, but the mutex
	// must be held when writing.
	downCh syncs.AtomicValue[chan struct{}]
	down   bool // whether the downCh is closed
}

// tunDevice wraps and drives a single tun.Device.
type tunDevice struct {
	dev tun.Device
	// close asks the device's goroutines to stop. It may be closed more
	// than once by rotation and shutdown, so it is guarded by closeOnce.
	close     chan struct{}
	closeOnce sync.Once
	// closeDevOnce guards dev.Close, which is not necessarily idempotent.
	closeDevOnce sync.Once
	closeErr     error
	// readDone is notified when the read goroutine is done.
	readDone chan struct{}
	// writeDone is notified when the write goroutine is done.
	writeDone chan struct{}
	// reading and writing record which goroutines were started. They are
	// only accessed by the run goroutine.
	reading bool
	writing bool
}

func (dev *tunDevice) stop() {
	dev.closeOnce.Do(func() { close(dev.close) })
}

// closeDevice closes the underlying device at most once and reports the
// result of that first close.
func (dev *tunDevice) closeDevice() error {
	dev.closeDevOnce.Do(func() { dev.closeErr = dev.dev.Close() })
	return dev.closeErr
}

// wait blocks until every goroutine started for this device has returned.
func (dev *tunDevice) wait() {
	if dev.reading {
		<-dev.readDone
	}
	if dev.writing {
		<-dev.writeDone
	}
}

// addRequest acknowledges that run has stopped the previous device before
// callers retire its lease. Sending alone does not complete that handoff.
type addRequest struct {
	device    tun.Device
	installed chan struct{}
}

type readRequest struct {
	slab    []byte
	packets []tun.ReadPacket
	reply   chan<- ioReply
}

type writeRequest struct {
	data   [][]byte
	offset int
	reply  chan<- ioReply
}

type ioReply struct {
	count int
	err   error
}

type mtuReply struct {
	mtu int
	err error
}

type nameReply struct {
	name string
	err  error
}

func newTUNDevices() *multiTUN {
	d := &multiTUN{
		devices:      make(chan addRequest),
		events:       make(chan tun.Event),
		close:        make(chan struct{}),
		closed:       make(chan struct{}),
		reads:        make(chan readRequest),
		writes:       make(chan writeRequest),
		mtus:         make(chan chan mtuReply),
		names:        make(chan chan nameReply),
		shutdowns:    make(chan struct{}),
		shutdownDone: make(chan struct{}, 1),
		down:         true, // The device is initially down.
	}
	downCh := make(chan struct{})
	d.downCh.Store(downCh)
	close(downCh)
	go d.run()
	return d
}

// stopAll asks every device to stop, waits for its goroutines, and closes the
// underlying devices. It returns the first close error, if any.
func (d *multiTUN) stopAll(devices []*tunDevice) error {
	for _, dev := range devices {
		dev.stop()
	}
	var derr error
	for _, dev := range devices {
		dev.wait()
		if err := dev.closeDevice(); err != nil && derr == nil {
			derr = err
		}
	}
	return derr
}

func (d *multiTUN) run() {
	// Publish the final close error before waking up Close callers.
	defer close(d.closed)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("panic in multiTUN.run %s: %s", p, debug.Stack())
			panic(p)
		}
	}()

	var devices []*tunDevice
	// readDone is the readDone channel of the device being read from.
	var readDone chan struct{}
	for {
		select {
		case <-readDone:
			// The oldest device has reached EOF, replace it.
			devices = devices[1:]
			readDone = nil
			if len(devices) > 0 {
				// Start reading from the next device.
				dev := devices[0]
				readDone = dev.readDone
				dev.reading = true
				go d.readFrom(dev)
			}
		case <-d.shutdowns:
			// Shut down all devices, but keep the multiTUN usable so that
			// a later reconfiguration can add a new device.
			d.stopAll(devices)
			devices = nil
			readDone = nil
			// shutdownDone is buffered, so this never blocks if the
			// caller gave up because Close raced with Shutdown.
			d.shutdownDone <- struct{}{}
		case <-d.close:
			d.closeErr = d.stopAll(devices)
			return
		case request := <-d.devices:
			dev := request.device
			if len(devices) > 0 {
				// Ask the most recent device to stop. Its write goroutine
				// closes it, which also unblocks any pending read once it
				// becomes the head.
				devices[len(devices)-1].stop()
			}
			wrap := &tunDevice{
				dev:       dev,
				close:     make(chan struct{}),
				readDone:  make(chan struct{}, 1),
				writeDone: make(chan struct{}, 1),
			}
			devices = append(devices, wrap)
			// Every device gets a write goroutine, so every device is
			// guaranteed to have its file descriptor released.
			wrap.writing = true
			go d.runDevice(wrap)
			if len(devices) == 1 {
				// Start using this first device.
				readDone = wrap.readDone
				wrap.reading = true
				go d.readFrom(wrap)
			}
			close(request.installed)
		case m := <-d.mtus:
			r := mtuReply{mtu: defaultMTU}
			if len(devices) > 0 {
				dev := devices[len(devices)-1]
				r.mtu, r.err = dev.dev.MTU()
			}
			m <- r
		case n := <-d.names:
			var r nameReply
			if len(devices) > 0 {
				dev := devices[len(devices)-1]
				r.name, r.err = dev.dev.Name()
			}
			n <- r
		}
	}
}

func (d *multiTUN) readFrom(dev *tunDevice) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("panic in multiTUN.readFrom %s: %s", p, debug.Stack())
			panic(p)
		}
	}()

	defer func() {
		dev.readDone <- struct{}{}
	}()
	for {
		select {
		case r := <-d.reads:
			n, err := dev.dev.Read(r.slab, r.packets)
			stop := false
			if err != nil {
				select {
				case <-dev.close:
					stop = true
					err = nil
				default:
				}
			}
			r.reply <- ioReply{n, err}
			if stop {
				return
			}
		case <-dev.close:
			return
		case <-d.close:
			return
		}
	}
}

func (d *multiTUN) runDevice(dev *tunDevice) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("panic in multiTUN.runDevice %s: %s", p, debug.Stack())
			panic(p)
		}
	}()

	defer func() {
		// The documentation for https://developer.android.com/reference/android/net/VpnService.Builder#establish()
		// states that "Therefore, after draining the old file
		// descriptor...", but pending Reads are never unblocked
		// when a new descriptor is created.
		//
		// Close it instead and hope that no packets are lost.
		dev.closeDevice()
		dev.writeDone <- struct{}{}
	}()
	// Pump device events.
	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic in multiTUN.readFrom.events %s: %s", p, debug.Stack())
				panic(p)
			}
		}()
		for {
			select {
			case e, ok := <-dev.dev.Events():
				if !ok {
					return
				}
				select {
				case d.events <- e:
				case <-dev.close:
					return
				case <-d.close:
					return
				}
			case <-dev.close:
				return
			case <-d.close:
				return
			}
		}
	}()
	for {
		select {
		case w := <-d.writes:
			n, err := dev.dev.Write(w.data, w.offset)
			w.reply <- ioReply{n, err}
		case <-dev.close:
			// Device closed.
			return
		case <-d.close:
			// Multi-device closed.
			return
		}
	}
}

// add installs dev as the newest underlying device. It returns os.ErrClosed
// if the multiTUN has been permanently closed, so callers do not block
// forever on a run loop that has already exited.
func (d *multiTUN) add(dev tun.Device) error {
	request := addRequest{device: dev, installed: make(chan struct{})}
	select {
	case d.devices <- request:
		// Once accepted, run completes the nonblocking installation before
		// handling close or another request, so this acknowledgment is owed.
		<-request.installed
		return nil
	case <-d.close:
		return os.ErrClosed
	}
}

// Up brings the multiTUN up, allowing it to write packets
// to the underlying tunnel device. If there is no underlying
// device yet, write operations are pended until a new device
// is added with [multiTUN.add].
//
// It reports whether this call brought the device up.
func (d *multiTUN) Up() bool {
	d.downMu.Lock()
	defer d.downMu.Unlock()
	if !d.down {
		return false
	}
	d.downCh.Store(make(chan struct{}))
	d.down = false
	return true
}

// Down brings the multiTUN down, causing all outgoing packets
// to be dropped without waiting for the underlying tunnel device,
// and makes all [multiTUN.Write] calls return immediately
// until [multiTUN.Up] is called.
//
// It mainly exists to distinguish between cases where the underlying
// device is temporarily unavailable due to VPN reconfiguration,
// in which case write requests should be pended, and cases where
// Tailscale is stopped, where any pending and new requests
// should complete immediately to prevent deadlocks.
// See tailscale/tailscale#18679.
//
// It reports whether this call brought the device down.
func (d *multiTUN) Down() bool {
	d.downMu.Lock()
	defer d.downMu.Unlock()
	if d.down {
		return false
	}
	close(d.downCh.Load())
	d.down = true
	return true
}

func (d *multiTUN) File() *os.File {
	// The underlying file descriptor is not constant on Android.
	// Let's hope no-one uses it.
	panic("not available on Android")
}

func (d *multiTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	r := make(chan ioReply)
	select {
	// We don't care about d.downCh here, as it's fine
	// to continue waiting until the tunnel is up again
	// or the multiTUN device is permanently closed.
	// This does not block WireGuard reconfiguration.
	case d.reads <- readRequest{
		slab:    slab,
		packets: packets,
		reply:   r,
	}:
		rep := <-r
		return rep.count, rep.err
	case <-d.close:
		// Return immediately if the multiTUN device is closed.
		return 0, os.ErrClosed
	}
}

func (d *multiTUN) Write(data [][]byte, offset int) (int, error) {
	r := make(chan ioReply)
	select {
	case d.writes <- writeRequest{
		data:   data,
		offset: offset,
		reply:  r,
	}:
		rep := <-r
		return rep.count, rep.err
	case <-d.downCh.Load():
		// Drop the packet silently if the tunnel is down.
		// Otherwise, a race may occur during wireguard reconfig
		// and result in a deadlock, since a wireguard-go/device.Peer
		// cannot be removed until its RoutineSequentialReceiver
		// returns, and it will not return if it is blocked in
		// (*multiTUN).Write while sending to d.writes without
		// a receiver on the other side of the pipe.
		return 0, nil
	case <-d.close:
		// Return immediately if the multiTUN device is closed.
		return 0, os.ErrClosed
	}
}

func (d *multiTUN) MTU() (int, error) {
	r := make(chan mtuReply)
	select {
	case d.mtus <- r:
		rep := <-r
		return rep.mtu, rep.err
	case <-d.close:
		return defaultMTU, os.ErrClosed
	}
}

func (d *multiTUN) Name() (string, error) {
	r := make(chan nameReply)
	select {
	case d.names <- r:
		rep := <-r
		return rep.name, rep.err
	case <-d.close:
		return "", os.ErrClosed
	}
}

func (d *multiTUN) Events() <-chan tun.Event {
	return d.events
}

// Shutdown stops all current devices but leaves the multiTUN usable, so a
// later reconfiguration can add a new device. It returns immediately if the
// multiTUN has already been permanently closed.
func (d *multiTUN) Shutdown() {
	select {
	case <-d.close:
		return
	case d.shutdowns <- struct{}{}:
	}
	<-d.shutdownDone
}

// Close permanently shuts down the multiTUN. It is safe to call more than once
// and from multiple goroutines.
func (d *multiTUN) Close() error {
	d.closeOnce.Do(func() { close(d.close) })
	<-d.closed
	return d.closeErr
}

func (d *multiTUN) BatchSize() int {
	// TODO(raggi): currently Android disallows the necessary ioctls to enable
	// batching. File a bug.
	return 1
}

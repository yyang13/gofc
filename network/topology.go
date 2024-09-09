/*
 * Cherry - An OpenFlow Controller
 *
 * Copyright (C) 2015 Samjung Data Service, Inc. All rights reserved.
 * Kitae Kim <superkkt@sds.co.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package network

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yyang13/gofc/graph"

	"github.com/pkg/errors"
)

type watcher interface {
	DeviceAdded(*Device)
	DeviceLinked([2]*Port)
	DeviceRemoved(*Device)
	PortRemoved(*Port)
}

type Finder interface {
	Device(id string) *Device
	Devices() []*Device
	// IsEnabledBySTP returns whether p is disabled by spanning tree protocol
	IsEnabledBySTP(p *Port) bool
	// IsEdge returns whether p is an edge among two switches
	IsEdge(p *Port) bool
	Node(mac net.HardwareAddr) (*Node, LocationStatus, error)
	Path(srcDeviceID, dstDeviceID string) [][2]*Port
}

type topology struct {
	mutex sync.RWMutex
	// Key is the device ID
	devices  map[string]*Device
	graph    *graph.Graph
	listener TopologyEventListener
	db       database
}

func newTopology(db database) *topology {
	v := &topology{
		devices: make(map[string]*Device),
		graph:   graph.New(),
		db:      db,
	}
	go v.staleEdgeRemover()

	return v
}

func (r *topology) String() string {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%v\n", r.graph))

	return buf.String()
}

func (r *topology) setEventListener(l TopologyEventListener) {
	r.listener = l
}

// Caller should make sure the mutex is unlocked before calling this function.
// Otherwise, event listeners may cause a deadlock by calling other topology functions.
func (r *topology) sendEvent() {
	if r.listener == nil {
		return
	}

	if err := r.listener.OnTopologyChange(r); err != nil {
		logger.Errorf("OnTopologyChange: %v", err)
		return
	}
}

func (r *topology) Devices() []*Device {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	v := make([]*Device, 0)
	for _, d := range r.devices {
		v = append(v, d)
	}

	return v
}

// Device may return nil if a device whose ID is id does not exist
func (r *topology) Device(id string) *Device {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.devices[id]
}

func (r *topology) DeviceAdded(d *Device) {
	// NOTE: This is an anonymous function (NOT a goroutine!) that has a critical section.
	func() {
		// Write lock
		r.mutex.Lock()
		defer r.mutex.Unlock()

		r.devices[d.ID()] = d
		r.graph.AddVertex(d)
	}()
	// XXX: Make sure the mutex is unlocked before calling sendEvent().
	r.sendEvent()
}

// XXX: Caller should lock the mutex
func (r *topology) removeDevice(d *Device) {
	// Remove from the device database
	delete(r.devices, d.ID())
}

func (r *topology) DeviceRemoved(d *Device) {
	// NOTE: This is an anonymous function (NOT a goroutine!) that has a critical section.
	func() {
		// Write lock
		r.mutex.Lock()
		defer r.mutex.Unlock()

		r.removeDevice(d)
		r.graph.RemoveVertex(d)
	}()
	// XXX: Make sure the mutex is unlocked before calling sendEvent().
	r.sendEvent()
}

func (r *topology) DeviceLinked(ports [2]*Port) {
	var added bool
	var err error

	// NOTE: This is an anonymous function (NOT a goroutine!) that has a critical section.
	func() {
		// Write lock
		r.mutex.Lock()
		defer r.mutex.Unlock()

		link := newLink(ports)
		added, err = r.graph.AddEdge(link)
		if err != nil {
			logger.Errorf("failed to add a new graph edge: %v", err)
			return
		}
	}()

	// Send the event only if the topology has been changed.
	if err == nil && added {
		// XXX: Make sure the mutex is unlocked before calling sendEvent().
		r.sendEvent()
		logger.Infof("devices have been linked: %v:%v / %v:%v", ports[0].Device().ID(), ports[0].Number(), ports[1].Device().ID(), ports[1].Number())
	}
}

// Node may return nil if the node is unregistered or still undiscovered.
func (r *topology) Node(mac net.HardwareAddr) (*Node, LocationStatus, error) {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	dpid, portNum, status, err := r.db.Location(mac)
	if err != nil {
		return nil, status, errors.Wrap(&networkErr{temporary: true, err: err}, "querying host location to the database")
	}
	if status != LocationDiscovered {
		return nil, status, nil
	}

	device, ok := r.devices[dpid]
	if !ok {
		return nil, LocationUnregistered, nil
	}
	port := device.Port(portNum)
	if port == nil {
		return nil, LocationUnregistered, nil
	}

	return NewNode(port, mac), LocationDiscovered, nil
}

func (r *topology) PortRemoved(p *Port) {
	edge := false

	// NOTE: This is an anonymous function (NOT a goroutine!) that has a critical section.
	func() {
		// Write lock
		r.mutex.Lock()
		defer r.mutex.Unlock()

		if edge = r.graph.IsEdge(p); edge == true {
			// Remove an edge from the graph if this port is an edge connected to another switch
			r.graph.RemoveEdge(p)
		}
	}()

	if edge {
		// XXX: Make sure the mutex is unlocked before calling sendEvent().
		r.sendEvent()
	}
}

func (r *topology) Path(srcDeviceID, dstDeviceID string) [][2]*Port {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	v := make([][2]*Port, 0)
	src := r.devices[srcDeviceID]
	dst := r.devices[dstDeviceID]
	// Unknown source or destination device?
	if src == nil || dst == nil {
		// Return empty path
		return v
	}

	path := r.graph.FindPath(src, dst)
	for _, p := range path {
		device := p.V.(*Device)
		link := p.E.(*link)
		v = append(v, pickPort(device, link))
	}

	return v
}

func pickPort(d *Device, l *link) [2]*Port {
	p := l.Points()
	if p[0].Vertex().ID() == d.ID() {
		return [2]*Port{p[0].(*Port), p[1].(*Port)}
	}

	return [2]*Port{p[1].(*Port), p[0].(*Port)}
}

func (r *topology) IsEdge(p *Port) bool {
	return r.graph.IsEdge(p)
}

func (r *topology) IsEnabledBySTP(p *Port) bool {
	return r.graph.IsEnabledPoint(p)
}

// staleEdgeRemover removes stale edges that have not been updated for a long time.
func (r *topology) staleEdgeRemover() {
	ticker := time.Tick(10 * time.Second)

	// Infinite loop.
	for range ticker {
		var removed bool

		// NOTE: This is an anonymous function (NOT a goroutine!) that has a critical section.
		func() {
			// Write lock
			r.mutex.Lock()
			defer r.mutex.Unlock()

			logger.Debug("trying to remove stale edges from the topology...")
			removed = r.graph.RemoveStaleEdges(deviceExplorerInterval * 3)
		}()

		// Send the event only if the topology has been changed.
		if removed {
			logger.Debug("removed stale edge(s) from the topology")
			// XXX: Make sure the mutex is unlocked before calling sendEvent().
			r.sendEvent()
		}
	}
}

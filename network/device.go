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
	"encoding"
	"errors"
	"fmt"
	"sync"

	"github.com/yyang13/gofc/openflow"
	"github.com/yyang13/gofc/openflow/transceiver"
)

type Descriptions struct {
	Manufacturer string
	Hardware     string
	Software     string
	Serial       string
	Description  string
}

type Features struct {
	DPID       uint64
	NumBuffers uint32
	NumTables  uint8
}

type Device struct {
	mutex        sync.RWMutex
	id           string
	session      *session
	descriptions Descriptions
	features     Features
	ports        map[uint32]*Port
	factory      openflow.Factory
	closed       bool
}

var (
	ErrClosedDevice = errors.New("already closed device")
)

func newDevice(s *session) *Device {
	if s == nil {
		panic("Session is nil")
	}

	return &Device{
		session: s,
		ports:   make(map[uint32]*Port),
	}
}

func (r *Device) String() string {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	v := fmt.Sprintf("Device ID=%v, Descriptions=%+v, Features=%+v, # of ports=%v, Connected=%v\n", r.id, r.descriptions, r.features, len(r.ports), !r.closed)
	for _, p := range r.ports {
		v += fmt.Sprintf("\t%v\n", p.String())
	}

	return v
}

func (r *Device) ID() string {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.id
}

func (r *Device) setID(id string) {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.id = id
}

func (r *Device) isReady() bool {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.id) > 0
}

func (r *Device) Factory() openflow.Factory {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.factory
}

func (r *Device) setFactory(f openflow.Factory) {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if f == nil {
		panic("Factory is nil")
	}
	r.factory = f
}

func (r *Device) Writer() transceiver.Writer {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.session
}

func (r *Device) Descriptions() Descriptions {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.descriptions
}

func (r *Device) setDescriptions(d Descriptions) {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.descriptions = d
}

func (r *Device) Features() Features {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.features
}

func (r *Device) setFeatures(f Features) {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.features = f
}

// Port may return nil if there is no port whose number is num
func (r *Device) Port(num uint32) *Port {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.ports[num]
}

func (r *Device) Ports() []*Port {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	p := make([]*Port, 0)
	for _, v := range r.ports {
		p = append(p, v)
	}

	return p
}

func (r *Device) setPort(num uint32, p openflow.Port) {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if p == nil {
		panic("Port is nil")
	}
	logger.Debugf("Device=%v, PortNum=%v, AdminUp=%v, LinkUp=%v", r.id, p.Number(), !p.IsPortDown(), !p.IsLinkDown())

	port, ok := r.ports[num]
	if ok {
		port.SetValue(p)
	} else {
		v := NewPort(r, num)
		v.SetValue(p)
		r.ports[num] = v
	}
}

func (r *Device) SendMessage(msg encoding.BinaryMarshaler) error {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if msg == nil {
		panic("Message is nil")
	}
	if r.closed {
		return ErrClosedDevice
	}

	return r.session.Write(msg)
}

func (r *Device) IsClosed() bool {
	// Read lock
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return r.closed
}

func (r *Device) Close() {
	// Write lock
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.closed = true
}

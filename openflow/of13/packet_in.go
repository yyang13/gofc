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

package of13

import (
	"encoding/binary"

	"github.com/yyang13/gofc/openflow"
)

type PacketIn struct {
	openflow.Message
	bufferID       uint32
	length         uint16
	inPort         uint32
	tableID        uint8
	reason         uint8
	cookie         uint64
	vlanID         uint16
	vlanIDPriority uint8
	data           []byte
}

func (r PacketIn) BufferID() uint32 {
	return r.bufferID
}

func (r PacketIn) InPort() uint32 {
	return r.inPort
}

func (r PacketIn) Data() []byte {
	return r.data
}

func (r PacketIn) Length() uint16 {
	return r.length
}

func (r PacketIn) TableID() uint8 {
	return r.tableID
}

func (r PacketIn) Reason() uint8 {
	return r.reason
}

func (r PacketIn) Cookie() uint64 {
	return r.cookie
}

func (r PacketIn) VLANID() uint16 {
	return r.vlanID
}

func (r PacketIn) VLANPriority() uint8 {
	return r.vlanIDPriority
}

func (r *PacketIn) UnmarshalBinary(data []byte) error {
	if err := r.Message.UnmarshalBinary(data); err != nil {
		return err
	}

	payload := r.Payload()
	if payload == nil || len(payload) < 24 {
		return openflow.ErrInvalidPacketLength
	}
	r.bufferID = binary.BigEndian.Uint32(payload[0:4])
	r.length = binary.BigEndian.Uint16(payload[4:6])
	r.reason = payload[6]
	r.tableID = payload[7]
	r.cookie = binary.BigEndian.Uint64(payload[8:16])

	match := NewMatch()
	if err := match.UnmarshalBinary(payload[16:]); err != nil {
		return err
	}
	_, inport := match.InPort()
	r.inPort = inport.Value()

	_, vlanID := match.VLANID()
	r.vlanID = vlanID

	_, vlanIDPriority := match.VLANPriority()
	r.vlanIDPriority = vlanIDPriority

	matchLength := binary.BigEndian.Uint16(payload[18:20])
	// Calculate padding length
	rem := matchLength % 8
	if rem > 0 {
		matchLength += 8 - rem
	}

	dataOffset := 16 + matchLength + 2 // +2 is padding
	if len(payload) >= int(dataOffset) {
		// TODO: Check data size by comparing with r.Length
		r.data = payload[dataOffset:]
	}

	return nil
}

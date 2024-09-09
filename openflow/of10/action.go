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

package of10

import (
	"encoding/binary"
	"net"

	"github.com/yyang13/gofc/openflow"
)

type Action struct {
	*openflow.BaseAction
}

func NewAction() openflow.Action {
	return &Action{
		openflow.NewBaseAction(),
	}
}

func marshalOutPort(p openflow.OutPort) ([]byte, error) {
	v := make([]byte, 8)
	binary.BigEndian.PutUint16(v[0:2], uint16(OFPAT_OUTPUT))
	binary.BigEndian.PutUint16(v[2:4], 8)

	var port uint16
	switch {
	case p.IsTable():
		port = OFPP_TABLE
	case p.IsFlood():
		port = OFPP_FLOOD
	case p.IsAll():
		port = OFPP_ALL
	case p.IsController():
		port = OFPP_CONTROLLER
	case p.IsInPort():
		port = OFPP_IN_PORT
	case p.IsNone():
		port = OFPP_NONE
	default:
		port = uint16(p.Value())
	}
	binary.BigEndian.PutUint16(v[4:6], port)
	// We don't support buffer ID and partial PACKET_IN
	binary.BigEndian.PutUint16(v[6:8], 0xFFFF)

	return v, nil
}

func marshalQueue(p openflow.OutPort, queue uint32) ([]byte, error) {
	v := make([]byte, 16)
	binary.BigEndian.PutUint16(v[0:2], uint16(OFPAT_ENQUEUE))
	binary.BigEndian.PutUint16(v[2:4], 16)

	var port uint16
	switch {
	case p.IsTable():
		port = OFPP_TABLE
	case p.IsFlood():
		port = OFPP_FLOOD
	case p.IsAll():
		port = OFPP_ALL
	case p.IsController():
		port = OFPP_CONTROLLER
	case p.IsNone():
		port = OFPP_NONE
	default:
		port = uint16(p.Value())
	}
	binary.BigEndian.PutUint16(v[4:6], port)
	// v[6:12] is padding
	binary.BigEndian.PutUint32(v[12:16], queue)

	return v, nil
}

func marshalMAC(t uint16, mac net.HardwareAddr) ([]byte, error) {
	if mac == nil || len(mac) < 6 {
		return nil, openflow.ErrInvalidMACAddress
	}

	v := make([]byte, 16)
	binary.BigEndian.PutUint16(v[0:2], t)
	binary.BigEndian.PutUint16(v[2:4], 16)
	copy(v[4:10], mac)

	return v, nil
}

func marshalVLANID(vid uint16) ([]byte, error) {
	v := make([]byte, 8)
	binary.BigEndian.PutUint16(v[0:2], uint16(OFPAT_SET_VLAN_VID))
	binary.BigEndian.PutUint16(v[2:4], 8)
	binary.BigEndian.PutUint16(v[4:6], vid)
	// v[6:8] is padding

	return v, nil
}

func (r *Action) MarshalBinary() ([]byte, error) {
	if err := r.Error(); err != nil {
		return nil, err
	}

	result := make([]byte, 0)
	if ok, srcMAC := r.SrcMAC(); ok {
		v, err := marshalMAC(OFPAT_SET_DL_SRC, srcMAC)
		if err != nil {
			return nil, err
		}
		result = append(result, v...)
	}
	if ok, dstMAC := r.DstMAC(); ok {
		v, err := marshalMAC(OFPAT_SET_DL_DST, dstMAC)
		if err != nil {
			return nil, err
		}
		result = append(result, v...)
	}

	ok, vlanID := r.VLANID()
	if ok {
		v, err := marshalVLANID(vlanID)
		if err != nil {
			return nil, err
		}
		result = append(result, v...)
	}

	// XXX: Output action should be specified as a last element of this action command.
	var buf []byte
	var err error
	// Need QoS?
	ok, queueID := r.Queue()
	if ok {
		buf, err = marshalQueue(r.OutPort(), queueID)
	} else {
		buf, err = marshalOutPort(r.OutPort())
	}
	if err != nil {
		return nil, err
	}
	result = append(result, buf...)

	return result, nil
}

func (r *Action) UnmarshalBinary(data []byte) error {
	buf := data
	for len(buf) >= 4 {
		t := binary.BigEndian.Uint16(buf[0:2])
		length := binary.BigEndian.Uint16(buf[2:4])
		if len(buf) < int(length) {
			return openflow.ErrInvalidPacketLength
		}

		switch t {
		case OFPAT_OUTPUT:
			if len(buf) < 8 {
				return openflow.ErrInvalidPacketLength
			}
			outPort := openflow.NewOutPort()
			outPort.SetValue(uint32(binary.BigEndian.Uint16(buf[4:6])))
			r.SetOutPort(outPort)
			if err := r.Error(); err != nil {
				return err
			}
		case OFPAT_SET_DL_SRC:
			if len(buf) < 16 {
				return openflow.ErrInvalidPacketLength
			}
			r.SetSrcMAC(buf[4:10])
			if err := r.Error(); err != nil {
				return err
			}
		case OFPAT_SET_DL_DST:
			if len(buf) < 16 {
				return openflow.ErrInvalidPacketLength
			}
			r.SetDstMAC(buf[4:10])
			if err := r.Error(); err != nil {
				return err
			}
		case OFPAT_ENQUEUE:
			if len(buf) < 16 {
				return openflow.ErrInvalidPacketLength
			}
			outPort := openflow.NewOutPort()
			outPort.SetValue(uint32(binary.BigEndian.Uint16(buf[4:6])))
			r.SetOutPort(outPort)
			r.SetQueue(binary.BigEndian.Uint32(buf[12:16]))
			if err := r.Error(); err != nil {
				return err
			}
		case OFPAT_SET_VLAN_VID:
			if len(buf) < 8 {
				return openflow.ErrInvalidPacketLength
			}
			r.SetVLANID(binary.BigEndian.Uint16(buf[4:6]))
			if err := r.Error(); err != nil {
				return err
			}
		default:
			// Do nothing
		}

		buf = buf[length:]
	}

	return nil
}

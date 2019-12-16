#!/usr/bin/python

"""
LLDP fuzzer
2007 Jeremy Hollander 

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License version 2
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from lldppacket import *

"""
List of Test Cases
1: chassis information string is 512 bytes instead of allowed 255 bytes
2: chassis information string is 0 bytes instead of a legal minimum of 2 bytes
3: chassis information string is legal (between 1-255) yet information string length is set to 1 byte
4: chassis information string is 257 bytes instead of a legal maximum of 256 bytes
5: ttl information string is 15 seconds yet send a burst of 1000 of the same message
6: end_of_lldpdu information string length is 0 yet there is a payload of 65535
7: end_of_lldpdu information string length is 2 with a payload of 65535
8: some enabled capability which is initially not shown as supported in system capabilities
9: out of 4 compulsory tlvs the port id tlv is missing
10:network address says it's ipv6 but in reality it's an ipv4 address
"""
self_iface = "eth0"
self_mac = "01:23:45:67:89:AB"

def test_case1():
	p=lldppacket()
	p.chassis_id_header=new_header(1,0,511)
	p.chassis_id_payload_data=510*"a"
	p.chassis_id_msg=p.chassis_id_header+p.chassis_id_payload
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

def test_case2():
	p=lldppacket()
	p.chassis_id_header=new_header(1,0,0)
	p.chassis_id_msg=p.chassis_id_header
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

def test_case3():
	p=lldppacket()
	p.chassis_id_header=new_header(1,0,1)
	p.chassis_id_msg=p.chassis_id_header+p.chassis_id_payload
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

def test_case4():
	p=lldppacket()
	p.chassis_id_subtype_data=6
	p.chassis_id_payload_data=256*"a"
	p.mod_chassis_id()
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

def test_case5():
	p=lldppacket()
	p.ttl_payload_data=15
	p.mod_ttl()
	p.mod_assemble_packet()
	for i in range (0,1000):
		p.send_packet(self_iface,self_mac)

def test_case6():
	p=lldppacket()
	p.packet+=new_field(0,65535,"short")
	p.send_packet(self_iface,self_mac)

def test_case7():
	p=lldppacket()
	p.end_of_lldpdu_data_customsize=2
	p.mod_end_of_lldpdu()
	p.mod_assemble_packet()
	p.packet+=new_field(0,65535,"short")
	p.send_packet(self_iface,self_mac)

def test_case8():
	p=lldppacket()
	p.system_capabilities_payload_data=24#equivalent to 0000000000011000
	p.enabled_capabilities_payload_data=28#equivalent to 0000000000011100
	p.mod_system_capabilities()
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

def test_case9():
	p=lldppacket()
	p.packet = p.chassis_id_msg+p.ttl_msg+p.end_of_lldpdu_msg
	p.send_packet(self_iface,self_mac)

def test_case10():
	p=lldppacket()
	p.chassis_id_subtype_data=5
	p.chassis_id_payload_data="10.10.10.10"
	p.chassis_id_payload=new_field(p.chassis_id_subtype_data,p.chassis_id_payload_data, "network_address", 4, 2)
	p.chassis_id_header=new_header(1,p.chassis_id_payload)
	p.chassis_id_msg=p.chassis_id_header+p.chassis_id_payload
	p.mod_assemble_packet()
	p.send_packet(self_iface,self_mac)

test_case1()

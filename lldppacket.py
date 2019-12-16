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

import dpkt
import ethernet
import random
import socket
import string
import struct

LLDP_BROADCAST_ADDR = "\x01\x80\xc2\x00\x00\x0e"
dictionary  = [i for i in string.ascii_letters]
dictionary += ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
hex_dictionary = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

class lldppacket:

	#set default values
	def __init__(self,chassis_id_subtype=None, port_id_subtype=None, ttl_payload_data=None):
		
		self.chassis_id_subtype_data=1
		self.chassis_id_payload_data="\xde\xfa\x01\x23\x45\x67\x89\xbc"
		self.chassis_id_payload=new_field(self.chassis_id_subtype_data,self.chassis_id_payload_data)
		self.chassis_id_header=new_header(1,self.chassis_id_payload)
		self.chassis_id_msg=self.chassis_id_header+self.chassis_id_payload

		self.port_id_subtype_data=1
		self.port_id_payload_data="default interface alias"
		self.port_id_payload=new_field(self.port_id_subtype_data,self.port_id_payload_data)
		self.port_id_header=new_header(2,self.port_id_payload)			
		self.port_id_msg=self.port_id_header+self.port_id_payload
	
		self.ttl_payload_data=60
		self.ttl_payload=new_field(0,self.ttl_payload_data,"short")
		self.ttl_header=new_header(3,self.ttl_payload)
		self.ttl_msg=self.ttl_header+self.ttl_payload

		self.port_description_payload_data="default port description"
		self.port_description_payload=new_field(0,self.port_description_payload_data, "")
		self.port_description_header=new_header(4,self.port_description_payload)
		self.port_description_msg=self.port_description_header+self.port_description_payload

		self.system_name_payload_data="system name default"
		self.system_name_payload=new_field(0,self.system_name_payload_data,"information_string_only")
		self.system_name_header=new_header(5,self.system_name_payload)
		self.system_name_msg=self.system_name_header+self.system_name_payload

		self.system_description_payload_data="system description default"			
		self.system_description_payload=new_field(0,self.system_description_payload_data, "information_string_only")
		self.system_description_header=new_header(6,self.system_description_payload)
		self.system_description_msg=self.system_description_header+self.system_description_payload

		self.system_capabilities_payload_data=5#equivalent to 0000000000000101
		self.enabled_capabilities_payload_data=5
		self.system_capabilities_payload=new_field(0, self.system_capabilities_payload_data, "short")
		self.system_capabilities_payload+=new_field(0, self.enabled_capabilities_payload_data, "short")
		self.system_capabilities_header=new_header(7,self.system_capabilities_payload)
		self.system_capabilities_msg=self.system_capabilities_header+self.system_capabilities_payload

		self.management_address_string_length_payload_data = 4 + 1 #length is 4 bytes for ipv4 address + 1 byte for address subtype	
		self.management_address_subtype_payload_data=1#ipv4
		self.management_address_payload_data="192.168.1.1"
		self.management_address_iface_numbering_subtype_payload_data=3
		self.management_address_iface_number_payload_data= 123456789
			
		self.management_address_oid_payload_data="\xde\xfa\x01\x23\x45\x67\x89\xbc"
		self.management_address_oid_string_length_payload_data=len(self.management_address_oid_payload_data)

		self.management_address_string_length_payload=new_field(0,self.management_address_string_length_payload_data,"byte")
		self.management_address_payload=new_field(0,self.management_address_payload_data,"network_address",4)
		self.management_address_iface_numbering_subtype_payload=new_field(0,self.management_address_iface_numbering_subtype_payload_data,"byte")
		self.management_address_iface_number_payload=new_field(0,self.management_address_iface_number_payload_data,"long")
		self.management_address_oid_string_length_payload=new_field(0,self.management_address_oid_string_length_payload_data,"byte")
		self.management_address_oid_payload=new_field(0,self.management_address_oid_payload_data,"information_string_only")
			
		self.management_address_all_tlv=self.management_address_string_length_payload#+self.management_address_subtype_payload
		self.management_address_all_tlv+=self.management_address_payload+self.management_address_iface_numbering_subtype_payload
		self.management_address_all_tlv+=self.management_address_iface_number_payload+self.management_address_oid_string_length_payload
		self.management_address_all_tlv+=self.management_address_oid_payload
		self.management_address_header=new_header(8,self.management_address_all_tlv)
		self.management_address_msg=self.management_address_header+self.management_address_all_tlv
	
		self.end_of_lldpdu_type_data = 0
		self.end_of_lldpdu_data = ""
		self.end_of_lldpdu_msg = new_header(self.end_of_lldpdu_type_data, self.end_of_lldpdu_data)

		self.packet = self.chassis_id_msg+self.port_id_msg+self.ttl_msg+self.port_description_msg+self.system_name_msg
		self.packet+= self.system_description_msg+self.system_capabilities_msg+self.management_address_msg+self.end_of_lldpdu_msg		

	#apply modifications
	def mod_chassis_id(self):
        	if self.chassis_id_subtype_data == 4:
			self.chassis_id_payload=new_field(self.chassis_id_subtype_data,self.chassis_id_payload_data,"mac")
		elif self.chassis_id_subtype_data == 5:
			self.chassis_id_payload=new_field(self.chassis_id_subtype_data,self.chassis_id_payload_data,"network_address", 4)
		else:
			self.chassis_id_payload=new_field(self.chassis_id_subtype_data,self.chassis_id_payload_data)
		self.chassis_id_header=new_header(1,self.chassis_id_payload)
		self.chassis_id_msg=self.chassis_id_header+self.chassis_id_payload

	def mod_port_id(self):
		if self.port_id_subtype == 3:
			self.port_id_payload=new_field(self.port_id_subtype,self.port_id_payload_data, "mac")		
		elif port_payload_subtype == 4:
			self.port_id_payload=new_field(self.port_id_subtype,self.port_id_payload_data, "network_address", 4)		
		else:
			self.port_id_payload=new_field(self.port_id_subtype,self.port_id_payload_data)				
		self.port_id_header=new_header(2,self.port_id_payload)
		self.port_id_msg=self.port_id_header+self.port_id_payload

	def mod_ttl(self):
		self.ttl_payload=new_field(0,self.ttl_payload_data,"short")
		self.ttl_header=new_header(3,self.ttl_payload)
		self.ttl_msg=self.ttl_header+self.ttl_payload

	def mod_port_description(self):
		self.port_description_payload=new_field(0, port_description_payload_information, "information_string_only")
		self.port_description_header=new_header(4,port_description_payload)
		self.port_description_msg=self.port_description_header+self.port_description_payload

	def mod_system_name(self):
		self.system_name_payload=new_field(0,self.system_name_payload_data,"information_string_only")
		self.system_name_header=new_header(5,self.system_name_payload)
		self.system_name_msg=self.system_name_header+self.system_name_payload

	def mod_system_description(self):
		self.system_description_payload=new_field(0,self.system_description_payload_data, "information_string_only")
		self.system_description_header=new_header(6,self.system_description_payload)
		self.system_description_msg=self.system_description_header+self.system_description_payload

	def mod_system_capabilities(self):
		self.system_capabilities_payload=new_field(0, self.system_capabilities_payload_data, "short")
		self.system_capabilities_payload+=new_field(0, self.enabled_capabilities_payload_data, "short")
		self.system_capabilities_header=new_header(7,self.system_capabilities_payload)
		self.system_capabilities_msg=self.system_capabilities_header+self.system_capabilities_payload

	def mod_management_address(self):
		self.management_address_string_length_payload=new_field(0,self.management_address_string_length_payload_data,"byte")
		self.management_address_subtype_payload=new_field(0,self.management_address_subtype_payload_data,"byte")
		self.management_address_payload=new_field(0,self.management_address_payload_data,"network_address",4)
		self.management_address_iface_numbering_subtype=new_field(0,self.management_address_iface_numbering_subtype_payload_data,"byte")
		self.management_address_iface_number_payload=new_field(0,self.management_address_iface_number_payload_data,"byte")
		self.management_address_oid_string_length_payload=new_field(0,self.management_address_oid_string_length_payload_data,"byte")
		self.management_address_oid_payload=new_field(0,self.management_address_oid_payload_data,"information_string_only")
		self.management_address_all_tlv=self.management_address_string_length_payload+self.management_address_subtype_payload
		self.management_address_all_tlv+=self.management_address_payload+self.management_address_iface_numbering_subtype
		self.management_address_all_tlv+=self.management_address_iface_number_payload+self.management_address_oid_string_length_payload
		self.management_address_all_tlv+=self.management_address_oid_payload
		self.management_address_header=new_header(8,self.management_address_all_tlv)
		self.management_address_msg=self.management_address_header+self.management_address_all_tlv

	def mod_end_of_lldpdu(self):
		if self.end_of_lldpdu_data_customsize == None:
			self.end_of_lldpdu_msg = new_header(self.end_of_lldpdu_type_data, self.end_of_lldpdu_data)
		else:
			self.end_of_lldpdu_msg = new_header(self.end_of_lldpdu_type_data, 0, self.end_of_lldpdu_data_customsize)

	def mod_assemble_packet(self):
		self.packet = self.chassis_id_msg+self.port_id_msg+self.ttl_msg+self.port_description_msg+self.system_name_msg
		self.packet+= self.system_description_msg+self.system_capabilities_msg+self.management_address_msg+self.end_of_lldpdu_msg

	def send_packet(self, iface, mac):
		packet_to_send = ethernet.Ethernet()
		packet_to_send.src = encode_mac(mac)
		packet_to_send.dst = LLDP_BROADCAST_ADDR
		packet_to_send.type = 0x88cc
		packet_to_send.data = self.packet	
		
		s = socket.socket (socket.PF_PACKET, socket.SOCK_RAW)
		s.bind ((iface, 0x88cc))
		s.send(str(packet_to_send))

#return a random ip address
def random_ip_address():
	ip_address = ''
	for i in range (0,4):
		ip_address += str(random.randrange(0,255))
		if (i!=3):
			ip_address += '.'
	return ip_address

#return a random mac address
def random_mac_address():
	mac_address = ''
	for i in range (0,11):
		mac_address += '%01X' % (random.randrange(0,15))
		if (i%2 != 0 and i!=11):
		#if (i==1 or i==3 or i==5 or i==7 or i==9):
			mac_address += ':'
	return mac_address

#encode MAC address
def encode_mac(buffer):
	addr =''
   	temp = string.split(buffer,':')
	buffer = string.join(temp,'')
	# Split up the hex values and pack
    	for i in range(0, len(buffer), 2):
        	addr = ''.join([addr,struct.pack('B', int(buffer[i: i + 2], 16))],)
	return addr

#create customized header. customsize replaces payload size
def new_header(tlv_type, payload, customsize=None):
	if customsize == None:
		type_len = (tlv_type << 9 | len (payload))
	else:
		type_len = (tlv_type << 9 | customsize)
	return struct.pack('!H', type_len)

#create customized field.
def new_field(subtype, info, info_type=None, ip_version=None,return_ipversion=None):
	if info_type == "mac":
		info_data_int = [int(x,16) for x in info.split(":")]
		info_data = struct.pack("6B", *info_data_int)
		subtype_data = struct.pack("!B", subtype)
		return subtype_data + info_data
	elif info_type == "network_address":	
		if subtype == 0 or return_ipversion != None:#special case for management address ip address, no subtype
			if ip_version == 4:	
				info_data_ip = ''.join(["%02X" % long(i) for i in info.split('.')])#change each decimal portion of the IP to a HEX pair
				info_data_ip_int = long(info_data_ip, 16) #make it a long integer	
				info_data_struct_ip_version = struct.pack("!B", 1)#need a 1 because using IPv4
				info_data_struct_ip = struct.pack("!L", info_data_ip_int)#this is a long (the IP address is 4 bytes)
				if return_ipversion != None:#add custom ip version
					subtype_data = struct.pack("!B", subtype)					
					info_data_struct_ip_version = struct.pack("!B", return_ipversion)
					info_data = subtype_data + info_data_struct_ip_version + info_data_struct_ip
				else:#keep ip version 4
					info_data = info_data_struct_ip_version + info_data_struct_ip
				return info_data
			elif ip_version == 6:
				info_data_struct_ip_version = struct.pack("!B", 2)#need a 2 because using IPv6
				info_data_struct_ip = struct.pack("!2L", info_data_ip_int)#this is a long (the IP address is 8 bytes)
				info_data = info_data_struct_ip_version + info_data_struct_ip
				if return_ipversion != None:#add custom ip version
					subtype_data = struct.pack("!B", subtype)					
					info_data_struct_ip_version = struct.pack("!B", return_ipversion)
					info_data = subtype_data + info_data_struct_ip_version + info_data_struct_ip
				else:#keep ip version 6
					info_data = info_data_struct_ip_version + info_data_struct_ip
				return info_data
		elif ip_version == 4:
			info_data_ip = ''.join(["%02X" % long(i) for i in info.split('.')])#change each decimal portion of the IP to a HEX pair
			info_data_ip_int = long(info_data_ip, 16) #make it a long integer	
			info_data_struct_ip_version = struct.pack("!B", 1)#need a 1 because using IPv4
			info_data_struct_ip = struct.pack("!L", info_data_ip_int)#this is a long (the IP address is 4 bytes)
			info_data = info_data_struct_ip_version + info_data_struct_ip
			subtype_data = struct.pack("!B", subtype)
			return subtype_data + info_data
		else:#ip_version 6
			info_data_struct_ip_version = struct.pack("!B", 2)#need a 2 because using IPv6
			info_data_struct_ip = struct.pack("!2L", info_data_ip_int)#this is a long (the IP address is 8 bytes)
			info_data = info_data_struct_ip_version + info_data_struct_ip
			subtype_data = struct.pack("!B", subtype)
			return subtype_data + info_data
	elif info_type == "information_string_only":
		return info
	elif info_type == "short":
		return struct.pack("!H", info)	
	elif info_type == "byte":
		return struct.pack("!B", info)
	elif info_type == "long":
		return struct.pack("!L", info)
	else:
		info_data = info
		subtype_data = struct.pack("!B", subtype)
		return subtype_data + info_data

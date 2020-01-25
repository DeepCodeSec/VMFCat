#!/usr/bin/env python
#
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
#
# You are free to use and modify this code for your own software 
# as long as you retain information about the original author
# in your code as shown below.
#
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
#
__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////
# Imports Statements
import sys
from enum import Enum
from bitstring import BitArray
from Fields import *
from Groups import *
from Logger import *
from Elements import *
#//////////////////////////////////////////////////////////

class Message(object):

	def __init__(self, _logger=None):
		self.header = Header()
		self.data = None
		self.logger = _logger
		if (_logger == None):
			self.logger = Logger(sys.stdout)

	def get_bit_array(self):
		return self.header.get_bit_array()

		
class Header(object):
	
	def __init__(self):
		self.elements = {
			CODE_FLD_VERSION    : Field(
						_name="Version",
						_size=4,
						_enumerator=version,
						_groupcode=CODE_GRP_HEADER,
						_indicator=True,
						_index=0),
			CODE_FLD_COMPRESS      : Field(
						_name="Data Compression",
						_size=2,
						_enumerator=data_compression,
						_groupcode=CODE_GRP_HEADER,
						_index=1),
			CODE_FLD_ORIG_URN: Field(
						_name="Originator URN",
						_size=24, 
						_groupcode=CODE_GRP_ORIGIN_ADDR,
						_index=0),
			CODE_FLD_ORIG_UNIT: Field(
						_name="Originator Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_ORIGIN_ADDR,
						_string=True,
						_index=0),
			CODE_FLD_RCPT_URN     : Field(
						_name="Recipient URN", 
						_size=24, 
						_groupcode=CODE_GRP_RCPT_ADDR,
						_index=0),
			CODE_FLD_RCPT_UNIT    : Field(
						_name="Recipient Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_RCPT_ADDR,
						_string=True,
						_index=0),
			CODE_FLD_INFO_URN     : Field(
						_name="Information URN", 
						_size=24, 
						_groupcode=CODE_GRP_INFO_ADDR,
						_index=0),
			CODE_FLD_INFO_UNIT    : Field(
						_name="Information Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_INFO_ADDR,
						_string=True,
						_index=0),
			CODE_FLD_UMF           : Field(
						_name="UMF", 
						_size=4, 
						_enumerator=umf,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=0),
			CODE_FLD_MSG_VERS       : Field(
						_name="Message Standard Version", 
						_size=4, 
						_groupcode=CODE_GRP_MSG_HAND,
						_index=1),
			CODE_FLD_FAD           : Field(
						_name="FAD", 
						_size=4,
						_enumerator=fad_codes, 
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=0),
			CODE_FLD_MSG_NUM     : Field(
						_name="Message Number",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=1),
			CODE_FLD_MSG_STYPE	: Field(
						_name="Message Subtype",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=2),
			CODE_FLD_FILENAME	: Field(
						_name="File name",
						_size=448,
						_groupcode=CODE_GRP_MSG_HAND,
						_string=True,
						_index=3),
			CODE_FLD_MSG_SIZE	: Field(
						_name="Message Size",
						_size=20,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=4),
			CODE_FLD_OPIND		: Field(
						_name="Operation Indicator",
						_size=2,
						_enumerator=operation,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=5),
			CODE_FLD_RETX		: Field(
						_name="Retransmit Indicator",
						_size=1,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=6),
			CODE_FLD_MSG_PREC	: Field(
						_name="Message Precedence Code",
						_size=3,
						_enumerator=precedence,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=7),
			CODE_FLD_CLASS		: Field(
						_name="Security Classification",
						_size=2,
						_enumerator=classification,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=8),
			CODE_FLD_RELEASE	: Field(
						_name="Control/Release Marking",
						_size=9,
						_repeatable=True,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=9),
			CODE_FLD_ORIG_DTG	: dtg_field(
						_name="Originator DTG",
						_groupcode=CODE_GRP_ORIGIN_DTG,
						_index=10),
			CODE_FLD_PRSH_DTG	: dtg_field(
						_name="Perishability DTG",
						_groupcode=CODE_GRP_PERISH_DTG,
						_extension=False,
						_index=11),
			CODE_FLD_MCHN_ACK	: Field(
						_name="Machine Acknowledge",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=1),
			"ackop"         : Field(
						_name="Operator Acknowledge",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=2),
			"reply"         : Field(
						_name="Operator Reply Request",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=3),
			"ackdtg"        : dtg_field(
						_name="DTG of Ack'd Msg.",
						_groupcode=CODE_GRP_RESPONSE,
						_index=12),
			"rccode"        : Field(
						_name="R/C",
						_size=3,
						_enumerator=rc_codes,
						_groupcode=CODE_GRP_RESPONSE,
						_indicator=True,
						_index=13),
			"cantco"        : Field(
						_name="Cantco Reason Code",
						_size=3,
						_enumerator=cantco_reasons,
						_groupcode=CODE_GRP_RESPONSE,
						_index=14),
			"cantpro"       : Field(
						_name="Cantpro Reason Code",
						_size=6,
						_enumerator=cantpro_reasons,
						_groupcode=CODE_GRP_RESPONSE,
						_index=15),
			"replyamp"      : Field(
						_name="Reply Amplification",
						_size=350,
						_groupcode=CODE_GRP_RESPONSE,
						_index=16),
			"ref_urn"       : Field(
						_name="Reference Message URN",
						_size=24,
						_groupcode=CODE_GRP_REF,
						_index=0),
			"ref_unitname"      : Field(
						_name="Reference Message Unit Name",
						_size=448,
						_groupcode=CODE_GRP_REF,
						_index=0),
			"refdtg"        : dtg_field(
						_name="Reference Message DTG",
						_groupcode=CODE_GRP_REF,
						_index=1),
			"secparam"      : Field(
						_name="Security Parameters",
						_size=4,
						_groupcode=CODE_GRP_MSG_SECURITY,
						_indicator=True,
						_index=0),
			"keymatlen"     : Field(
						_name="Keying Material Id Length",
						_size=3,
						_groupcode=CODE_GRP_KEYMAT,
						_indicator=True,
						_index=0),
			"keymatid"      : Field(
						_name="Keying Material Id",
						_size=64,
						_groupcode=CODE_GRP_KEYMAT,
						_indicator=True,
						_index=1),
			"crypto_init_len"   : Field(
						_name="Crypto Initialization Length",
						_size=4,
						_groupcode=CODE_GRP_CRYPTO_INIT,
						_indicator=True,
						_index=0),
			"crypto_init"       : Field(
						_name="Crypto Initialization",
						_size=1024,
						_groupcode=CODE_GRP_CRYPTO_INIT,
						_indicator=True,
						_index=1),
			"keytok_len"        : Field(
						_name="Key Token Length",
						_size=8,
						_groupcode=CODE_GRP_KEY_TOKEN,
						_indicator=True,
						_index=0),
			"keytok"        : Field(
						_name="Key Token",
						_size=16384,
						_groupcode=CODE_GRP_KEY_TOKEN,
						_indicator=True,
						_repeatable=True,
						_index=1),
			"autha_len"     : Field(
						_name="Auth. Data Length (A)",
						_size=7,
						_groupcode=CODE_GRP_AUTH_A,
						_indicator=True,
						_index=0),
			"autha"         : Field(
						_name="Auth Data (A)",
						_size=8192,
						_groupcode=CODE_GRP_AUTH_A,
						_indicator=True,
						_index=1),
			"authb_len"     : Field(
						_name="Auth. Data Length (B)",
						_size=7,
						_groupcode=CODE_GRP_AUTH_B,
						_indicator=True,
						_index=0),
			"authb"         : Field(
						_name="Auth Data (B)",
						_size=8192,
						_groupcode=CODE_GRP_AUTH_B,
						_indicator=True,
						_index=1),
			"acksigned"     : Field(
						_name="Signed Acknowledge Indicator",
						_size=1,
						_groupcode=CODE_GRP_MSG_SECURITY,
						_indicator=True,
						_index=6),
			"pad_len"       : Field(
						_name="Message Security Padding Length",
						_size=8,
						_groupcode=CODE_GRP_SEC_PAD,
						_indicator=True,
						_index=0),
			"padding"       : Field(
						_name="Message Security Padding",
						_size=2040,
						_groupcode=CODE_GRP_SEC_PAD,
						_index=1),
			CODE_GRP_HEADER     : Group(
						_name="Application Header",
						_isroot=True),
			CODE_GRP_ORIGIN_ADDR    : Group(
						_name="Originator Address",
						_parent=CODE_GRP_HEADER,
						_index=2),
			CODE_GRP_RCPT_ADDR  : Group(
						_name="Recipient Address Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=3),
			CODE_GRP_INFO_ADDR  : Group(
						_name="Information Address Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=4),
			CODE_GRP_MSG_HAND   : Group(
						_name="Message Handling Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=5+5*ENABLE_FUTURE_GRP),

			CODE_GRP_VMF_MSG_IDENT  : Group(
						_name="VMF Message Identification",
						_parent=CODE_GRP_MSG_HAND,
						_index=2),
			CODE_GRP_ORIGIN_DTG : Group(
						_name="Originator DTG",
						_parent=CODE_GRP_MSG_HAND,
						_index=10),
			CODE_GRP_PERISH_DTG : Group(
						_name="Perishability DTG",
						_parent=CODE_GRP_MSG_HAND,
						_index=11),
			CODE_GRP_ACK        : Group(
						_name="Acknowledgement Req. Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=12),
			CODE_GRP_RESPONSE   : Group(
						_name="Response Data Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=13),
			CODE_GRP_REF        : Group(
						_name="Reference Message Data Group",
						_is_repeatable=True,
						_max_repeat=4,
						_parent=CODE_GRP_MSG_HAND,
						_index=14),
			CODE_GRP_MSG_SECURITY   : Group(
						_name="Message Security Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=15+5*ENABLE_FUTURE_GRP),
			CODE_GRP_KEYMAT     : Group(
						_name="Keying Material Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=1),
			CODE_GRP_CRYPTO_INIT    : Group(
						_name="Crypto. Initialization Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=2),
			CODE_GRP_KEY_TOKEN  : Group(
						_name="Key Token Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=3),
			CODE_GRP_AUTH_A     : Group(
						_name="Authentication Group (A)",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=4),
			CODE_GRP_AUTH_B     : Group(
						_name="Authentication Group (B)",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=5),
			CODE_GRP_SEC_PAD    : Group(
						_name="Message Security Padding",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=7)
		}	
	
		
	def __setitem__(self, _key, _value):
		self.append_element(_key, _value)

	def __getitem__(self, _name):
		self.elements[_name]	
	
	def __delitem__(self, _key):
		self.remove_element(_key)
	
	def append_element(self, _key, _elem):
		"""
			Adds a field or group to the header.
		"""
		name = _key
		#Check if an element with a similar name
		#exists
		if name in self.elements.keys():
			value = self.elements[name]
			# Check if the value is a list, if it is 
			# and the field is repeatable, append the
			# element to the list.
			if (isinstance(value, list)):
				nb_elem = len(value)
				if (nb_elem < _elem.max_repeat):
					value.append(_elem)
				else:
					raise Exception("""
						Cannot add additional element '{:s}'. Either the element 
						is not repeatable or maximum number of elements 
						reached.""".format(name))
			else:
				# If the element is repeatable, assume that the provided
				# element is a new one. Creates a list of elements.
				if _elem.is_repeatable:
					tmplist = [value, _elem]
					self.elements[name] = tmplist
				# Other, the default behaviour is to replace the current
				# element
				else:
					self.elements[name] = _elem
					
					
	def remove_element(self, _name):
		del self.elements[_name]
		
	def clear_elements(self):
		self.elements.clear()
		
	def groups(self):
		"""
		Returns a dictionary of the header elements which are
		groups.
		"""
		g = {}
		for (key, value) in self.elements.iteritems():
			if isinstance(value, Group):
				g[key] = value
		return g

	def fields(self):
		"""
		Returns a dictionary of the header elements which are
		fields.
		"""
		f = {}
		for (key, value) in self.elements.iteritems():
			if isinstance(value, Field):
				f[key] = value
		return f 
		
	def sort(self):
		root = self.elements[CODE_GRP_HEADER]
		if (root):
			root.fields.sort()
		else:
			raise Exception("No root group from in message.")
		
	
	def __iter__(self): 
		return self.elements.itervalues()

	def get_bit_array(self):
		root = self.elements[CODE_GRP_HEADER]
		root.fields.sort()
		if (root):
			return root.get_bit_array()
		else:
			raise Exception("No root group from in message.")

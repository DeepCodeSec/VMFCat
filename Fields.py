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
import imp
try:
	imp.find_module('enum')
	from enum import Enum
except ImportError:
	print("[-] Could not load the 'Enum' module. Use `pip install Enum` to install it.")
	sys.exit(1)

try:
	imp.find_module('bitstring')
	from bitstring import BitArray
except ImportError:
	print("[-] Could not load the 'bitstring' module. Use `pip install bitstring` to install it.")
	sys.exit(1)

from Elements import *
from datetime import datetime
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Global Variables

ENABLE_FUTURE_GRP = 0
# Terminator character for strings in VMF messages
TERMINATOR 	= 0x7F
# Value used when seconds are not specified in date time groups
NO_STATEMENT	= 63
#//////////////////////////////////////////////////////////


# =============================================================================
# VMF Version Enumeration Class
#
# Description: 
#   Enumerates the different versions of the VMF protocol.
#
class version(Enum):
    std47001  = 0x0
    std47001b = 0x1
    std47001c = 0x2
    std47001d = 0x3
    std47001d_change = 0x4
    undefined1 = 0x5
    undefined2 = 0x6
    undefined3 = 0x7
    undefined4 = 0x8
    undefined5 = 0x9
    undefined6 = 0xa
    undefined7 = 0xb
    undefined8 = 0xc
    undefined9 = 0xd
    undefined10 = 0xe
    not_implemented = 0xf
# =============================================================================

# =============================================================================
# Data Compression Types Enumeration Class
#
# Description: 
#   Enumerates the different data compression methods
#   supported by the VMF protocol.
#
class data_compression(Enum):
    unix = 0x0
    gzip = 0x1
    undefined1 = 0x2
    undefined2 = 0x3
# =============================================================================

# =============================================================================
# Uniform Message Format (UMF) Enumeration Class
#
# Description: 
#
class umf(Enum):
    link16 = 0x0
    binary = 0x1
    vmf = 0x2
    nitfs = 0x3
    rdm = 0x4
    usmtf = 0x5
    doi103 = 0x6
    xml_mtf = 0x7
    xml_vmf = 0x8
    undefined1 = 0x9
    undefined2 = 0xA
    undefined3 = 0xB
    undefined4 = 0xC
    undefined5 = 0xD
    undefined6 = 0xE
    undefined7 = 0xF    
# =============================================================================

class operation(Enum):
    operation = 0x0
    exercise = 0x1
    simulation = 0x2
    test = 0x3
    
class precedence(Enum):
    reserved1 = 0x7
    reserved2 = 0x6
    critic = 0x5
    flash_override = 0x4
    flash = 0x3
    immediate = 0x2
    priority = 0x1
    routine = 0x0
    
class classification(Enum):
    unclassified = 0x0
    confidential = 0x1
    secret = 0x2
    top_secret = 0x3

class rc_codes(Enum):
    undefined0 = 0x0
    machine_receipt = 0x1
    cantpro = 0x2
    oprack = 0x3
    wilco = 0x4
    havco = 0x5
    cantco = 0x6
    undefined7 = 0x7

class fad_codes(Enum):
    netcon = 0x0
    geninfo = 0x1
    firesp = 0x2
    airops = 0x3
    intops = 0x4
    landops = 0x5
    marops = 0x6
    css = 0x7
    specialops = 0x8
    jtfopsctl = 0x9
    airdef = 0xA
    undefined1 = 0xB
    undefined2 = 0xC
    undefined3 = 0XD
    undefined4 = 0xE
    undefined5 = 0xF


class cantco_reasons(Enum):
    comms = 0x0
    ammo = 0x1
    pers = 0x2
    fuel = 0x3
    env = 0x4
    equip = 0x5
    tactical = 0x6
    other = 0x7

class cantpro_reasons(Enum):
    undefned = 0x00
    field_content = 0x01
    msg_routing = 0x02
    address = 0x03
    ref_point = 0x04
    fire_units = 0x05
    mission_ctrl = 0x06
    mission_num = 0x07
    target_num = 0x08
    schd_num = 0x09
    ctrl_addr = 0x0A
    track_num = 0x0B
    invalid = 0x0C
    msg_conv = 0x0D
    file_full = 0x0E
    unrec_msg_num = 0x0F
    corelate_file = 0x10
    limit_exceed = 0x11
    sys_inactive = 0x12
    addr_unk = 0x13
    cant_fwd_acy = 0x14
    cant_fwd_lnk = 0x15
    ill_jux_fields = 0x16
    fail_uncompress_lzw = 0x17
    fail_uncompress_lz77 = 0x18
    too_old = 0x19
    sec_restrict = 0x1A
    auth_fail = 0x1B
    crt_404 = 0x1C
    crt_invalid = 0x1D
    spi_unsupported = 0x1E
    fail_signed_ack = 0x1F
    no_retrans = 0x20


# =============================================================================
# Parameter information
class Params:
    parameters = {
      "debug" : {
            "cmd"       : "debug",
            "help"      : "Enables debug mode.",
            "choices"   : [True, False]
            },
      "data" : {
	    "cmd"	: "data",
	    "help"  : "Specifies a file containing data to be included in the VMF message.",
	    "choices"	: []
	    },
      CODE_FLD_VERSION : {
            "cmd"       : "vmfversion",
            "help"      :
                """Field representing the version of the MIL-STD-2045-47001 header being used for the message.""",
            "choices"   : ["std47001", "std47001b","std47001c","std47001d","std47001d_change"]
            },
      CODE_FLD_COMPRESS : {
            "cmd"       : "compress",
            "help"      :
                """This field represents whether the message or messages contained in the User Data portion of the Application PDU have been UNIX compressed or compressed using GZIP.""",
            "choices"   : ["unix", "gzip"]
            },
      CODE_FLD_MSG_SIZE : {
            "cmd"       : "headersize",
            "help"      :
                """Indicates the size in octets of the header""",
            "choices"   : []
          },
      CODE_FLD_ORIG_URN : {
            "cmd"       : "originator_urn",
            "help"      : """24-bit code used to uniquely identify friendly military units, broadcast networks and multicast groups.""",
            "choices"   : []
          },
      CODE_FLD_ORIG_UNIT : {
            "cmd"       : "originator_unitname",
            "help"      : """Specify the name of the unit sending the message.""",
            "choices"   : []
          },
      CODE_FLD_RCPT_URN : {
            "cmd"       : "rcpt_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      CODE_FLD_RCPT_UNIT: {
            "cmd"       : "rcpt_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      CODE_FLD_INFO_URN : {
            "cmd"       : "info_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      CODE_FLD_INFO_UNIT: {
            "cmd"       : "info_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      CODE_FLD_UMF      : {
            "cmd"       : "umf",
            "choices"   : ["link16", "binary", "vmf", "nitfs", "rdm", "usmtf", "doi103", "xml-mtf", "xml-vmf"],
            "help"      : """ Indicates the format of the message contained in the user data field."""
          },
      CODE_FLD_MSG_VERS : {
            "cmd"       : "messagevers",
            "choices"   : [],
            "help"      : """Represents the version of the message standard contained in the user data field."""
            },
      CODE_FLD_FAD      : {
            "cmd"       : "fad",
            "choices"   : ["netcon", "geninfo", "firesp", "airops", "intops", "landops","marops", "css", "specialops", "jtfopsctl", "airdef"],
            "help"      : "Identifies the functional area of a specific VMF message using code words."
            },
      CODE_FLD_MSG_NUM  : {
            "cmd"       : "msgnumber",
            "choices"   : [],
            "help"      : """Represents the number that identifies a specific VMF message within a functional area."""
            },
      "msgsubtype"      : {
            "cmd"       : "msgsubtype",
            "choices"   : [],
            "help"      : """Represents a specific case within a VMF message, which depends on the UMF, FAD and message number."""
            },
      CODE_FLD_FILENAME : {
            "cmd"       : "filename",
            "choices"   : [],
            "help"      : """Indicates the name of the computer file or data block contained  in the User Data portion of the application PDU."""
            },
      "msgsize"         : {
            "cmd"       : "msgsize",
            "choices"   : [],
            "help"      : """Indicates the size(in bytes) of the associated message within the User Data field."""
            },
      "opind"           : {
            "cmd"       : "opind",
            "choices"   : ["op", "ex", "sim", "test"],
            "help"      : "Indicates the operational function of the message."
            },
      "retransmission"  : {
            "cmd"       : "retransmission",
            "choices"   : [1, 0],
            "help"      : """Indicates whether a message is a retransmission."""
            },
      "msgprecedence"   : {
            "cmd"       : "msgprecedence",
            "choices"   : ["reserved", "critic", "flashover", "flash", "imm", "pri", "routine"],
            "help"      : """Indicates relative precedence of a message."""
            },
      "classification"  : {
            "cmd"       : "classification",
            "choices"   : ["unclass", "conf", "secret", "topsecret"],
            "help"      : """Security classification of the message."""
            },
      "releasemark"     : {
            "cmd"       : "releasemark",
            "choices"   : [],
            "help"      : """Support the exchange of a list of up to 16 country codes with which the message can be release."""
            },
      "originatordtg"   : {
            "cmd"       : "originatordtg",
            "choices"   : [],
            "help"      : """ Contains the date and time in Zulu Time that the message was prepared."""
            },
      "perishdtg"   : {
            "cmd"       : "perishdtg",
            "choices"   : [],
            "help"      : """Provides the latest time the message is still of value."""
            },
      "ackmachine"      : {
            "cmd"       : "ackmachine",
            "choices"   : [1, 0],
            "help"      : """Indicates whether the originator of a machine requires a machine acknowledgement for the message."""
            },
      "ackop"           : {
            "cmd"       : "ackop",
            "choices"   : [1, 0],
            "help"      : """Indicates whether the originator of the message requires an acknowledgement for the message from the recipient."""
            },
      "reply"           : {
            "cmd"       : "reply",
            "choices"   : [1, 0],
            "help"      : """Indicates whether the originator of the message requires an operator reply to the message."""
            }
    }


# =============================================================================
# Field Class
# Contains common properties to VMF fields 
class Field(HeaderElement):

	def __init__(self, _name, _size, _value=0, _groupcode = 0, 
		_repeatable=False, _max_repeat=0, _indicator=False, _string=False,
		_enumerator=None, _index=0):
		
		super(Field, self).__init__(_name, _repeatable, _max_repeat, _index)
		
		self.pi = DEFAULT_FPI
		self.ri = DEFAULT_FRI
		self.size = _size
		self.value = _value
		self.is_string = _string
		self.grp_code = _groupcode
		self.is_indicator = _indicator
		self.enumerator = _enumerator
		self.format_str = "{:#0" + str(self.size+2) + "b}"

	def __repr__(self):
		return "<Field: {:d}:{:s}:{:s}>".format(self.index, self.name, str(self.value))

	def __cmp__(self, _field):
		if (isinstance(_field, Field)):
			return self.index.__cmp__(_field.index)
		elif (isinstance(_field, Group)):
			return self.index.__cmp__(_field.index)
		else:
			raise Exception("Provided comparision item must be an integer.")
			
	def enable_and_set(self, _value):
		if (_value != None):
			self.pi = PRESENT
			self.value = _value

	def get_value_from_dict(self, _key, _dict):
		for key, value in _dict.__dict__.items():
			if (key.lower() == _key.lower()):
				return value
		return None		
		
	def get_bit_array(self):
		b = BitArray()
		# Some fields do no have a FPI field assigned to them.
		# Therefore, these fields must only contain bits representing
		# their value.
		if (self.is_indicator):
			field_value = self.value
			#TODO: Replace string with constant/field variable
			if (self.name == "Version" and self.enumerator):
				field_value = self.get_value_from_dict(self.value, self.enumerator)
				b.append(self.format_str.format(field_value))
			else: 
				field_value = int(self.value)
				b.append("{:#03b}".format(field_value))
			return b
		else:
			# Include the FPI
			b.append("{:#03b}".format(self.pi))

			# If the fiels is flagged as present, then
			# append additional data.
			if (self.pi == PRESENT):
				if (not self.is_string):
					field_value = int(self.value)
				else:
					field_value = self.value

				# If the field is provided with an enumerator,get the
				# numeric value.
				if (self.enumerator):
					field_value = self.get_value_from_dict(self.value, self.enumerator)
				

				# If the value is numeric, convert directly to a bitstring
				if (isinstance(field_value, int)):
					# Include the FRI is the field is repeatable
					if (self.is_repeatable):
						b.append("{:#03b}".format(self.fri))
				#	if (self.pi == PRESENT or self.is_indicator):
					b.append(self.format_str.format(field_value))
				elif (isinstance(field_value, str) or isinstance(field_value, unicode)):
					sb = self.string_to_bitarray(field_value)
					b.append(sb)
				else:
					raise Exception("Unsupported type for field {:s}: {:s}".format(self.name, type(field_value)))
			return b

	def string_to_bitarray(self, _string, _maxsize=448):
		b = BitArray()
		pos = 0
		if (_string):
			for c in _string:
				c_str = "{:#09b}".format(ord(c))
				print("{:s}:{:s}".format(c, c_str))
				b.insert(c_str, pos)
				pos += 7
		if (len(b.bin) < _maxsize):
			b.insert("{:#09b}".format(TERMINATOR), pos)
		if (len(b.bin) > _maxsize):
			raise Exception("Size of bit array exceeds the maximum size allowed ({:d}).".format(_maxsize))
		return b


# =============================================================================

# =============================================================================
# Datetime Group (DTG) Field Class
# Represents a field containing a DTG value. 
class dtg_field(Field):
    has_extension = False
        
    def __init__(self, _name, _size=46, _value=0, _groupcode = 0, _repeatable=False, _extension=True, _index=0):
        super(dtg_field, self).__init__(_name, _size, _value, _groupcode, _repeatable, _index)
        self.has_extension=_extension
        self.fields = {
            "year"  : Field(
                    _name="year", 
                    _size=7, 
                    _indicator=True,
                    _index=0),
            "month" : Field(
                    _name="month", 
                    _size=4, 
                    _indicator=True,
                    _index=1),
            "day"   : Field(
                    _name="day", 
                    _size=5, 
                    _indicator=True,
                    _index=2),
            "hour"  : Field(
                    _name="hour", 
                    _size=5, 
                    _indicator=True,
                    _index=3),
            "minute": Field(
                    _name="minute", 
                    _size=6, 
                    _indicator=True,
                    _index=4),
            "second": Field(
                    _name="second", 
                    _size=6, 
                    _value=NO_STATEMENT,
                    _indicator=True,
                    _index=5),
            "ext"   : Field(
                    _name="extension",
                    _size=12,
                    _index=6)
        }
        self.enable_and_set(_value)

    def enable_and_set(self, _value):
        #Expected format: YYYY-MM-DD HH:mm[:ss] [extension]"
	if (_value == None):
		return 

        self.value = _value
        if (_value):
            self.pi = PRESENT
            date_items = _value.split(' ')

            if (len(date_items) == 2 or len(date_items) == 3):
                format_str = "%Y-%m-%d %H:%M"
                #
                # Check if seconds are included.
                #
                secondsIncluded = False
                if (date_items[1].count(":") > 1):
                    format_str = "%Y-%m-%d %H:%M:%S"
                    secondsIncluded = True
                else:
                    self.fields["second"].enable_and_set(NO_STATEMENT)
                #TODO: the year should only contain the last 2 digits, not the entire
                date_obj = datetime.strptime(date_items[0] + ' ' + date_items[1], format_str)
		century = int(date_obj.year / 100)
		year = date_obj.year % 100
			
                # 4 digits.
                self.fields["year"].enable_and_set(year)
                self.fields["month"].enable_and_set(date_obj.month)
                self.fields["day"].enable_and_set(date_obj.day)
                self.fields["hour"].enable_and_set(date_obj.hour)
                self.fields["minute"].enable_and_set(date_obj.minute)
                if (secondsIncluded):
                    self.fields["second"].enable_and_set(date_obj.second)
                #               
                # Check if extension has been included
                #
                if (len(date_items) == 3):
                    self.fields["ext"].enable_and_set(date_items[2])
                print(self)
            else:
                raise Exception("Unknown datetime group format: {:s}.".format(_value))

        #else:
        #   raise Exception("Datetime group provided is null or empty.")
        
    def get_bit_array(self):
        b = BitArray()
        dtgfields = self.fields.values()
        #self.fields.sort()
        dtgfields.sort()
        for f in dtgfields:
            if (f.name == "ext"):
                if (self.has_extension):
                    fbits = f.get_bit_array()
                    b.append(fbits)
            else:
                fbits = f.get_bit_array()
                b.append(fbits)
        return b

    def __repr__(self):
        return "<Datetime Group Field: {:d}:{:s}:{:s}>".format(self.index, self.name, str(self.value))
        
# =============================================================================



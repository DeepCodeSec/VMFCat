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
from Fields import Field
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Global Variables


#//////////////////////////////////////////////////////////

# =============================================================================
# Group Class
#
# Description:
#   Class to represent sets of fields with similar functions.
#
class Group(HeaderElement):

    def __init__(self, _name, _is_repeatable=False, _isroot=False, 
		_parent=None, _max_repeat=1, _index=0):
		
        super(Group, self).__init__(_name, _is_repeatable, _max_repeat, _index)
		
        self.pi = DEFAULT_GPI
        self.ri = DEFAULT_GRI
        self.is_root = _isroot
        self.parent_group = _parent
        self.fields = []#*(6+15*ENABLE_FUTURE_GRP)

    def __repr__(self):
        return "{:d}:{:s}".format(self.index, self.name)

    def __cmp__(self, _field):
        if (isinstance(_field, Field)):
            return self.index.__cmp__(_field.index)
        elif (isinstance(_field, Group)):
            return self.index.__cmp__(_field.index)
        else:
            raise Exception("Provided comparision item must be an integer.")

    def enable(self):
        self.pi = PRESENT

    def set_gri(self, _value):
        self.ri = _value

    def clear_fields(self):
        self.fields = []
		
    def append_field(self, _field):
        if (_field.pi == PRESENT):
            self.pi = PRESENT
        self.fields.append(_field)

		
    def get_bit_array(self):
		b = BitArray()
		# Do not include a GPI/GRI for the root group,
		# which is only a container.
		if (not self.is_root):
			# Includes the GPI
			b.append("{:#03b}".format(self.pi))
		
			# If this group is absent, no more bits
			# are needed
			if (self.pi == ABSENT):
				return b

			# If this is a repeatable field, include
			# the current value of the GRI
			if (self.is_repeatable):
				b.append("{:#03b}".format(self.ri))

		# Append all the sub bitstrings of each
		# field contained in the group
		for f in self.fields:
			fbits = f.get_bit_array()
			b.append(fbits)
		return b



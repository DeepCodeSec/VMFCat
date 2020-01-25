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
from enum import Enum
from bitstring import BitArray
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Global constants
ABSENT  = 0x0
PRESENT = 0x1

DEFAULT_FPI = ABSENT
DEFAULT_FRI = 0
DEFAULT_GPI = ABSENT
DEFAULT_GRI = 0

CODE_FLD_VERSION 	=	"vmfversion"
CODE_FLD_COMPRESS	=	"compress"
CODE_FLD_ORIG_URN	=	"originator_urn"
CODE_FLD_ORIG_UNIT	= 	"originator_unitname"
CODE_FLD_RCPT_URN	= 	"rcpt_urns"
CODE_FLD_RCPT_UNIT	= 	"rcpt_unitnames"
CODE_FLD_INFO_URN	= 	"info_urns"
CODE_FLD_INFO_UNIT	= 	"info_unitnames"
CODE_FLD_UMF		=	"umf"
CODE_FLD_MSG_VERS	=	"messagevers"
CODE_FLD_FAD		=	"fad"
CODE_FLD_MSG_NUM	=	"msgnumber"
CODE_FLD_MSG_STYPE	=	"msgsubtype" 
CODE_FLD_FILENAME	=	"filename"
CODE_FLD_MSG_SIZE	=	"msgsize" 
CODE_FLD_OPIND		=	"opind"
CODE_FLD_RETX		=	"retransmission"
CODE_FLD_MSG_PREC	=	"msgprecedence"
CODE_FLD_CLASS		=	"classification"
CODE_FLD_RELEASE	=	"releasemark"
CODE_FLD_ORIG_DTG	=	"originatordtg"
CODE_FLD_PRSH_DTG	=	"perishdtg"
CODE_FLD_MCHN_ACK	=	"ackmachine"

CODE_GRP_HEADER     = "header"
CODE_GRP_ORIGIN_ADDR    = "g1"
CODE_GRP_RCPT_ADDR  = "g2"
CODE_GRP_INFO_ADDR  = "g3"
CODE_GRP_MSG_HAND   = "r3"
CODE_GRP_VMF_MSG_IDENT  = "g9"
CODE_GRP_ORIGIN_DTG = "g10"
CODE_GRP_PERISH_DTG = "g11"
CODE_GRP_ACK        = "g12"
CODE_GRP_RESPONSE   = "g13"
CODE_GRP_REF        = "g14"
CODE_GRP_MSG_SECURITY   = "g20"
CODE_GRP_KEYMAT     = "g21"
CODE_GRP_CRYPTO_INIT    = "g22"
CODE_GRP_KEY_TOKEN  = "g23"
CODE_GRP_AUTH_A     = "g24"
CODE_GRP_AUTH_B     = "g25"
CODE_GRP_SEC_PAD    = "g26"
#//////////////////////////////////////////////////////////

class HeaderElement(object):

	def __init__(self, _name, _repeatable=False, _max_repeat=0, _index=0):
		
		self.pi	= ABSENT					# Presence indicator
		self.ri = ABSENT					# Recurrence indicator
		self.name = _name					# Name of the element
		self.is_repeatable = _repeatable	# Is the element repeatable?
		self.max_repeat = _max_repeat		# If so, maximum times it 
											# can repeated
		self.index = _index					# Index/order of the element
											# in the header/group
		
	def __repr__(self):
		return "<HeaderElement '{:s}'>".format(self.name)
		
	def __str__(self):
		return self.name
		
	def __cmp__(self, _object):
		pass
		
	def is_present(self):
		return self.pi == PRESENT		

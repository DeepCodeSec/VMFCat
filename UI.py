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
#//////////////////////////////////////////////////////////
# Program Information
#
PROGRAM_NAME = "vmfcat"
PROGRAM_DESC = ""
PROGRAM_USAGE = "%(prog)s [-i] [-h|--help] (OPTIONS)"

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Imports Statements
import re
import sys
import json
import argparse
import traceback
from Factory import *
from Logger import *
from bitstring import *
#//////////////////////////////////////////////////////////


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
		"choices" : []
	    },
      "vmfversion" : {
            "cmd"       : "vmfversion",
            "help"      :
                """Field representing the version of the MIL-STD-2045-47001 header being used for the message.""",
            "choices"   : ["std47001", "std47001b","std47001c","std47001d","std47001d_change"]
            },
      "compress" : {
            "cmd"       : "compress",
            "help"      :
                """This field represents whether the message or messages contained in the User Data portion of the Application PDU have been UNIX compressed or compressed using GZIP.""",
            "choices"   : ["unix", "gzip"]
            },
      "headersize" : {
            "cmd"       : "headersize",
            "help"      :
                """Indicates the size in octets of the header""",
            "choices"   : []
          },
      "originator_urn" : {
            "cmd"       : "originator_urn",
            "help"      : """24-bit code used to uniquely identify friendly military units, broadcast networks and multicast groups.""",
            "choices"   : []
          },
      "originator_unitname" : {
            "cmd"       : "originator_unitname",
            "help"      : """Specify the name of the unit sending the message.""",
            "choices"   : []
          },
      "rcpt_urns"       : {
            "cmd"       : "rcpt_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      "rcpt_unitnames"       : {
            "cmd"       : "rcpt_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      "info_urns"       : {
            "cmd"       : "info_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      "info_unitnames"       : {
            "cmd"       : "info_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      "umf"             : {
            "cmd"       : "umf",
            "choices"   : ["link16", "binary", "vmf", "nitfs", "rdm", "usmtf", "doi103", "xml-mtf", "xml-vmf"],
            "help"      : """ Indicates the format of the message contained in the user data field."""
          },
      "messagevers"     : {
            "cmd"       : "messagevers",
            "choices"   : [],
            "help"      : """Represents the version of the message standard contained in the user data field."""
            },
      "fad"             : {
            "cmd"       : "fad",
            "choices"   : ["netcon", "geninfo", "firesp", "airops", "intops", "landops","marops", "css", "specialops", "jtfopsctl", "airdef"],
            "help"      : "Identifies the functional area of a specific VMF message using code words."
            },
      "msgnumber"       : {
            "cmd"       : "msgnumber",
            "choices"   : [],
            "help"      : """Represents the number that identifies a specific VMF message within a functional area."""
            },
      "msgsubtype"      : {
            "cmd"       : "msgsubtype",
            "choices"   : [],
            "help"      : """Represents a specific case within a VMF message, which depends on the UMF, FAD and message number."""
            },
      "filename"        : {
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
      "ackdtg"           : {
            "cmd"       : "ackdtg",
            "choices"   : [],
            "help"      : """Provides the date and time of the original message that is being acknowledged."""
            },
      "rc"           : {
            "cmd"       : "rc",
            "choices"   : ["mr", "cantpro", "oprack", "wilco", "havco", "cantco", "undef"],
            "help"      : """Codeword representing the Receipt/Compliance answer to the acknowledgement request."""
            },
	  "cantpro"       	: {
			"cmd"       : "cantpro",
			"choices"   : [],
			"help"      : """Indicates the reason that a particular message cannot be processed by a recipient or information address."""
			},	
      "reply"           : {
            "cmd"       : "reply",
            "choices"   : [1, 0],
            "help"      : """Indicates whether the originator of the message requires an operator reply to the message."""
            },
	  "cantco"       	: {
			"cmd"       : "cantco",
			"choices"   : ["comm", "ammo", "pers", "fuel", "env", "equip", "tac", "other"],
			"help"      : """Indicates the reason that a particular recipient cannot comply with a particular message."""
			},
	  "replyamp"       	: {
			"cmd"       : "replyamp",
			"choices"   : [],
			"help"      : """Provide textual data an amplification of the recipient's reply to a message."""
			},			
	  "ref_urn"       	: {
			"cmd"       : "ref_urn",
			"choices"   : [],
			"help"      : """URN of the reference message."""
			},
	  "ref_unitname"       	: {
			"cmd"       : "ref_unitname",
			"choices"   : [],
			"help"      : """Name of the unit of the reference message."""
			},
	  "refdtg"       	: {
			"cmd"       : "refdtg",
			"choices"   : [],
			"help"      : """Date time group of the reference message."""
			},
	  "secparam"       	: {
			"cmd"       : "secparam",
			"choices"   : ['auth', 'undef'],
			"help"      : """Indicate the identities of the parameters and algorithms that enable security processing."""			
			},		
	  "keymatlen"       	: {
			"cmd"       : "keymatlen",
			"choices"   : [],
			"help"      : """Defines the size in octets of the Keying Material ID field."""			
			},
	  "keymatid"       	: {
			"cmd"       : "keymatid",
			"choices"   : [],
			"help"      : """Identifies the key which was used for encryption."""			
			},
	  "crypto_init_len"       	: {
			"cmd"       : "crypto_init_len",
			"choices"   : [],
			"help"      : """Defines the size, in 64-bit blocks, of the Crypto Initialization field."""
			},
	  "crypto_init"       	: {
			"cmd"       : "crypto_init",
			"choices"   : [],
			"help"      : """Sequence of bits used by the originator and recipient to initialize the encryption/decryption process."""
			},
	  "keytok_len"       	: {
			"cmd"       : "keytok_len",
			"choices"   : [],
			"help"      : """Defines the size, in 64-bit blocks, of the Key Token field."""
			},
	  "keytok"       	: {
			"cmd"       : "keytok",
			"choices"   : [],
			"help"      : """Contains information enabling each member of each address group to decrypt the user data associated with this message header."""
			},
	  "autha-len"       : {
			"cmd"       : "autha-len",
			"choices"   : [],
			"help"      : """Defines the size, in 64-bit blocks, of the Authentification Data (A) field."""
			},	
	  "authb-len"       : {
			"cmd"       : "authb-len",
			"choices"   : [],
			"help"      : """Defines the size, in 64-bit blocks, of the Authentification Data (B) field."""
			},	
	  "autha"       : {
			"cmd"       : "autha",
			"choices"   : [],
			"help"      : """Data created by the originator to provide both connectionless integrity and data origin authentication (A)."""
			},	
	  "authb"       : {
			"cmd"       : "authb",
			"choices"   : [],
			"help"      : """Data created by the originator to provide both connectionless integrity and data origin authentication (B)."""
			},	
	  "acksigned"       : {
			"cmd"       : "acksigned",
			"choices"   : [],
			"help"      : """Indicates whether the originator of a message requires a signed response from the recipient."""
			},
	  "pad_len"       : {
			"cmd"       : "pad_len",
			"choices"   : [],
			"help"      : """Defines the size, in octets, of the message security padding field."""
			},
	  "padding"       : {
			"cmd"       : "padding",
			"choices"   : [],
			"help"      : """Necessary for a block encryption algorithm so the content of the message is a multiple of the encryption block length."""
			},						
    }
	

#//////////////////////////////////////////////////////////////////////////////
# Argument Parser Declaration
#
usage = "%(prog)s [options] data"
parser = argparse.ArgumentParser(usage=usage,
    prog="vmfcat",
    version="%(prog)s "+__version__,
    description="Allows crafting of Variable Message Format (VMF) messages.")

io_options = parser.add_argument_group(
    "Input/Output Options", "Types of I/O supported.")
io_options.add_argument("-d", "--debug",
    dest=Params.parameters['debug']['cmd'],
    action="store_true",
    help=Params.parameters['debug']['help'])
io_options.add_argument("-i", "--interactive",
    dest="interactive",
    action="store_true",
    help="Create and send VMF messages interactively.")
io_options.add_argument("-of", "--ofile",
    dest="outputfile",
    nargs="?",
    type=argparse.FileType('w'),
        default=sys.stdout,
        help="File to output the results. STDOUT by default.")
io_options.add_argument("--data",
    dest=Params.parameters['data']['cmd'],
    help=Params.parameters['data']['help'])
# =============================================================================
# Application Header Arguments
header_options = parser.add_argument_group(
    "Application Header", "Flags and Fields of the application header.")
header_options.add_argument("--vmf-version",
    dest=Params.parameters["vmfversion"]["cmd"],
    action="store",
    choices=Params.parameters["vmfversion"]["choices"],
        default="std47001c",
        help=Params.parameters["vmfversion"]["help"])
header_options.add_argument("--compress",
    dest=Params.parameters["compress"]["cmd"],
    action="store",
    choices=Params.parameters["compress"]["choices"],
    help=Params.parameters["compress"]["help"])
header_options.add_argument("--header-size",
    dest=Params.parameters["headersize"]["cmd"],
    action="store",
    type=int,
    help=Params.parameters["headersize"]["help"])

# =============================================================================
# Originator Address Group Arguments
orig_addr_options = parser.add_argument_group(
    "Originator Address Group", "Fields of the originator address group.")
orig_addr_options.add_argument("--orig-urn",
    dest=Params.parameters["originator_urn"]["cmd"],
    metavar="URN",
    type=int,
    action="store",
    help=Params.parameters["originator_urn"]["help"])
orig_addr_options.add_argument("--orig-unit",
    dest=Params.parameters["originator_unitname"]["cmd"],
    metavar="STRING",
    action="store",
    help=Params.parameters["originator_unitname"]["help"])
# =============================================================================

# =============================================================================
# Recipient Address Group Arguments
recp_addr_options = parser.add_argument_group(
    "Recipient Address Group", "Fields of the recipient address group.")
recp_addr_options.add_argument("--rcpt-urns",
    nargs="+",
    dest=Params.parameters['rcpt_urns']['cmd'],
    metavar="URNs",
    help=Params.parameters['rcpt_urns']['help'])
recp_addr_options.add_argument("--rcpt-unitnames",
    nargs="+",
    dest=Params.parameters['rcpt_unitnames']['cmd'],
    metavar="UNITNAMES",
    help=Params.parameters['rcpt_unitnames']['help'])
# =============================================================================

# =============================================================================
# Information Address Group Arguments
info_addr_options = parser.add_argument_group(
    "Information Address Group", "Fields of the information address group.")
info_addr_options.add_argument("--info-urns",
    dest=Params.parameters["info_urns"]["cmd"],
    metavar="URNs",
    nargs="+",
    action="store",
    help=Params.parameters["info_urns"]["help"])
info_addr_options.add_argument("--info-units",
    dest="info_unitnames",
    metavar="UNITNAMES",
    action="store",
    help="Specify the name of the unit of the reference message.")
# =============================================================================

# =============================================================================
# Message Handling Group Arguments
msg_handling_options = parser.add_argument_group(
    "Message Handling Group", "Fields of the message handling group.")
msg_handling_options.add_argument("--umf",
    dest=Params.parameters["umf"]["cmd"],
    action="store",
    choices=Params.parameters["umf"]["choices"],
    help=Params.parameters["umf"]["help"])
msg_handling_options.add_argument("--msg-version",
    dest=Params.parameters["messagevers"]["cmd"],
    action="store",
    metavar="VERSION",
    type=int,
    help=Params.parameters["messagevers"]["help"])
msg_handling_options.add_argument("--fad",
    dest=Params.parameters["fad"]["cmd"],
    action="store",
    choices=Params.parameters["fad"]["choices"],
    help=Params.parameters["fad"]["help"])
msg_handling_options.add_argument("--msg-number",
    dest=Params.parameters["msgnumber"]["cmd"],
    action="store",
    type=int,
    metavar="1-127",
    help=Params.parameters["msgnumber"]["help"])
msg_handling_options.add_argument("--msg-subtype",
    dest=Params.parameters["msgsubtype"]["cmd"],
    action="store",
    type=int,
    metavar="1-127",
    help=Params.parameters["msgsubtype"]["help"])
msg_handling_options.add_argument("--filename",
    dest=Params.parameters["filename"]["cmd"],
    action="store",
    help=Params.parameters["filename"]["help"])
msg_handling_options.add_argument("--msg-size",
    dest=Params.parameters["msgsize"]["cmd"],
    action="store",
    type=int,
    metavar="SIZE",
    help=Params.parameters["msgsize"]["help"])

msg_handling_options.add_argument("--opind",
    dest=Params.parameters["opind"]["cmd"],
    action="store",
    choices=Params.parameters["opind"]["choices"],
    help=Params.parameters["opind"]["help"])

msg_handling_options.add_argument("--retrans",
    dest=Params.parameters["retransmission"]["cmd"],
    action="store_true",
    help=Params.parameters["retransmission"]["help"])

msg_handling_options.add_argument("--msg-prec",
    dest=Params.parameters["msgprecedence"]["cmd"],
    action="store",
    choices=Params.parameters["msgprecedence"]["choices"],
    help=Params.parameters["msgprecedence"]["help"])

msg_handling_options.add_argument("--class",
    dest=Params.parameters["classification"]["cmd"],
    action="store",
    nargs="+",
    choices=Params.parameters["classification"]["choices"],
    help=Params.parameters["classification"]["cmd"])

msg_handling_options.add_argument("--release",
    dest=Params.parameters["releasemark"]["cmd"],
    action="store",
    metavar="COUNTRIES",
    help=Params.parameters["releasemark"]["help"])

msg_handling_options.add_argument("--orig-dtg",
    dest=Params.parameters["originatordtg"]["cmd"],
    action="store",
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]",
    help=Params.parameters["originatordtg"]["cmd"])
msg_handling_options.add_argument("--perish-dtg",
    dest=Params.parameters["perishdtg"]["cmd"],
    action="store",
    metavar="YYYY-MM-DD HH:mm[:ss]",
    help=Params.parameters["perishdtg"]["cmd"])

# =====================================================================================

# =====================================================================================
# Acknowledge Request Group Arguments
ack_options = parser.add_argument_group(
    "Acknowledgement Request Group", "Options to request acknowledgement and replies.")
ack_options.add_argument("--ack-machine",
    dest=Params.parameters["ackmachine"]["cmd"],
    action="store_true",
    help=Params.parameters["ackmachine"]["help"])
ack_options.add_argument("--ack-op",
     dest=Params.parameters["ackop"]["cmd"],
    action="store_true",
    help=Params.parameters["ackop"]["help"])
ack_options.add_argument("--reply",
    dest=Params.parameters["reply"]["cmd"],
    action="store_true",
    help=Params.parameters["reply"]["help"])
# =====================================================================================

# =====================================================================================
# Response Data Group Arguments
#
resp_options = parser.add_argument_group(
    "Response Data Options", "Fields for the response data group.")
resp_options.add_argument("--ack-dtg", 
	dest=Params.parameters["ackdtg"]["cmd"],
	help=Params.parameters["ackdtg"]["help"],
    action="store", 
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]")
resp_options.add_argument("--rc",
	dest=Params.parameters["rc"]["cmd"],
    help=Params.parameters["rc"]["help"],
	choices=Params.parameters["rc"]["choices"],
    action="store")
resp_options.add_argument("--cantpro",
	dest=Params.parameters["cantpro"]["cmd"],
	help=Params.parameters["cantpro"]["help"],
    action="store",
    type=int,
    metavar="1-32")
resp_options.add_argument("--cantco", 
	dest=Params.parameters["cantco"]["cmd"],
    help=Params.parameters["cantco"]["help"],
	choices=Params.parameters["cantco"]["choices"],
	action="store")
resp_options.add_argument("--reply-amp", 
	dest=Params.parameters["replyamp"]["cmd"],
    help=Params.parameters["replyamp"]["help"],
    action="store")

# =====================================================================================


# =====================================================================================
# Reference Message Data Group Arguments
#
ref_msg_options = parser.add_argument_group(
    "Reference Message Data Group", "Fields of the reference message data group.")
ref_msg_options.add_argument("--ref-urn",
	dest=Params.parameters["ref_urn"]["cmd"],
    help=Params.parameters["ref_urn"]["help"],
    metavar="URN",
    action="store")
ref_msg_options.add_argument("--ref-unit", 
	dest=Params.parameters["ref_unitname"]["cmd"],
    help=Params.parameters["ref_unitname"]["help"],
    metavar="STRING",
    action="store")
ref_msg_options.add_argument("--ref-dtg", 
	dest=Params.parameters["refdtg"]["cmd"],
    help=Params.parameters["refdtg"]["help"],
    action="store", 
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]")
# =====================================================================================


# =====================================================================================
# Message Security Data Group Arguments
#
msg_sec_grp = parser.add_argument_group(
    "Message Security Group", "Fields of the message security group.")
msg_sec_grp.add_argument("--sec-param",
 	dest=Params.parameters["secparam"]["cmd"],
    help=Params.parameters["secparam"]["help"],
	choices=Params.parameters["secparam"]["choices"],
    action="store")
msg_sec_grp.add_argument("--keymat-len",
 	dest=Params.parameters["keymatlen"]["cmd"],
    help=Params.parameters["keymatlen"]["help"],
    action="store", 
    type=int)	
msg_sec_grp.add_argument("--keymat-id", 
 	dest=Params.parameters["keymatid"]["cmd"],
    help=Params.parameters["keymatid"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--crypto-init-len", 
 	dest=Params.parameters["crypto_init_len"]["cmd"],
    help=Params.parameters["crypto_init_len"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--crypto-init", 
	dest=Params.parameters["crypto_init"]["cmd"],
    help=Params.parameters["crypto_init"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--keytok-len", 
	dest=Params.parameters["keytok_len"]["cmd"],
    help=Params.parameters["keytok_len"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--keytok", 
	dest=Params.parameters["keytok"]["cmd"],
    help=Params.parameters["keytok"]["help"],
    action="store", 
    type=int)	
msg_sec_grp.add_argument("--autha-len", 
	dest=Params.parameters["autha-len"]["cmd"],
    help=Params.parameters["autha-len"]["help"],
    action="store", 
    type=int, 
    metavar="LENGTH")
msg_sec_grp.add_argument("--authb-len",
	dest=Params.parameters["authb-len"]["cmd"],
    help=Params.parameters["authb-len"]["help"],
    action="store",
    type=int,
    metavar="LENGTH")
msg_sec_grp.add_argument("--autha", 
	dest=Params.parameters["autha"]["cmd"],
    help=Params.parameters["autha"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--authb", 
	dest=Params.parameters["authb"]["cmd"],
    help=Params.parameters["authb"]["help"],
    action="store", 
    type=int)
msg_sec_grp.add_argument("--ack-signed", 
	dest=Params.parameters["acksigned"]["cmd"],
    help=Params.parameters["acksigned"]["help"],
    action="store_true")
msg_sec_grp.add_argument("--pad-len",
	dest=Params.parameters["pad_len"]["cmd"],
    help=Params.parameters["pad_len"]["help"],
    action="store", 
	type=int,
    metavar="LENGTH")
msg_sec_grp.add_argument("--padding",
	dest=Params.parameters["padding"]["cmd"],
    help=Params.parameters["padding"]["help"],
    action="store",
    type=int)
# =============================================================================
#//////////////////////////////////////////////////////////////////////////////


class VmfShell(object):
	"""
		Interative shell to Vmfcat. The shell can be use to build a VMF message.
	"""
	CMD_SAVE = 'save'
	CMD_LOAD = 'load'
	CMD_SEARCH = 'search'
	CMD_SET = 'set'
	CMD_SHOW = 'show'
	CMD_HEADER = 'header'
	CMD_HELP = 'help'
	CMD_QUIT = 'quit'

	PROMPT = "<<< "

	def __init__(self, _output=sys.stdout):
		"""
			Initializes the user interface by defining a Logger object
			and defining the standard output.
		"""
		self.output = _output
		self.logger = Logger(_output, _debug=True)

	def start(self):
		"""
			Starts the main loop of the interactive shell.
		"""
		
		# Command entered by the user
		cmd = ""
		self.logger.print_info("Type 'help' to show a list of available commands.")
		
		while (cmd.lower() != VmfShell.CMD_QUIT):
			try:
				self.output.write(VmfShell.PROMPT)
				user_input = sys.stdin.readline()
				tokens = user_input.rstrip().split()
				cmd = tokens[0]
				if (cmd.lower() == VmfShell.CMD_QUIT):
					pass
				elif (cmd.lower() == VmfShell.CMD_HELP):
					if (len(tokens) == 1):
						self.logger.print_info("{:s} <field>|all".format(VmfShell.CMD_SHOW))
						self.logger.print_info("{:s} <field> <value>".format(VmfShell.CMD_SET))
						self.logger.print_info("{:s} [field] {{bin, hex}}".format(VmfShell.CMD_HEADER))
						self.logger.print_info("{:s} <field>".format(VmfShell.CMD_HELP))
						self.logger.print_info("{:s} <field>".format(VmfShell.CMD_SEARCH))
						self.logger.print_info("{:s} <file>".format(VmfShell.CMD_SAVE))
						self.logger.print_info("{:s} <file>".format(VmfShell.CMD_LOAD))
						self.logger.print_info("{:s}".format(VmfShell.CMD_QUIT))
					else:
						param = tokens[1]
						if (param in Params.__dict__.keys()):
							help_msg = Params.parameters[param]['help']
							self.logger.print_info(help_msg)
							if (len(Params.parameters[param]['choices']) > 0):
								choices_msg = ', '.join([ choice for choice in Params.parameters[param]['choices']])
								self.logger.print_info("Available values: {:s}".format(choices_msg))
						else:
							self.logger.print_error("Unknown parameter/option: {:s}.".format(param))
				elif (cmd.lower() == VmfShell.CMD_SHOW):
					#
					# Displays the value of the given field
					#
					if (len(tokens) == 2):
						param = tokens[1]
						if (param in Params.parameters.keys()):
							value = Params.__dict__[param]
							if (isinstance(value, int)):
								value = "0x{:02x}".format(value)
							self.logger.print_info("{} = {}".format(param, value))
						elif param.lower() == "all":
							for p in Params.parameters.keys():
								value = Params.__dict__[p]
								self.logger.print_info("{} = {}".format(p, value))
						else:
							self.logger.print_error("Unknown parameter/option {:s}.".format(param))

					else:
						self.logger.print_error("Usage: {s} <field>".format(VmfShell.CMD_SHOW))
				elif (cmd.lower() == VmfShell.CMD_SET):
					#
					# Sets a field with the given value
					#
					# TODO: Issues with parameters with boolean values
					if (len(tokens) >= 3):
						param = tokens[1]
						value = ' '.join(tokens[2:])
						if (param in Params.__dict__.keys()):
							if (Params.parameters[param]["choices"]):
								if (value in Params.parameters[param]["choices"]):
									Params.__dict__[param] = value
									new_value = Params.__dict__[param]
									self.logger.print_success("{:s} = {:s}".format(param, new_value))
								else:
									self.logger.print_error("Invalid value ({:s}) for field {:s}.".format(value, param))
									self.logger.print_info("Values for field are : {:s}.".format(','.join(str(Params.parameters[param]["choices"]))))
							else:
								Params.__dict__[param] = value
								new_value = Params.__dict__[param]
								self.logger.print_success("{:s} = {:s}".format(param, new_value))
						else:
							self.logger.print_error("Unknown parameter {:s}.".format(param))
					else:
						self.logger.print_error("Usage: {:s} <field> <value>".format(VmfShell.CMD_SET))
				elif (cmd.lower() == VmfShell.CMD_HEADER):
					field = "vmfversion"
					fmt = "bin"
	
					if (len(tokens) >= 2):
						field = tokens[1]

					if (len(tokens) == 3):
						fmt = tokens[2]
					
					vmf_factory = Factory(_logger=self.logger)
					vmf_message = vmf_factory.new_message(Params)
					vmf_elem = vmf_message.header.elements[field]

					if (isinstance(vmf_elem, Field)):
						vmf_value = vmf_elem.value
					elif (isinstance(vmf_elem, Group)):
						vmf_value = "n/a"
					else:
						raise Exception("Unknown type for element '{:s}'.".format(field))

					vmf_bits = vmf_elem.get_bit_array()
					output = vmf_bits

					if (fmt == "bin"):
						output = vmf_bits.bin
					if (fmt == "hex"):
						output = vmf_bits.hex

					self.logger.print_success("{}\t{}\t{}".format(field, vmf_value, output))
				elif (cmd.lower() == VmfShell.CMD_SEARCH):
					keyword = ' '.join(tokens[1:]).lower()
					for p in Params.parameters.keys():
						help = Params.parameters[p]['help']
						if (p.lower() == keyword or keyword in help.lower()):
							self.logger.print_success("{:s}: {:s}".format(p, help))
				elif (cmd.lower() == VmfShell.CMD_SAVE):
					if len(tokens) == 2:
						file = tokens[1]
						
						tmpdict = {}
						for param in Params.parameters.keys():
							value = Params.__dict__[param]
							tmpdict[param] = value
							
						with open(file, 'w') as f:
							json.dump(tmpdict, f)
							
						self.logger.print_success("Saved VMF message to {:s}.".format(file))
					else:
						self.logger.print_error("Specify a file to save the configuration to.")
				elif (cmd.lower() == "test"):
					if (len(tokens) == 2):
						vmf_params = tokens[1]
					else:
						vmf_params = '0x4023'
					s = BitStream(vmf_params)
					bstream = BitStream('0x4023')
					vmf_factory = Factory(_logger=self.logger)
					vmf_message = vmf_factory.read_message(bstream)					
				elif (cmd.lower() == VmfShell.CMD_LOAD):
					if len(tokens) == 2:
						file = tokens[1]
						with open(file, 'r') as f:
							param_dict = json.load(f)
							for (param, value) in param_dict.iteritems():
								Params.__dict__[param] = value
						self.logger.print_success("Loaded VMF message from {:s}.".format(file))
					else:
						self.logger.print_error("Specify a file to load the configuration from.")
						
				else:
					self.logger.print_error("Unknown command {:s}.".format(cmd))
			except Exception as e:
				self.logger.print_error("An exception as occured: {:s}".format(e.message))
				traceback.print_exc(file=sys.stdout)

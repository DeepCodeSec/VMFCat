# vmfcat
Simple Variable Message Format (VMF) message generation and manipulation via command-line. This program
requires the Enum and bitstring packages, which can be installed with:

```
pip install Enum
pip install bitstring
```

```
Copyright (C) 2015  Jonathan Racicot <jonathan.racicot@rmc.ca>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can use and modify this code for your own software as long as you 
    retain information about the original author in your code, including
    the name, email address and website:

    <author>Jonathan Racicot</author>
    <email>infectedpacket@gmail.com</email>
    <url>https://github.com/infectedpacket</url>

	
usage: vmfcat [options] -of OUTPUT

Allows crafting of Variable Message Format (VMF) messages.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit

Input/Output Options:
  Types of I/O supported.

  -of [OUTPUTFILE], --ofile [OUTPUTFILE]
                        File to output the results. STDOUT by default.

Application Header:
  Flags and Fields of the application header.

  --vmf-version {std47001,std47001B,std47001C,std47001D,std47001D_CHANGE}
                        Specifies the version of the application header to
                        use.
  --compress {UNIX,GZIP}
                        Specifies the data compression algorithm to use if
                        any.
  --header-size HEADERSIZE
                        Specifies the size of the header.

Originator Address Group:
  Fields of the originator address group.

  --orig-urn URN        Specify the URN of the originator of the message.
  --orig-unit STRING    Specify the name of the unit sending the message.

Recipient Address Group:
  Fields of the recipient address group.

  --rcpt-urns URNs [URNs ...]
                        List of 24-bit codes used to uniquely identify
                        friendly units.
  --rcpt-unitnames UNITNAMES [UNITNAMES ...]
                        List of variable size fields of character-coded
                        identifiers for friendly units.

Information Address Group:
  Fields of the information address group.

  --info-urns URNs [URNs ...]
                        Specify the URN of the reference message.
  --info-units UNITNAMES
                        Specify the name of the unit of the reference message.

Message Handling Group:
  Fields of the message handling group.

  --umf {link16,binary,vmf,nitfs,rdm,usmtf,doi103,xml-mtf,xml-vmf}
                        Indicates the format of the message contained in the
                        user data field.
  --msg-version VERSION
                        Represents the version of the message standard
                        contained in the user data field.
  --fad {netcon,infoex,firesupport,airops,int,land,navy,css,special,jtfops,airdef}
                        Identifies the functional area of a specific VMF
                        message using code words.
  --msg-number 1-127    Represents the number that identifies a specific VMF
                        message within a functional area.
  --msg-subtype 1-127   Represents a specific case within a VMF message, which
                        depends on the UMF, FAD and message number.
  --filename FILENAME   Indicates the name of the computer file or data block
                        contained in the User Data portion of the application
                        PDU.
  --msg-size SIZE       Indicates the size (in bytes) of the associated
                        message within the User Data field.
  --opind {op,ex,sim,test}
                        Indicates the operational function of the message.
  --retrans             Indicates whether a message is a retransmission.
  --msg-prec {reserved,critic,flashover,flash,imm,pri,routine}
                        Indicates relative precedence of a message.
  --class {unclass,conf,secret,topsecret} [{unclass,conf,secret,topsecret} ...]
                        Security classification of the message.
  --release COUNTRIES   Support the exchange of a list of up to 16 country
                        codes with which the message can be release.
  --orig-dtg YYYY-MM-DD HH:mm[:ss] [extension]
                        Contains the date and time in Zulu Time that the
                        message was prepared.
  --perish-dtg YYYY-MM-DD HH:mm[:ss]
                        Provides the latest time the message is still of
                        value.

Acknowledgement Request Group:
  Options to request acknowledgement and replies.

  --ack-machine         Indicates whether the originator of a machine requires
                        a machine acknowledgement for the message.
  --ack-op              Indicates whether the originator of the message
                        requires an acknowledgement for the message from the
                        recipient.
  --reply               Indicates whether the originator of the message
                        requires an operator reply to the message.

Response Data Options:
  Fields for the response data group.

  --ack-dtg YYYY-MM-DD HH:mm[:ss] [extension]
                        Provides the date and time of the original message
                        that is being acknowledged.
  --rc {mr,cantpro,oprack,wilco,havco,cantco,undef}
                        Codeword representing the Receipt/Compliance answer to
                        the acknowledgement request.
  --cantpro 1-32        Indicates the reason that a particular message cannot
                        be processed by a recipient or information address.
  --cantco {comm,ammo,pers,fuel,env,equip,tac,other}
                        Indicates the reason that a particular recipient
                        cannot comply with a particular message.
  --reply-amp REPLYAMP  Provide textual data an amplification of the
                        recipient's reply to a message.

Reference Message Data Group:
  Fields of the reference message data group.

  --ref-urn URN         Specify the URN of the reference message.
  --ref-unit STRING     Specify the name of the unit of the reference message.
  --ref-dtg YYYY-MM-DD HH:mm[:ss] [extension]
                        Date time group of the reference message.

Message Security Group:
  Fields of the message security group.

  --sec-param {auth,undef}
                        Indicate the identities of the parameters and
                        algorithms that enable security processing.
  --keymat-len KEYMATLEN
                        Defines the size in octets of the Keying Material ID
                        field.
  --keymat-id KEYMATID  Identifies the key which was used for encryption.
  --crypto-init-len CRYPTO_INIT_LEN
                        Defines the size, in 64-bit blocks, of the Crypto
                        Initialization field.
  --crypto-init CRYPTO_INIT
                        Sequence of bits used by the originator and recipient
                        to initialize the encryption/decryption process.
  --keytok-len KEYTOK_LEN
                        Defines the size, in 64-bit blocks, of the Key Token
                        field.
  --keytok KEYTOK       Contains information enabling each member of each
                        address group to decrypt the user data associated with
                        this message header.
  --autha-len LENGTH    Defines the size, in 64-bit blocks, of the
                        Authentification Data (A) field.
  --authb-len LENGTH    Defines the size, in 64-bit blocks, of the
                        Authentification Data (B) field.
  --autha AUTHA         Data created by the originator to provide both
                        connectionless integrity and data origin
                        authentication (A).
  --authb AUTHB         Data created by the originator to provide both
                        connectionless integrity and data origin
                        authentication (B).
  --ack-signed          Indicates whether the originator of a message requires
                        a signed response from the recipient.
  --pad-len LENGTH      Defines the size, in octets, of the message security
                        padding field.
  --padding PADDING     Necessary for a block encryption algorithm so the
                        content of the message is a multiple of the encryption
                        block length.
```

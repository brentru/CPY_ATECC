# The MIT License (MIT)
#
# Copyright (c) 2019 Brent Rubell for Adafruit Industries
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
`atecc_asn1`
================================================================================

ASN.1 Utilities for the Adafruit_ATECC Module.

* Author(s): Brent Rubell

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases
"""
import struct

# pylint: disable=invalid-name
def get_signature(signature, data):
    """Appends signature data to buffer."""
    # Signature algorithm
    data += b"\x30\x0a\x06\x08"
    # ECDSA with SHA256
    data += b"\x2a\x86\x48\xce\x3d\x04\x03\x02"
    r = signature[0]
    s = signature[32]
    r_len = 32
    s_len = 32

    while (r == 0x00 and r_len > 1):
        r += 1
        r_len -= 1

    while (s == 0x00 and s_len > 1):
        s += 1
        s_len -= 1

    if r & 0x80:
        r_len += 1

    if s & 0x80:
        s_len += 1

    data += b"\x03" + struct.pack("B", r_len + s_len + 7) + b"\x00"

    data += b"\x30" + struct.pack("B", r_len + s_len + 4)

    data += b"\x02" + struct.pack("B", r_len)
    if r & 0x80:
        data += b"\x00"
        r_len -= 1
    data += signature[0:r_len]

    if r & 0x80:
        r_len += 1

    data += b"\x02" + struct.pack("B", s_len)
    if s & 0x80:
        data += b"\x00"
        s_len -= 1

    data += signature[s_len:]

    if s & 0x80:
        s_len += 1

    return 21 + r_len + s_len


# pylint: disable=too-many-arguments
def get_issuer_or_subject(data, country, state_prov, locality,
                          org, org_unit, common):
    """Appends issuer or subject data, if they exist."""
    if country:
        get_name(country, 0x06, data)
    if state_prov:
        get_name(state_prov, 0x08, data)
    if locality:
        get_name(locality, 0x07, data)
    if org:
        get_name(org, 0x0a, data)
    if org_unit:
        get_name(org_unit, 0x0b, data)
    if common:
        get_name(common, 0x03, data)


def get_name(name, obj_type, data):
    """Appends ASN.1 string in form: set -> seq -> objid -> string
    :param str name: String to append to buffer.
    :param int obj_type: Object identifier type.
    :param bytearray data: Buffer to write to.
    """

    # ASN.1 SET
    data += b"\x31" + struct.pack("B", len(name) + 9)
    # ASN.1 SEQUENCE
    data += b"\x30" + struct.pack("B", len(name) + 7)
    # ASN.1 OBJECT IDENTIFIER
    data += b"\x06\x03\x55\x04" + struct.pack("B", obj_type)

    # ASN.1 PRINTABLE STRING
    data += b"\x13" + struct.pack("B", len(name))
    data.extend(name)
    return len(name) + 11

def get_version(data):
    """Sets X.509 version"""
    #  If no extensions are present, but a UniqueIdentifier
    # is present, the version SHOULD be 2 (value is 1) [4-1-2]
    data += b"\x02\x01\x00"

def get_sequence_header(length, data):
    """Appends sequence header to data."""
    data += b"\x30"
    if length > 255:
        data += b"\x82"
        data.append((length >> 8) & 0xff)
    elif length > 127:
        data += b"\x81"
    length_byte = struct.pack("B", (length) & 0xff)
    data += length_byte


def get_public_key(data, public_key):
    """Appends public key subject and object identifiers."""
    # Subject: Public Key
    data += b"\x30" + struct.pack("B", (0x59) & 0xff) + b"\x30\x13"
    # Object identifier: EC Public Key
    data += b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
    # Object identifier: PRIME 256 v1
    data += b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04"
    # Extend the buffer by the public key
    data += public_key

def get_signature_length(signature):
    """Get length of ECDSA signature.
    :param bytearray signature: Signed SHA256 hash.
    """
    r = signature[0]
    s = signature[32]
    r_len = 32
    s_len = 32

    while (r == 0x00 and r_len > 1):
        r += 1
        r_len -= 1

    if r & 0x80:
        r_len += 1

    while (s == 0x00 and s_len > 1):
        s += 1
        s_len -= 1

    if s & 0x80:
        s_len += 1
    return 21 + r_len + s_len

def get_sequence_header_length(seq_header_len):
    """Returns length of SEQUENCE header."""
    if seq_header_len > 255:
        return 4
    if seq_header_len > 127:
        return 3
    return 2

def issuer_or_subject_length(country, state_prov, city, org, org_unit, common):
    """Returns total length of provided certificate information."""
    tot_len = 0
    if country:
        tot_len += 11 + len(country)
    if state_prov:
        tot_len += 11 + len(state_prov)
    if city:
        tot_len += 11 + len(city)
    if org:
        tot_len += 11 + len(org)
    if org_unit:
        tot_len += 11 + len(org_unit)
    if common:
        tot_len += 11 + len(common)
    else:
        raise TypeError("Provided length must be > 0")
    return tot_len

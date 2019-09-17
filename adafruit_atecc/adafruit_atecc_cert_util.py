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
`adafruit_atecc_cert_util`
================================================================================

Certification Generation and Helper Utilities for the Adafruit_ATECC Module.

* Author(s): Brent Rubell

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases
"""
import struct
from micropython import const
from adafruit_binascii import b2a_base64
import adafruit_atecc.adafruit_atecc_asn1 as asn1

ASN1_INTEGER = const(0x02)
ASN1_BIT_STRING = const(0x03)
ASN1_NULL = const(0x05)
ASN1_OBJECT_IDENTIFIER = const(0x06)
ASN1_PRINTABLE_STRING = const(0x13)
ASN1_SEQUENCE = const(0x30)
ASN1_SET = const(0x31)

# Subject public key data length, fixed.
SUB_PUB_KEY_DATA_LEN = const(0x59)

class CSR:
    """Certificate Signing Request Builder.

    :param adafruit_atecc atecc: ATECC module.
    :param slot_num: ATECC module slot (from 0 to 4).
    :param bool private_key: Generate a new private key in selected slot?
    :param str country: 2-letter country code.
    :param str state_prov: State or Province name,
    :param str city: City name.
    :param str org: Organization name.
    :param str org_unit: Organizational unit name.

    """
    # pylint: disable=too-many-arguments
    def __init__(self, atecc, slot_num, private_key, country, state_prov,
                 city, org, org_unit):
        self._atecc = atecc
        self.private_key = private_key
        self._slot = slot_num
        self._country = country
        self._state_province = state_prov
        self._locality = city
        self._org = org
        self._org_unit = org_unit
        self._common = self._atecc.serial_number
        self._version_len = 3
        self._cert = None
        self._pub_key = None

    def generate_csr(self):
        """Generates and returns
        a certificate signing request.
        """
        self._csr_begin()
        csr = self._csr_end()
        return csr


    def _csr_begin(self):
        """Initializes CSR generation
        """
        assert 0 <= self._slot <= 4, "Provided slot must be between 0 and 4."
        self._pub_key = bytearray(64)
        if self.private_key:
            self._atecc.gen_key(self._pub_key, self._slot, self.private_key)
            return
        self._atecc.gen_key(self._pub_key, self._slot, self.private_key)


    def _csr_end(self):
        """Generates and returns
        a certificate signing request."""
        len_issuer_subject = asn1.issuer_or_subject_length(self._country, self._state_province,
                                                           self._locality, self._org, self._org_unit,
                                                           self._common)
        len_sub_header = asn1.seq_header_length(len_issuer_subject)
        len_pub_key = 91

        len_csr_info = self._version_len + len_issuer_subject
        len_csr_info += len_sub_header + len_pub_key + 2
        len_csr_info_header = asn1.seq_header_length(len_csr_info)

        # CSR Info Packet
        csr_info = bytearray()

        # Append CSR Info --> [0:2]
        asn1.get_sequence_header(len_csr_info, csr_info)

        # Append Version --> [3:5]
        asn1.get_version(csr_info)

        # Append Subject --> [6:7]
        asn1.get_sequence_header(len_issuer_subject, csr_info)

        # Append Issuer or Subject
        asn1.get_issuer_or_subject(csr_info, self._country, self._state_province,
                                   self._locality, self._org, self._org_unit, self._common)

        # Append Public Key
        asn1.get_public_key(csr_info, self._pub_key)

        # Termination bits
        csr_info += b"\xa0\x00"

        csr_info_sha_256 = bytearray(64)

        # Init. SHA-256 Calculation
        self._atecc.sha_start()

        for i in range(0, len_csr_info + len_csr_info_header, 64):
            chunk_len = (len_csr_info_header + len_csr_info) - i

            if chunk_len > 64:
                chunk_len = 64
            if chunk_len == 64:
                self._atecc.sha_update(csr_info[i:i+64])
            else:
                csr_info_sha_256 = self._atecc.sha_digest(csr_info[i:])

        # Sign the SHA256 Digest
        signature = bytearray(64)
        signature = self._atecc.ecdsa_sign(self._slot, csr_info_sha_256)

        # Calculate lengths of post-signature csr
        len_signature = asn1.get_signature_length(signature)
        len_csr = len_csr_info_header + len_csr_info + len_signature
        asn1.get_sequence_header_length(len_csr)

        # Final CSR
        csr = bytearray()

        asn1.get_sequence_header(len_csr, csr)

        # append csr_info
        csr += csr_info

        # append signature to csr
        asn1.get_signature(signature, csr)

        csr = b2a_base64(csr)
        return csr







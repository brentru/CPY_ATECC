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

Certificate Utilities for ATECCx08A

* Author(s): Brent Rubell

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases
"""
from micropython import const
import adafruit_atecc.adafruit_atecc_asn1 as asn1

ASN1_INTEGER           = const(0x02)
ASN1_BIT_STRING        = const(0x03)
ASN1_NULL              = const(0x05)
ASN1_OBJECT_IDENTIFIER = const(0x06)
ASN1_PRINTABLE_STRING  = const(0x13)
ASN1_SEQUENCE          = const(0x30)
ASN1_SET               = const(0x31)

class CSR:
    """Certificate signing request generation.

    :param adafruit_atecc atecc: ATECC module.
    :param slot_num: ATECC module slot (0 to 4).
    :param bool private_key: Generate a new private key in selected slot?
    :param str country: 2-letter country code.
    :param str state_prov: State or Province name,
    :param str city: City name.
    :param str org: Organization name.
    :param str org_unit: Organizational unit name.

    """
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

    def generate_csr(self):
        """Generates a new CSR.
        """
        self._csr_begin()
        csr = self._csr_end()

    def _csr_begin(self):
        """Initializes CSR generation
        """
        assert 0 <= self._slot <= 4, "Provided slot must be between 0 and 4."
        # Initialize ASN1 certificate info
        self._cert_info = asn1.cert(self._country, self._state_province, self._locality, 
                                      self._org, self._org_unit, self._common)
        self._pub_key = bytearray(64)
        if self.private_key:
            self._atecc.gen_key(self._pub_key, self._slot, self.private_key)
            return
        self._atecc.gen_key(self._pub_key, self._slot, self.private_key)


    def _csr_end(self):
      """Generates and returns CSR."""
      len_issuer_subject = self._cert_info.issuer_or_subject_length()
      len_sub_header = asn1.seq_header_length(len_issuer_subject)
      len_pub_key = 2 + 2 + 9 + 10 + 4 + 64
      
      len_csr_info = self._cert_info._version_len + len_issuer_subject + len_sub_header + len_pub_key + 2
      len_csr_info_header = asn1.seq_header_length(len_csr_info)

      print("Version Length:", self._cert_info._version_len)
      print("len_issuer_subject: ", len_issuer_subject)
      print("len_sub_header: ", len_sub_header)
      print("len_pub_key: ", len_pub_key)
      print("len_csr_info: ", len_csr_info)
      print("len_csr_info_header: ", len_csr_info_header)

      # CSR Info
      #csr_info = bytearray(len_csr_info + len_csr_info_header)
      csr_info = bytearray()

      # Append CSR Info
      self.get_sequence_header(len_csr_info, csr_info)
      csr_info.append(len_csr_info)

      # Append Version
      self.get_version(csr_info)
      csr_info.append(self._cert_info._version_len)

      # Append Subject
      self.get_sequence_header(len_sub_header, csr_info)
      csr_info.append(len_sub_header)
      print(csr_info)


    def get_sequence_header(self, length, data):
        data.append(ASN1_SEQUENCE)
        if length > 255:
          data.append(0x82)
          data.append((length >> 8) & 0xff)
        elif (length > 127):
          data.append(0x81)

        data.append((length >> 8) & 0xff)

    def get_version(self, data):
        """Sets X.509 version"""
        data[0] = ASN1_INTEGER
        #  If no extensions are present, but a UniqueIdentifier
        # is present, the version SHOULD be 2 (value is 1) [4-1-2]
        data[1] = 0x01
        data[2] = 0x00
    
    def get_name(self, name, type, data):
        """Appends ASN.1 string in form: set -> seq -> objid -> string
        :param str name: String to append to buffer.
        :param int type: Object identifier type.
        :param bytearray data: Buffer to write to.
        """
        data.append(ASN1_SET)
        data.append(len(name) + 9)
        
        data.append(ASN1_SEQUENCE)
        data.append(len(name) + 7)

        data.append(ASN1_OBJECT_IDENTIFIER)
        data.append(0x03)
        data.append(0x55)
        data.append(0x04)
        data.append(type)

        data.append(ASN1_PRINTABLE_STRING)
        data.append(len(name))
        data.append(name)


    def get_issuer_or_subject(self, data):
      # TODO: relies on impl. of get_name
      if len(self._country) > 0:
        data += self.get_name(self._country, 0x06, data)
      if len(self._state_province) > 0:
        data += self.get_name(self._state_province, 0x07, data)
      if len(self._locality) > 0:
        data += self.get_name(self._locality, 0x0a, data)
      if len(self._org) > 0:
        data += self.get_name(self._org, 0x0b, data)
      if len(self._org_unit) > 0:
        data += self.get_name(self._org_unit, 0x03, data)
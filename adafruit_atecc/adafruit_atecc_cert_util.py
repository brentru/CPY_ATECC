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

      csr_info = bytearray(len_csr_info + len_csr_info_header)
      csr_out = csr_info

      # CSR Info
      asn1.append_seq_header(len_csr_info, csr_out)

      # Version
      asn1.append_version(csr_out)
      csr_out.append(self._cert_info._version_len)
      return 1
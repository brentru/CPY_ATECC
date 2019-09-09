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

ASN.1 Utilities for Adafruit_ATECC Module.

* Author(s): Brent Rubell

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases
"""
from micropython import const

ASN1_INT = const(0x02)
ASN1_SEQ = const(0x30)

def seq_header_length(length):
  if length > 255:
    return 4
  elif length > 127:
    return 3
  else:
    return 2

def append_seq_header(length, out):
  out.append(ASN1_SEQ)
  if length > 255:
    out[0] += 0x82
    out[0] += (length >> 8) & 0xff
  elif length > 127:
    out.append(0x81)
  out.append((length) & 0xff)
  
  if length > 255:
    return 4
  elif length > 127:
    return 3
  else:
    return 2

def append_version(out):
  out.append(ASN1_INT)
  out.append(0x01)
  out.append(0x00)

class cert:
    def __init__(self, country, state_prov, city, org, org_unit, atecc_serial_num):
      self._country = country
      self._state_prov = state_prov
      self._city = city
      self._org = org
      self._org_unit = org_unit
      self._common = str(atecc_serial_num)
      self._version_len = 3

    def issuer_or_subject_length(self):
      tot_len = 0
      if len(self._country):
        tot_len+= (11+len(self._country))
      if len(self._state_prov):
        tot_len+= (11+len(self._state_prov))
      if len(self._city):
        tot_len+= (11+len(self._city))
      if len(self._org):
        tot_len+= (11+len(self._org))
      if len(self._org_unit):
        tot_len+= (11+len(self._org_unit))
      if len(self._common):
        tot_len+= (11+len(self._common))
      else:
        raise TypeError("Provided length must be > 0")
      return tot_len
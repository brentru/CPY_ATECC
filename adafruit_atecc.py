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
`adafruit_atecc`
================================================================================

CircuitPython module for the Microchip ATECCx08A Crryptographic Co-Processor


* Author(s): Brent Rubell

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases


 * Adafruit's Bus Device library: https://github.com/adafruit/Adafruit_CircuitPython_BusDevice
"""
import time
from micropython import const
import busio
from adafruit_bus_device.i2c_device import I2CDevice

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Circuitpython_CircuitPython_CircuitPython_CryptoAuth.git"

# Device Address
_REG_ATECC_ADDR = 0xC0
_REG_ATECC_DEVICE_ADDR = _ATECC_ADDR >> 1

# Version Registers
_REG_REVISION = 0x00 # device version register address
_ATECC_508_VER = 0x50
_ATECC_608_VER = 0x60

# Clock constants
_WAKE_CLK_FREQ = 100000 # slower clock speed 
_NORMAL_CLK_FREQ = 1000000 # regular clock speed
_TWLO_TIME = 6e-5 # TWlo, in microseconds


class ATECCx08A:
    """
    CircuitPython interface for ATECCx08A Crypto Co-Processor Devices.
    """
    def __init__(self, i2c_bus, address = _ATECC_DEVICE_ADDR):
        """Initializes an ATECC device.
        :param i2cdevice i2c_bus: I2C Bus.
        :param int address: Device address, defaults to _ATECC_DEVICE_ADDR.
        """
        # dont create an i2cdevice yet, we need to wakeup
        print('waking the i2c device...')
        self.i2c_bus = i2c_bus
        is_found = self._wake()
        if is_found == -1:
            raise TypeError('ATECCx08 not found - please check your wiring!')
        print('device found and awake!')


    def _wake(self):
        """Wakes up THE ATECC608A from sleep or idle modes.
        Returns 1 if device woke up from sleep/idle mode. 
        """
        while not self.i2c_bus.try_lock():
            pass
        print('bus unlocked!')
        try:
            self.i2c_bus.writeto(_ATECC_ADDR, bytes([b'\x00\x00']), stop=False)
        except:
            pass # allow writing to ATECC_ADDR
        # wait for TWLO millis before attempting an i2c scan
        time.sleep(_TWLO_TIME)
        # check for an i2c device
        data = self.i2c_bus.scan()
        if data[0] != 96:
            return -1
        return 1

    # pylint: disable=no-member
    # Reconsider pylint: disable when this can be tested
    def _read_into(self, address, buf, length=None):
        # Read a number of bytes from the specified address into the provided
        # buffer.  If length is not specified (the default) the entire buffer
        # will be filled.
        if length is None:
            length = len(buf)
        with self._device as device:
            self._BUFFER[0] = address & 0x7F  # Strip out top bit to set 0
                                              # value (read).
            device.write(self._BUFFER, end=1)
            device.readinto(buf, end=length)

    def _read_u8(self, address):
        # Read a single byte from the provided address and return it.
        self._read_into(address, self._BUFFER, length=1)
        return self._BUFFER[0]

    def _write_from(self, address, buf, length=None):
        # Write a number of bytes to the provided address and taken from the
        # provided buffer.  If no length is specified (the default) the entire
        # buffer is written.
        if length is None:
            length = len(buf)
        with self._device as device:
            self._BUFFER[0] = (address | 0x80) & 0xFF  # Set top bit to 1 to
                                                       # indicate a write.
            device.write(self._BUFFER, end=1)
            device.write(buf, end=length)

    def _write_u8(self, address, val):
        # Write a byte register to the chip.  Specify the 7-bit address and the
        # 8-bit value to write to that address.
        with self._device as device:
            self._BUFFER[0] = (address | 0x80) & 0xFF  # Set top bit to 1 to
                                                       # indicate a write.
            self._BUFFER[1] = val & 0xFF
            device.write(self._BUFFER, end=2)

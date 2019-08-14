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
import board
from micropython import const
import busio
from adafruit_bus_device.i2c_device import I2CDevice

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Circuitpython_CircuitPython_CircuitPython_CryptoAuth.git"

# Device Address
_REG_ATECC_ADDR = const(0xC0)
_REG_ATECC_DEVICE_ADDR = _REG_ATECC_ADDR >> 1

# Version Registers
_REG_REVISION = const(0x30) # device version register address
_ATECC_508_VER = const(0x50)
_ATECC_608_VER = const(0x60)

# Clock constants
_NORMAL_CLK_FREQ = 1000000 # regular clock speed
_WAKE_CLK_FREQ = 100000 # stretched clock for wakeup
_TWLO_TIME = 6e-5 # TWlo, in microseconds

# Status/Error Codes (9-3)
STATUS_SUCCESS = const(0x00)
STATUS_WAKE = const(0x11)
ERROR_CHECKMAC = const(0x01)
ERROR_PARSE = const(0x03)
ERROR_ECC = const(0x05)
ERROR_EXEC = const(0x0F)
ERROR_WATCHDOG = const(0xEE)
ERROR_CRC = const(0xFF)


# Constants
_RX_RETRIES = const(20)

class ATECCx08A:
    _BUFFER = bytearray(2)
    """
    CircuitPython interface for ATECCx08A Crypto Co-Processor Devices.
    """
    def __init__(self, i2c_bus, address = _REG_ATECC_DEVICE_ADDR):
        """Initializes an ATECC device.
        :param busio i2c_bus: I2C Bus object.
        :param int address: Device address, defaults to _ATECC_DEVICE_ADDR.
        """
        self._i2c_bus = i2c_bus
        self._i2c_device = None
        self.wakeup()

    def wakeup(self):
        """Wakes up THE ATECC608A from sleep or idle modes.
        Returns True if device woke up from sleep/idle mode.
        """
        while not self._i2c_bus.try_lock():
            pass
        #print('i2c bus unlocked!')
        zero_bits = bytearray(2)
        try:
            self._i2c_bus.writeto(0x0, zero_bits)
        except OSError:
            pass    # this may fail, that's ok - its just to wake up the chip!
        time.sleep(_TWLO_TIME)
        data = self._i2c_bus.scan()         # check for an i2c device
        print('I2C Addresses: ', [hex(i) for i in data])
        if data[0] != 96:
            raise TypeError('ATECCx08 not found - please check your wiring!')
        self._i2c_bus.unlock()

        if not self._i2c_device:
            self._i2c_device = I2CDevice(self._i2c_bus, _REG_ATECC_DEVICE_ADDR, debug=False)

        # check if we are ready to read from
        r = bytearray(1)
        self._get_response(r)
        if r[0] != 0x11:
            raise RuntimeError("Failed to wakeup")



    def rev_number(self):
        """Returns the ATECC608As revision number
        """
        self._send_command(0x30, 0x00)


    def _get_response(self, buf, length=None, retries=20):
        if length is None:
            length = len(buf)
        response = bytearray(length+3)   # 1 byte header, 2 bytes CRC, len bytes data
        with self._i2c_device as i2c:
            for _ in range(retries):
                try:
                    i2c.readinto(response)
                    break
                except OSError:
                    pass
            else:
                raise RuntimeError("Failed to read data from chip")
        print([hex(i) for i in response])
        crc = response[-2] | (response[-1] << 8)
        crc2 = self.at_crc(response[0:2])
        if crc != crc2:
            raise RuntimeError("CRC check failure")
        for i in range(length):
            buf[i] = response[i+1]

    def _send_command(self, opcode, param_1, param_2=0x00, data = ''):
        """Sends a security command packet over i2c.
        :param byte opcode: The command Opcode
        :param byte param_1: The first parameter
        :param byte param_2: The second parameter, can be two bytes.
        :param byte param_3 data: Optional remaining input data.
        """
        # Show Args in REPL
        print('Opcode: ', opcode)
        print('Param_1: ', param_1)
        print('Param_2: ', param_2)
        print('Data: ', data)

        # assembling command packet
        command_packet = bytearray(8+len(data))
        print('Command Size: ', len(command_packet))
        # word address
        command_packet[0] = 0x03
        # i/o group: count
        command_packet[1] = len(command_packet) - 1 # count
        # security command packets
        command_packet[2] = opcode
        command_packet[3] = param_1
        command_packet[4] = param_2
        print(command_packet)
        for i in range(0, len(command_packet)):
            print('command_packet[{0}]: {1}'.format(i, command_packet[i]))
        # Checksum, CRC16 verification
        crc = self.at_crc(command_packet, len(command_packet) - 2)
        print('Calculated CRC: ', crc)


        # WRITE to ATECC608A
        with self._device:
            self._device.write(command_packet)
        # small sleep
        time.sleep(2e-6)
        # RETURNING from ATECC608A
        # Command completion polling (6.2.2), (6.5)
        # the size of the group is determined by the command
        res_size = 3
        retries = _RX_RETRIES
        while retries > 0:
          with self._device:
            self._device.readinto(self._BUFFER)
            buff_size = len(self._BUFFER)
            print(buff_size)
            retries=-1
        print(self._BUFFER)
        print('returned!')

    def at_crc(self, data, length=None):
        if length is None:
            length = len(data)
        if not data or not length:
            return 0
        polynom = 0x8005
        crc = 0x0
        for i in range(length):
            b = data[i]
            for shift in range(8):
                data_bit = int(b & (1<<shift))
                crc_bit = (crc >> 15) & 0x1
                crc <<= 1
                if data_bit != crc_bit:
                    crc ^= polynom
        return crc & 0xFFFF

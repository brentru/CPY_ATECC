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
_REG_ATECC_ADDR = 0xC0
_REG_ATECC_DEVICE_ADDR = _REG_ATECC_ADDR >> 1

# Version Registers
_REG_REVISION = 0x30 # device version register address
_ATECC_508_VER = 0x50
_ATECC_608_VER = 0x60

# Clock constants
_NORMAL_CLK_FREQ = 1000000 # regular clock speed
_TWLO_TIME = 6e-5 # TWlo, in microseconds

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
        self.i2c_bus = i2c_bus
        is_found = self._wake(self.i2c_bus)
        if is_found == -1:
            raise TypeError('ATECCx08 not found - please check your wiring!')
        print('device found and awake!')
        self._device = I2CDevice(self.i2c_bus, _REG_ATECC_DEVICE_ADDR, debug=True)
        print('I2CDevice initd!')
        # check revision number
        data = self._send_command(0x30, 0x00)
        print(data)


    def _wake(self, i2c_bus):
        """Wakes up THE ATECC608A from sleep or idle modes.
        Returns 1 if device woke up from sleep/idle mode. 
        :param busio i2c_bus: I2C bus connected to the ATECCx08A.
        """
        while not i2c_bus.try_lock():
            pass
        print('bus unlocked!')
        try:
            i2c_bus.writeto(_REG_ATECC_ADDR, bytes([b'\x00\x00']), stop=False)
        except:
            pass # allow writes to ATECC_ADDR, ignore error
        time.sleep(_TWLO_TIME)
        # check for an i2c device
        data = i2c_bus.scan()
        if data[0] != 96:
            return -1
        print('deiniting bus...')
        self.i2c_bus.deinit()
        self.i2c_bus = busio.I2C(board.SCL, board.SDA, frequency = _NORMAL_CLK_FREQ)
        print('new i2c bus initd')
        return 1

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
        #print(bytes(crc))
        # command_packet[6] = crc

    def at_crc(self, data, length):
        if (data == 0 or length == 0):
            return 0
        polynom = 0x8005
        crc = 0xffff
        for i in range(length):
            d = data[i]
            for b in range(8):
                data_bit = 1 if d & 1 << b else 0
                crc_bit = crc >> 15 & 0xff
                crc = crc << 1 & 0xffff
                if data_bit != crc_bit:
                    crc = crc ^ polynom & 0xffff
        data[length] = crc & 0x00ff
        data[length+1] = crc >> 8 & 0xff
        return crc

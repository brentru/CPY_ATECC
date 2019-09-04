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

 * Adafruit's Bus Device library:
  https://github.com/adafruit/Adafruit_CircuitPython_BusDevice
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
# device version register address
_REG_REVISION = const(0x30)
_ATECC_508_VER = const(0x50)
_ATECC_608_VER = const(0x60)

# Clock constants
_NORMAL_CLK_FREQ = 1000000 # regular clock speed
_WAKE_CLK_FREQ = 100000    # slower clock speed
_TWLO_TIME = 6e-5          # TWlo, in microseconds

# Constants
_RX_RETRIES = const(20)

# Command Opcodes (9-1-3)
OP_COUNTER = const(0x24)
OP_INFO = const(0x30)
OP_NONCE = const(0x16)
OP_RANDOM = const(0x1B)
OP_SHA = const(0x47)

# Status/Error Codes (9-3)
STATUS_ERROR_CODES =   {const(0x00), "Command executed successfully.",
                        const(0x01), "CheckMac/Verify sent, input does not match expected value.",
                        const(0x03), "Parse Error - Illegal parameters provided.",
                        const(0x05), "Computation error occured during ECC processing. Please retry.",
                        const(0x0F), "Execution Error - Command could not be executed by the device in its current state",
                        const(0x11), "ATECC RX'd Wake token.",
                        const(0xEE), "Watchdog About to Expire.",
                        const(0xFF), "CRC or Communication Error"}


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
        self._I2CBUF = bytearray(12)
        self._i2c_bus = i2c_bus
        self._i2c_device = None
        self.wakeup()
        if not self._i2c_device:
            self._i2c_device = I2CDevice(self._i2c_bus, _REG_ATECC_DEVICE_ADDR)
        self.idle()
        if (self.version() >> 8) not in (_ATECC_508_VER, _ATECC_608_VER):
            raise RuntimeError("Failed to find 608 or 508 chip. Please check your wiring.")

    def wakeup(self):
        """Wakes up THE ATECC608A from sleep or idle modes.
        Returns True if device woke up from sleep/idle mode.
        """
        while not self._i2c_bus.try_lock():
            pass
        # check if it exists, first
        if 0x60 in self._i2c_bus.scan():
            self._i2c_bus.unlock()
            return

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

    def idle(self):
        self._I2CBUF[0] = 0x2
        with self._i2c_device as i2c:
            i2c.write(self._I2CBUF, end=1)
        time.sleep(0.001)

    def sleep(self):
        self._I2CBUF[0] = 0x1
        with self._i2c_device as i2c:
            i2c.write(self._I2CBUF, end=1)
        time.sleep(0.001)

    def version(self):
        """Returns the ATECC608As revision number
        """
        self.wakeup()
        self.idle()
        vers = bytearray(4)
        vers = self.info(0x00)
        return (vers[2] << 8) | vers[3]

    def locked(self):
        config = bytearray(4)
        self._read(0, 0x15, config)
        return config[2] == 0x0 and config[3] == 0x00


    def info(self, mode):
        """Access to statatic or dynamic information based on the
        value of the mode.
        :param int mode: Mode encoding, see Table 9-26.
        """
        self.wakeup()
        self.idle()
        self._send_command(OP_INFO, mode)
        info_out = bytearray(4)
        self._get_response(info_out)
        return info_out


    def nonce(self, data, mode=0, zero=0x0000):
        """Generates a nonce by combining internally generated random number
        with an input value.
        :param bytearray data: Input value from system or external.
        :param int mode: Controls the internal RNG and seed mechanism.
        :param int zero: Param2, see Table 9-35.
        """
        self.wakeup()
        self.idle()
        if mode == 0x00 or mode == 0x01:
            if zero == 0x00:
                assert len(data) == 20, "Data value must be 20 bytes long."
            self._send_command(OP_NONCE, mode, zero, data)
            # RNG output
            calculated_nonce = bytearray(32)
        elif mode == 0x03:
            # Operating in Nonce pass-through mode
            assert len(data) == 32, "Data value must be 32 bytes long."
            self._send_command(OP_NONCE, mode, zero, data)
            # Single byte with zero if mode is 0x03
            calculated_nonce = bytearray(1)
        else:
            raise RuntimeError("Invalid mode specified!")
        time.sleep(0.029)
        self._get_response(calculated_nonce)
        if mode == 0x03:
            # Successful pass-thru nonce should return "\x00"
            assert calculated_nonce[0] == 0x00, "Incorrectly calculated nonce in pass-thru mode"
        return calculated_nonce



    def counter(self, counter=0, increment_counter=True):
        """Reads the binary count value from one of the two monotonic
        counters located on the device within the configuration zone.
        The maximum value that the counter may have is 2,097,151.
        :param int counter: Device's counter to increment.
        :param bool increment_counter: Increments the value of the counter specified.
        """
        count = bytearray(4)
        self.wakeup()
        self.idle()
        counter= 0x00
        if counter == 1:
            counter = 0x01
        if increment_counter:
            self._send_command(OP_COUNTER, 0x01, counter)
        else:
            self._send_command(OP_COUNTER, 0x00, counter)
        self._get_response(count)
        self.version()
        return count


    def random(self):
        """Generates a random number for use by the system.
        """
        self.wakeup()
        self.idle()
        self._send_command(OP_RANDOM, 0x00, 0x0000)
        time.sleep(0.23)
        resp = bytearray(32)
        self._get_response(resp)
        self.idle()
        return resp

    def sha(self):
        self.wakeup()
        self.idle()
        # Start, length is zero
        self._send_command(0x47, 0x00, 0x00)
        # Update, with message
        message_bytes = bytearray(63)
        message_bytes[60] = 0x02
        self._send_command(0x47, 0b00000001, 0x40, message_bytes)
        self._send_command(0x47, 0x00)
        resp = bytearray(32)
        time.sleep(0.23)
        self._get_response(resp)


    def _read(self, zone, address, buffer):
        self.wakeup()
        if len(buffer) not in (4, 32):
            raise RuntimeError("Only 4 and 32 byte reads supported")
        if len(buffer) == 32:
            zone |= 0x80
        self._send_command(2, zone, address)
        time.sleep(0.005)
        self._get_response(buffer)
        time.sleep(0.001)
        self.idle()

    def _send_command(self, opcode, param_1, param_2=0x00, data = ''):
        """Sends a security command packet over i2c.
        :param byte opcode: The command Opcode
        :param byte param_1: The first parameter
        :param byte param_2: The second parameter, can be two bytes.
        :param byte param_3 data: Optional remaining input data.
        """
        # assembling command packet
        command_packet = bytearray(8+len(data))
        # word address
        command_packet[0] = 0x03
        # i/o group: count
        command_packet[1] = len(command_packet) - 1 # count
        # security command packets
        command_packet[2] = opcode
        command_packet[3] = param_1
        command_packet[4] = param_2 & 0xFF
        command_packet[5] = param_2 >> 8
        for i,c in enumerate(data):
            command_packet[6+i] = c
        #print("Command Packet Sz: ", len(command_packet))
        #print("\tSending:", [hex(i) for i in command_packet])
        # Checksum, CRC16 verification
        crc = self.at_crc(command_packet[1:-2])
        #print('Calculated CRC: ', hex(crc))
        command_packet[-1] = crc >> 8
        command_packet[-2] = crc & 0xFF
        #for i in range(0, len(command_packet)):
        #    print('command_packet[{0}]: {1}'.format(i, hex(command_packet[i])))

        self.wakeup()
        with self._i2c_device as i2c:
            i2c.write(command_packet)
        # small sleep
        time.sleep(0.001)


    def _get_response(self, buf, length=None, retries=20):
        self.wakeup()
        if length is None:
            length = len(buf)
        response = bytearray(length+3)   # 1 byte header, 2 bytes CRC, len bytes data
        with self._i2c_device as i2c:
            for _ in range(retries):
                try:
                    i2c.readinto(response)
                    #print(response)
                    break
                except OSError:
                    pass
            else:
                raise RuntimeError("Failed to read data from chip")
        #print("\tReceived: ", [hex(i) for i in response])
        crc = response[-2] | (response[-1] << 8)
        crc2 = self.at_crc(response[0:-2])
        #print(hex(crc2))
        if crc != crc2:
            raise RuntimeError(STATUS_ERROR_CODES[0xFF])
        for i in range(length):
            buf[i] = response[i+1]
        return response[1]


    def at_crc(self, data, length=None):
        if length is None:
            length = len(data)
        if not data or not length:
            return 0
        polynom = 0x8005
        crc = 0x0
        for b in data:
            #print("\tbyte 0x%02x crc 0x%04x" % (b, crc))
            for shift in range(8):
                data_bit = 0
                if b & (1<<shift):
                    data_bit = 1
                crc_bit = (crc >> 15) & 0x1
                crc <<= 1
                crc &= 0xFFFF
                if data_bit != crc_bit:
                    crc ^= polynom
                    crc &= 0xFFFF
        #print("\tfinal CRC", hex(crc))
        return crc & 0xFFFF
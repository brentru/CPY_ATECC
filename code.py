# testing adafruit atecc module
import board
import adafruit_atecc
import busio
import time


_WAKE_CLK_FREQ = 100000 # slower clock speed 	
i2c = busio.I2C(board.SCL, board.SDA, frequency=_WAKE_CLK_FREQ)

atecc = adafruit_atecc.ATECCx08A(i2c)
print("Found ATECC!")
r = bytearray(1)

print("Waking up chip")

atecc.wakeup()

atecc.idle()
v = atecc.version()

print("Found version 0x%04x" % v)


print("Locked?", atecc.locked())

print("Counter: ", atecc.counter(0))

print(atecc.nonce())
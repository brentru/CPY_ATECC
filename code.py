import board
import adafruit_atecc
import busio
import time

_WAKE_CLK_FREQ = 100000 # slower clock speed 	
i2c = busio.I2C(board.SCL, board.SDA, frequency=_WAKE_CLK_FREQ)

try:
    atecc = adafruit_atecc.ATECCx08A(i2c)
except:
    raise TypeError("Atecc not found")

print("Waking up ATECC...")
atecc.wakeup()
atecc.idle()
v = atecc.version()
print("Version: 0x%04x" % v)
print("Locked?", atecc.locked())
print("Monotonic Counter #0: ", atecc.counter(0))
print("Monotonic Counter #1: ", atecc.counter(1))

# atecc.sha()

# Generate random #
print(atecc.random())

# Generate Nonce based on provided input, nonce_input
#nonce_input = bytearray(20)
#nonce_input[0] = 0x05
#print(atecc.nonce(input=nonce_input))
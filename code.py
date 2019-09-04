import board
import adafruit_atecc
import busio
import time

# Initialize the i2c bus
i2c = busio.I2C(board.SCL, board.SDA,
                frequency=adafruit_atecc._WAKE_CLK_FREQ)

# Initialize an atecc object
atecc = adafruit_atecc.ATECCx08A(i2c)

# Generate random number
print("Generating Random Number...")
random_num = atecc.random()
print("Random Number[0]: ", random_num[0])

# Generate a nonce
print("Generating Nonce...")
input_data = bytearray(20)
input_data[3] = 0x03
nonce_value = atecc.nonce(input_data)
print("Nonce[0]: ", nonce_value[0])
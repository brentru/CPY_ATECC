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
random_num = atecc.random()
print("Random Number[0]: ", random_num[0])
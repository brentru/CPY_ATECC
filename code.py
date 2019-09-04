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

# Generate a nonce, mode is 1
input_data = bytearray(20)
input_data[1] = 0x01
print("Generating Nonce using input_data: ", input_data)
nonce_value = atecc.nonce(input_data)
print("Nonce[0]: ", nonce_value[0])

# Generate a nonce in passthru mode
input_data = bytearray(32)
input_data[1] = 0x01
print("Generating Nonce using input_data: ", input_data)
nonce_value = atecc.nonce(input_data, 0x03)

print("Generating SHA256 digest...")
calculated_sha = bytearray(64)
atecc.sha_start()
atecc.sha_update(b"hello")
calculated_sha = atecc.sha_digest()
print("Calculated SHA256 Digest: ", calculated_sha)
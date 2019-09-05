import board
import adafruit_atecc
import busio
import time
import adafruit_ssd1306

# -- Enter your configuration below -- #

# Lock the ATECC module when the code is run?
LOCK_ATECC = True
MY_COUNTRY = "US"
MY_STATE = "New York"
MY_CITY = "New York"
MY_ORG = "Adafruit Industries"
MY_SECTION = "Engineering"
ATECC_SLOT = 0
GENERATE_PRIVATE_KEY = True
# -- END Configuration, code below -- #


# Initialize the i2c bus
i2c = busio.I2C(board.SCL, board.SDA,
                frequency=adafruit_atecc._WAKE_CLK_FREQ)

# Initialize an atecc object
atecc = adafruit_atecc.ATECC(i2c)

print("Serial Number: ", atecc.serial_number)

if not atecc.locked:
    if not LOCK_ATECC:
        raise RuntimeError("The ATECC is not locked, set LOCK_ATECC to True in your code to unlock it.")
    print("Locking ATECC module...")
    # lock configuration zone
    atecc.lock(lock_config=True)
    # lock data and otp zones
    atecc.lock(lock_data_otp=True)

#TODO: Write default TLS config.



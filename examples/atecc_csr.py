import board
import adafruit_atecc
import atecc_asn1
import busio
import time
import adafruit_ssd1306

# -- Enter your configuration below -- #

# Lock the ATECC module when the code is run?
LOCK_ATECC = True
# 2-letter country code
MY_COUNTRY = "US"
# State or Province Name
MY_STATE = "New York"
# City Name
MY_CITY = "New York"
# Organization Name
MY_ORG = "Adafruit Industries"
# Organizational Unit Name
MY_SECTION = "Engineering"
# Which ATECC slot (0-4) to use
ATECC_SLOT = 0
# Generate new private key, or use existing key
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
    print("Writing default configuration to the device...")
    atecc.write_config(adafruit_atecc.CFG_TLS)
    print("Locking ATECC module...")
    # lock configuration zone
    #atecc.lock(lock_config=True)
    # lock data and otp zones
    #atecc.lock(lock_data_otp=True)
    print("ATECC locked!")

# CSR Initialization and Generation
atecc.csr_begin(ATECC_SLOT, GENERATE_PRIVATE_KEY, MY_COUNTRY, MY_STATE, MY_CITY, MY_ORG, MY_SECTION)
atecc.csr_end()
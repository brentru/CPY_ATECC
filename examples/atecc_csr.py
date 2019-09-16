import board
import busio
import time
import adafruit_ssd1306
from adafruit_atecc.adafruit_atecc import ATECC, _WAKE_CLK_FREQ

import adafruit_atecc.adafruit_atecc_cert_util as cert_utils

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
MY_ORG = "Adafruit"
# Organizational Unit Name
MY_SECTION = "Crypto"
# Which ATECC slot (0-4) to use
ATECC_SLOT = 1
# Generate new private key, or use existing key
GENERATE_PRIVATE_KEY = False

# -- END Configuration, code below -- #

# Initialize the i2c bus
i2c = busio.I2C(board.SCL, board.SDA,
                frequency=_WAKE_CLK_FREQ)

# Initialize an atecc object
atecc = ATECC(i2c, debug=False)

print("ATECC Serial Number: ", atecc.serial_number)

if not atecc.locked:
    if not LOCK_ATECC:
        raise RuntimeError("The ATECC is not locked, set LOCK_ATECC to True in your code to unlock it.")
    print("Writing default configuration to the device...")
    atecc.write_config(adafruit_atecc.CFG_TLS)
    print("Wrote configuration, locking ATECC module...")
    # lock configuration zone
    atecc.lock(lock_config=True)
    # lock data and otp zones
    atecc.lock(lock_data_otp=True)
    print("ATECC locked!")

# Initialize a certificate signing request with provided info
csr = cert_utils.CSR(atecc, ATECC_SLOT, GENERATE_PRIVATE_KEY, MY_COUNTRY, MY_STATE,
                MY_CITY, MY_ORG, MY_SECTION)

# Generate CSR
my_csr = csr.generate_csr()

print("-----BEGIN CERTIFICATE REQUEST-----\n")
print(my_csr.decode('utf-8'))
print("-----END CERTIFICATE REQUEST-----")

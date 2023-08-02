import time
from time import ctime
import ntplib

# adding this offset to the current time will give us the NTP server current time
ntp_offset = None 

# add requirements file: pip install ntplib
def get_ntp_time(ntp_server='time.google.com'):
    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_server)
        # Get the NTP timestamp as a long long (8 bytes) integer (Same as in Android)
        ntp_time = int(response.tx_time * 1000)  # Convert to milliseconds and then to an integer
        return ntp_time
    except ntplib.NTPException as e:
        print(f"Failed to fetch time from NTP server: {e}")
        return None

def get_ntp_offset():


def verify_timestamp_freshness(timestamp, signature, certificate):
    ntp_current_time = 
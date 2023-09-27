import time
import ntplib
from debug_colors import *

# adding this offset to the current time will give us the NTP server current time
NTP_OFFSET = None
TIMESTAMP_FRESHNESS_TOLERANCE_MSEC = 2500

def get_ntp_timestamp(ntp_server='time.google.com'):
    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_server)
        # Get the NTP timestamp as a long (8 bytes) integer (Same as in Android)
        ntp_time = int(response.tx_time * 1000)  # Convert to milliseconds and then to integer
        return ntp_time
    except ntplib.NTPException as e:
        print(f"Failed to fetch time from NTP server: {e}")
        return None

def get_local_timestamp():
    return int(time.time()*1000)

# This function effectively brings us in sync with the NTP server since NTP_OFFSET is updated.
def set_ntp_offset():
    global NTP_OFFSET
    NTP_OFFSET = get_ntp_timestamp() - get_local_timestamp()

# alias of set_ntp_offset
def ntp_sync():
    set_ntp_offset()

def verify_timestamp_freshness(timestamp):
    sync_delay = 0
    if NTP_OFFSET == None:
        print("Will perform sync and consider the delay for it. Ensure you sync with NTP before starting your TCP server!")
        before_sync_timestamp = get_local_timestamp()
        ntp_sync()
        after_sync_timestamp = get_local_timestamp()
        sync_delay = (after_sync_timestamp - before_sync_timestamp)
    # We tolerate at most 2.5 seconds delay (2500 msec)
    if (get_local_timestamp() + NTP_OFFSET) - (timestamp+sync_delay) > TIMESTAMP_FRESHNESS_TOLERANCE_MSEC:
        return False
    return True

def debug_fun():

    global NTP_OFFSET
    ntp_timestamp = get_ntp_timestamp()
    local_timestamp = get_local_timestamp()
    print(f"The NTP timestamp is {ntp_timestamp}")
    print(f"The local timestamp is {local_timestamp}")

    set_ntp_offset()
    print(f"The offset is {NTP_OFFSET}")
    
    print(f"Now checking that the freshness check is correct!")

    timestamp_old = get_local_timestamp() + NTP_OFFSET
    time.sleep(2.6)
    NTP_OFFSET = None
    if verify_timestamp_freshness(timestamp_old):
        print(f"{RED}Expired timestamp passed as fresh!{RESET}")
        return
    else:
        print(f"{GREEN}Expired timestamp was identified correctly!{RESET}")

    timestamp_new_1 = get_local_timestamp() + NTP_OFFSET
    time.sleep(1)
    NTP_OFFSET = None
    if verify_timestamp_freshness(timestamp_new_1):
        print(f"{GREEN}1 sec Fresh timestamp passed as fresh!{RESET}")
    else:
        print(f"{RED}1 sec Fresh timestamp was identified as expired!{RESET}")
        return

    timestamp_new_2 = get_local_timestamp() + NTP_OFFSET
    time.sleep(1)
    NTP_OFFSET = None
    if verify_timestamp_freshness(timestamp_new_2):
        print(f"{GREEN}2 sec Fresh timestamp passed as fresh!{RESET}")
    else:
        print(f"{RED}2 sec Fresh timestamp was identified as expired!{RESET}")
        return
    print(f"{GREEN}All timestamp verifications were correct!{RESET}")

if __name__ == "__main__":
    debug_fun()

import struct
info_reply = b'ONLINE'
unpacked = struct.unpack('6s', info_reply)
print(f"{unpacked}")

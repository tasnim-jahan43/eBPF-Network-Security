import socket
import ctypes
import time
import sys

libc = ctypes.CDLL("libc.so.6")
libc.prctl(15, b"myprocess", 0, 0, 0)

port = int(sys.argv[1])

print("Process name: myprocess")
print("Waiting for eBPF attachment...")

time.sleep(60)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", port))

    print(f"SUCCESS: Connection to port {port} allowed!")
    s.close()

except Exception as e:
    print(f"BLOCKED: Connection to port {port} failed!")
    print(e)

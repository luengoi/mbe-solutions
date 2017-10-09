#!/usr/bin/python
# coding: utf-8

'''
Crack for lab1B exercise
'''

import os


# The overall behaviour of this program is as follows:
#   -Seeds the random number generator used by function rand with
#   the current time.
#   -Our input (parsed as an integer) is passed along 0x1337d00d to test()
#   -The result of 0x1337d00d - input is compared to 0x15. If greater, jumps
#   to the default case.
#   -If the result is less or equal, the execution flows to a jumping table.
#   -A call to decrypt() is then performed and the program attempts to decrypt
#   a string with input - 0x1337d00d as the key

# We will break through the most important points as we write our crack

# Basically our objective is going to be finding a valid key.
# In order to do this we have to know how the decryption works:
#   -The algorithm iterates over the encrypted string and performs an xor
#   operation between a character and the key.
#   -Then compares the resulting string to "Congratulations!"

# Since this is a simple xor operation (and xor is an involutory function)
# we can xor the first character of the encrypted string and the first
# character of the decrypted string to get the key

key = ord('C') ^ 0x51

# key = 0x1337d00d - input -> input = 0x1337d00d - key
inp = 0x1337d00d - key

# Now that we have our input, we can crack the file
os.system('(python -c \'print %d\'; echo "cat /home/lab1A/.pass > ' % inp +
          '/tmp/lab1A.pass";) | /levels/lab01/lab1B')
print '\n[+] level lab1B cracked, password saved in /tmp/lab1A.pass'

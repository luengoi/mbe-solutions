These challenges can be solved in many different ways, here are some of the alternatives I've found:

## lab8C
This program allocates a buffer where the contents of the two files are copied one after the other. Using a normal stream  
only allow us to read up to 254 bytes, this is because the contents of the next file are being copied at the 256th byte  
of the previously allocated buffer (so there will be at least one NULL byte in between). We can circumvent this using a  
non seekable buffer, this will bypass the limitation of 254 characters since fseek() it will return -1 (0xffffffff) which  
is, in fact, less than 254. Then, we will be able to write 255 bytes to the buffer to get rid of that NULL and printing
the contents of the second file (conviniently the file containing the flag). This method is trickier to automate btw...

## lab8B
There is an obvious way of solving this level, this is using the secret function. Since that didn't supposed much of a  
challenge I've decided to take that extra points and find a way of solving it without using that secret function nor call-  
ing system() (but execvp instead :p).

## lab8A
Straight stack smash in selectABook() (easy to steal the canary with the format string bug); overwriting strcmp in the  
GOT or the return address + pivoting to the buffer (and forget about the canary). The format string bug makes it all  
easier :)

This lab can be very useful to practice all the things learned through out the course. Perfect to test our intuition and  
creativity!

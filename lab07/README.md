## Lab7A
This exploit has a little problem: when the address of the structure contains a '0x0a' byte the exploit fails. This is because   
we have to pass that address to the program and, if it contains a 0x0a ('\n' character), the program will stop reading from  
our input and the exploit will be incomplete. Just run it again until the address doesn't contain a 0x0a.  

This all happens because in order to pivot to the heap, I needed to pass the address of the structure to the index buffer when  
the program asks for an index to print (so my ROP chain can pivot accordingly). Since the program uses fgets to read that input, 
it will stop reading when it reads a '\n'.

It can be fixed by using another ROP chain or pivoting to a place inside the stack (so you won't have to deal with heap addresses)

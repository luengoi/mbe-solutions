## Lab7A
This exploit has a little problem: when the address of the structure contains a '0x0a' byte the exploit fails. This is because   
we have to pass that address to the program and, if it contains a 0x0a ('\n' character), the program will stop reading from  
our input and the exploit will be incomplete. Just run it again until the address doesn't contain a 0x0a.

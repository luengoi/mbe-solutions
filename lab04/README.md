## Notes on lab4C



## Notes on lab4B

If the exploit throws a segfault, there is a big chance that it is because a mismatch at the shellcode address.
The code I wrote to retreive the address is based on experimentation, so you should have a look at it and tweak the
'formula' a bit in order to fix it.

## Notes on lab4A

Same issue as lab4B with the env var address. With some experimenting we can fix it to get the right address if a segfault
is thrown by the exploit. This problem can be fixed using fixenv, in fact, the whole exploit is much easier to build. The
reason why I didn't use it here is to practice this kind of skills in case I don't have access to fixenv (although I used
it to exploit the bug the first time I tried)

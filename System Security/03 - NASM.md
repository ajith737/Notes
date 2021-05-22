## NASM - Study Guide

[NASM-X Project](https://forum.nasm.us/index.php?topic=1853.0) \- It is the collection of macros, includes and examples.  
[NASMX Download](https://sourceforge.net/projects/nasmx/).

* * *

#### Installing and configuring NASMX

- After downloading extract the file to C:\\nasmx and make sure the configuration does not have any spaces in the path.
- Add path variable,Open Environment variables windows and path `C:\nasmx\bin`.
- Open cammand prompt and navigate to nasmx folder and run `setpaths.bat`
- Navigate to `C:\nasmx\demos` and edit the `windemos.inc`, Comment the following lines:
    - `%include 'nasmx.inc'`
    - `%include 'C:\nasmx\inc\nasmx.inc'`
- Finally to verify open cmd and navigate to `C:\nasmx\demos\win32\DEMO1` and make sure there are three files: `demo1.asm`, `demo1.bat` and `makefile`.
- To assembe `demo1.asm` type the following command:  
    `nasm -f win32 demo1.asm -o demo1.obj`
- To use linker `GoLink.exe /entry_main demo1.obj kernel132.dll user32.dll` here we linked with two dll files.

* * *

#### ASM Basics

|     |     |
| --- | --- |
| **Data Transfer**: `MOV`, `XCHG`, `PUSH`, `POP` | **Arithmetic**: `ADD`, `SUB`, `MUL`, `XOR`, `NOT` |
| **Control Flow**: `CALL`, `RET`, `LOOP`, `Jcc` (where cc is any condition) | **Other**: `STI`. `CLI`, `IN`, `OUT` |

Intel vs AT&T

|     |     |     |
| --- | --- | --- |
|     | Intel (Windows) | AT&T (Linux) |
| Assembly | MOV EAX,8 | MOVL $8, %EAX |
| Syntax | &lt;instruction&gt;&lt;destination&gt;&lt;source&gt; | &lt;instruction&gt;&lt;source&gt;&lt;destination&gt; |

In AT&T % sign before registers and $ before numbers. And another thing to notice is that Q(quad -64bit), L(Long-32 bits), W(word - 16 bits), B(byte-8bits).


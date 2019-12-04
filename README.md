# adbg
 
A simple use and forget library that implements some basic antidebugging techniques.
It's based on mostly code found on the below sites which I ported to mingw.

It currently compiles on mingw32-gcc 9.2.1

Disclaimer: This is a "fun" project only. Maybe it will work, maybe it won't, maybe it will erase all pixels from your screen... Who knows ?
Just don't expect it to work ;)
I have not written C for like 20 years and it's probably badly done.
Please consider giving me feedback on ways to improve that one.

## What it does

It simply tests for debugger presence by trying a couple of different techniques.
Once found, it will execute a so called "bullshit function" that just messes around, then exits by showing the mighty commodore 64 basic that loads some linux (?)
Hold on, it shows a scary message, but nothing happens :)


## Usage

in C source:

`
#include "adbg.h"

void main(void)
{
	TestDebugger();
	// Your code
}
`

Original sources that run on MSVC:

https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
https://github.com/cetfor/AntiDBG

Porting Wish Core to a new platform
===================================

Introduction
------------

This documents shows how to port Wish/Mist C99 to new platform.

Start with a template app
-------------------------

You should build a port on a working template application, which allows you print messages on the system console, opening/closing TCP connections etc.


Implementing the filesystem interface
-------------------------------------

The Wish components need a filesystem to store things like the identity/contact database, host id etc. The files are not large, so a very small file system in the order of a few tens of kilobytes should be enough for a basic Wish system. (Of course, the files get larger the more contacts there are)

The Wish filesystem interface works like the Posix (open/write/seek/read/close) interface. 

If you are porting to a Desktop/Server like system, the operating system most certainly already provides this natively, or there is a wrapper library that provides these. In that case you only need to write wrapper functions, see the Linux port.

Filesystem for embedded targets
-------------------------------

If you port to a microcontroller, the platform should have a SPI flash chip or some other form of non-volatile storage. A file system suitable for these circumstances is SPIFFS, https://github.com/pellepl/spiffs

Start by importting spiffs sources to project

You will need to provide the spiffs hal functions, as described in https://github.com/pellepl/spiffs/wiki/Integrate-spiffs#integrating-spiffs

You should also pay attention to the config options described in: https://github.com/pellepl/spiffs/wiki/Configure-spiffs

You should write a small test routine to test the filesystem, and verify that you can open a file, write to it, read from it and seek to some location in the file.

Then you will implement the filesystem interface in wish_fs.h

Porting network functions
-------------------------

If you port to a platform that has a Berkeley socket API, and the platform provides the select() system call, then you can use the port components that are already in use in the Linux and ESP32 ports for instance (comming soon).

The order of porting work could be this:

- Wish local discovery: UDP send/receive
- TCP server
- TCP client
- Relay client functions
- (Relay server)




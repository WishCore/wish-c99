# Quick build instructions

Build using cmake:

```sh
mkdir build
cd build 
cmake ..
make
```

Build using make (deprecated):

$ make -f make-linux.mk



Cross-compile build for ESP8266


Wish/Mist C implementation for esp8266

This is the repository for the proof-of-concept ANSI C implementation of
the Wish/Mist IoT communications stack.

This software targets the Olimex ESP8266-EVB hardware. It is a
nearly-fully functional Wish/Mist node, offering Wish "chat" service and a
Mist node making it possible to toggle the on-board relay on and off.

The Mist service includes a reply to the "control.model" command, as
well as "control.follow" and "control.write". Any writes targetting the
"relay" endpoint feature will be replied by a "follow" reply indicating
the new state.  Note however, that currently all the Mist service messages have
hard-coded source and destination WSIDs! For this reason, it will only
work with traditional Mist-UI.

The Mist command "control.map" is not supported.

The chat service replies to any messages by telling how much it has has
free space on the TCP receive ring buffer and heap, but sometimes it
will enter a period where a cryptic movie quote from "Le charme discret
de la bourgeoisie", by Louis Buñuel (1972) is output... You should try it!

Actually, this C implementation should be applicable to all MCUs, but it
is developed on the ESP8266 hardware.

The project was started using the SDK version 1.4.1
(esp_iot_sdk_v1.4.1_pre5_15_10_27.zip).

The project includes the mbedTLS 2.x library (under Apache 2.0 license).

This software uses the ESP8266 wifi stack in "station" mode - it will
connect to the network defined in the begining of user/user_main.c

The user should also note, that the IP address of the remote wish-core
is hardcoded (in user/user_main.c), and also that the local and remote
Wish user identity hashes are also hard-coded (in the begining of
wish/wish_io.c). The implemenatation currently only supports one Wish
connection. No "incoming" Wish connections are accepted by this node.

Overall, this software shows that Wish/Mist can clearly be implemeted on
microcontroller platforms offering just some 30 kilobytes of RAM
and ca. 250 kB Flash memory.

About the flash configuration of ESP8266 modules
This project targets modules with 2Mbyte (16Mbit) flash chips. 
Configuration of flash chip must be reflected in at least the following
places:

-The LD script, where the length of the irom0 segment must be correct
(however it should must be inside the first 1024 Kbytes)

-in Makefile, in the esptool.py elf2image step, you should provide
--flash_size and --flash_mode correctly
(See flash chip's datasheet for supportted SPI modes (dual, quad..)

-in Makefile, the esptool.py write_flash step MUST have the correct
flash_size and flash_mode defined.


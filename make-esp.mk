# Makefile for ESP8266 projects
#
# Thanks to:
# - zarya
# - Jeroen Domburg (Sprite_tm)
# - Christian Klippel (mamalala)
# - Tommie Gannert (tommie)
#
# Changelog:
# - 2014-10-06: Changed the variables to include the header file directory
# - 2014-10-06: Added global var for the Xtensa tool root
# - 2014-11-23: Updated for SDK 0.9.3
# - 2014-12-25: Replaced esptool by esptool.py

# Output directors to store intermediate compiled files
# relative to the project directory
BUILD_BASE	= build
FW_BASE		= firmware

# base directory for the compiler
XTENSA_TOOLS_ROOT ?= /opt/Espressif/crosstool-NG/builds/xtensa-lx106-elf/bin

# base directory of the ESP8266 SDK package, absolute
SDK_BASE	?= /opt/Espressif/ESP8266_SDK

# esptool.py path and port
ESPTOOL		?= esptool.py
ESPPORT		?= /dev/ttyUSB0

# name for the target project
TARGET		= app

# which modules (subdirectories) of the project to include in compiling
MODULES		= port/esp8266/driver wish deps/mbedtls-2.1.2/library deps/cBSON deps/bson mist \
deps/ed25519/src wish_rpc wish_app port port/esp8266/ port/esp8266/spiffs/src \
apps/mist-esp8266-evb-app apps/mist-config apps/mist-esp8266-sonoff-app
EXTRA_INCDIR    = port/esp8266/include deps/mbedtls-2.1.2/include deps/ed25519/src wish_rpc \
wish_app port/esp8266 port/esp8266/spiffs/src deps/uthash/include

# libraries used in this project, mainly provided by the SDK
LIBS		= c gcc hal pp phy net80211 lwip wpa main crypto

# compiler flags using during compilation of source files
#CFLAGS		= -Os -g -O2 -Wpointer-arith -Wundef -Werror -Wl,-EL -fno-inline-functions -nostdlib -mlongcalls -mtext-section-literals  -D__ets__ -DICACHE_FLASH
# Remove -Werror for now, as our port of mbedTLS produces som many
# warnings
CFLAGS		= -O2 -Wall -Wno-pointer-sign -Wl,-EL -fno-inline-functions -nostdlib -mlongcalls -mtext-section-literals -D__ets__ -DICACHE_FLASH -ffunction-sections -fdata-sections -DCOMPILING_FOR_ESP8266

# linker flags used to generate the main object file
LDFLAGS		= -nostdlib -Wl,--no-check-sections -u call_user_start -Wl,-static

# linker script used for the above linkier step
LD_SCRIPT	= -Tport/esp8266/ld/eagle.app.v6.ld

# various paths from the SDK used in this project
SDK_LIBDIR	= lib
SDK_LDDIR	= ld
SDK_INCDIR	= include include/json

# we create two different files for uploading into the flash
# these are the names and options to generate them
# Note that these are for "no bootloader" configuration.
FW_FILE_1_ADDR	= 0x00000
FW_FILE_2_ADDR	= 0x40000
BLANK_FILE = /opt/Espressif/ESP8266_SDK/bin/blank.bin
ESP_INIT_DATA_FILE = /opt/Espressif/ESP8266_SDK/bin/esp_init_data_default.bin

BLANK_ADDR = 0xFE000	#setting for 1024 KB flash
ESP_INIT_DATA_ADDR = 0xFC000 #setting for 1024 KB flash
ESP_RF_CAL_SEC_ADDR = 0xFA000 #setting for 1024 KB flash
#Export the RF_CAL_SEC as macro to C code
CFLAGS += -DRF_CAL_SEC_ADDR=$(ESP_RF_CAL_SEC_ADDR)

# select which tools to use as compiler, librarian and linker
CC		:= $(XTENSA_TOOLS_ROOT)/xtensa-lx106-elf-gcc
AR		:= $(XTENSA_TOOLS_ROOT)/xtensa-lx106-elf-ar
LD		:= $(XTENSA_TOOLS_ROOT)/xtensa-lx106-elf-gcc
SIZE	:= $(XTENSA_TOOLS_ROOT)/xtensa-lx106-elf-size



####
#### no user configurable options below here
####
SRC_DIR		:= $(MODULES)
BUILD_DIR	:= $(addprefix $(BUILD_BASE)/,$(MODULES))

SDK_LIBDIR	:= $(addprefix $(SDK_BASE)/,$(SDK_LIBDIR))
SDK_INCDIR	:= $(addprefix -I$(SDK_BASE)/,$(SDK_INCDIR))

SRC		:= $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ		:= $(patsubst %.c,$(BUILD_BASE)/%.o,$(SRC))
LIBS		:= $(addprefix -l,$(LIBS))
APP_AR		:= $(addprefix $(BUILD_BASE)/,$(TARGET)_app.a)
TARGET_OUT	:= $(addprefix $(BUILD_BASE)/,$(TARGET).out)

#LD_SCRIPT	:= $(addprefix -T$(SDK_BASE)/$(SDK_LDDIR)/,$(LD_SCRIPT))

INCDIR	:= $(addprefix -I,$(SRC_DIR))
EXTRA_INCDIR	:= $(addprefix -I,$(EXTRA_INCDIR))
MODULE_INCDIR	:= $(addsuffix /include,$(INCDIR))

FW_FILE_1	:= $(addprefix $(FW_BASE)/,$(FW_FILE_1_ADDR).bin)
FW_FILE_2	:= $(addprefix $(FW_BASE)/,$(FW_FILE_2_ADDR).bin)

V ?= $(VERBOSE)
ifeq ("$(V)","1")
Q :=
vecho := @true
else
Q := @
vecho := @echo
endif

vpath %.c $(SRC_DIR)

define compile-objects
$1/%.o: %.c
	$(vecho) "CC $$<"
	$(Q) $(CC) $(INCDIR) $(MODULE_INCDIR) $(EXTRA_INCDIR) $(SDK_INCDIR) $(CFLAGS) -c $$< -o $$@
endef

.PHONY: all checkdirs flash clean

all: checkdirs $(TARGET_OUT) $(FW_FILE_1) $(FW_FILE_2)

$(FW_BASE)/%.bin: $(TARGET_OUT) | $(FW_BASE)
	$(vecho) "FW $(FW_BASE)/"
	$(Q) $(ESPTOOL) elf2image --flash_size 8m --flash_mode qio -o $(FW_BASE)/ $(TARGET_OUT)

$(TARGET_OUT): $(APP_AR)
	$(vecho) "LD $@"
	$(Q) $(LD) -L$(SDK_LIBDIR) $(LD_SCRIPT) $(LDFLAGS) -Wl,--start-group $(LIBS) $(APP_AR) -Wl,-Map=$(TARGET).map -Wl,--end-group -o $@
	$(Q) $(SIZE) $@

$(APP_AR): $(OBJ)
	$(vecho) "AR $@"
	$(Q) $(AR) cru $@ $^

checkdirs: $(BUILD_DIR) $(FW_BASE)

$(BUILD_DIR):
	$(Q) mkdir -p $@

$(FW_BASE):
	$(Q) mkdir -p $@

flash_all:
	$(vecho) "Flashing program, blank.bin and esp_init_data.bin, also \
blank.bin to RF_CAL sector"
	$(ESPTOOL) --port $(ESPPORT) write_flash --flash_size 8m --flash_mode qio $(FW_FILE_1_ADDR) $(FW_FILE_1) $(FW_FILE_2_ADDR) $(FW_FILE_2) $(BLANK_ADDR) $(BLANK_FILE) $(ESP_INIT_DATA_ADDR) $(ESP_INIT_DATA_FILE) $(ESP_RF_CAL_SEC_ADDR) $(BLANK_FILE)

flash: $(FW_FILE_1) $(FW_FILE_2)
	$(vecho) "Flashing just the program"
	$(ESPTOOL) --port $(ESPPORT) write_flash --flash_size 8m --flash_mode qio $(FW_FILE_1_ADDR) $(FW_FILE_1) $(FW_FILE_2_ADDR) $(FW_FILE_2)

flash_erase:
	$(vecho) "Erasing all of flash"
	$(ESPTOOL) --port $(ESPPORT) erase_flash

clean:
	$(Q) rm -rf $(FW_BASE) $(BUILD_BASE)

#A target for just starting the program when chip is in bootloader mode.
#Useful if you want to prevent the chip from rebooting automatically
#after a system fail
run:
	$(ESPTOOL) --port $(ESPPORT) run

$(foreach bdir,$(BUILD_DIR),$(eval $(call compile-objects,$(bdir))))

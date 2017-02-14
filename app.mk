BUILD_BASE	= build-app

# name for the target project
TARGET		= app

# which modules (subdirectories) of the project to include in compiling
MODULES		= wish_app_deps wish_app wish_rpc mist apps/mist-standalone deps/mbedtls-2.1.2/library deps/cBSON deps/ed25519/src ed25519/src deps/bson wish_app_port_deps/unix
EXTRA_INCDIR    = wish_app_deps deps/libuv/include deps/mbedtls-2.1.2/include deps/cBSON deps/bson deps/ed25519/src deps/uthash/include wish_app_port_deps/unix

# libraries used in this project, mainly provided by the SDK
LIBS		= 

# compiler flags using during compilation of source files
#CFLAGS		= -g -O0 -Wpointer-arith -Wundef -Werror -Wl,-EL -fno-inline-functions -nostdlib -mlongcalls -mtext-section-literals  -D__ets__ -DICACHE_FLASH
# Remove -Werror for now, as our port of mbedTLS produces som many
# warnings

# Mist Modbus changes by AK 2016-09-20
#CFLAGS		=  -g -Wall
CFLAGS		=  -g -Wall -Wno-pointer-sign -Werror -Wno-unused-function -Wno-unused-variable -pthread -MD -DSTDC_HEADERS -DHAVE_STDLIB_H -DENABLE_PTHREAD -DMBM_RTU_ENABLED=1 -DMBM_ASCII_ENABLED=0 -DMBM_SERIAL_RTU_MAX_INSTANCES=2 -DMBM_TCP_ENABLED=0
# OSX could not handle this:  -Wno-unused-but-set-variable
#-MD -D_XOPEN_SOURCE=500 -DSTDC_HEADERS -DHAVE_STDLIB_H -DMBM_SERIAL_ASCII_MAX_INSTANCES=2 -DMBM_TCP_ENABLED=0

# ASM flags
ASFLAGS     = -MD 

# linker flags used to generate the main object file
LDFLAGS		= -pthread
LDLIBS		= -L../../ts/libuv/.libs -lpthread -l:libuv.a

# select which tools to use as compiler, librarian and linker
CC		:= gcc
AR		:= 
LD		:=
SIZE	:=



####
#### no user configurable options below here
####
SRC_DIR		:= $(MODULES)
BUILD_DIR	:= $(addprefix $(BUILD_BASE)/,$(MODULES))

SRC		:= $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ		:= $(patsubst %.c,$(BUILD_BASE)/%.o,$(SRC))
LIBS		:= $(addprefix -l,$(LIBS))

INCDIR	:= $(addprefix -I,$(SRC_DIR))
EXTRA_INCDIR	:= $(addprefix -I,$(EXTRA_INCDIR))

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

all: clean checkdirs $(TARGET) 

noclean:  checkdirs $(TARGET) 

$(TARGET): $(OBJ)
	gcc $(OBJ) $(LDFLAGS) $(LDLIBS) -o wish_app_standalone_c99

checkdirs: $(BUILD_DIR) 

$(BUILD_DIR):
	$(Q) mkdir -p $@

clean:
	$(Q) rm -rf $(FW_BASE) $(BUILD_BASE)

$(foreach bdir,$(BUILD_DIR),$(eval $(call compile-objects,$(bdir))))

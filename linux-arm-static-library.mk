BUILD_BASE	= build

# name for the target project
TARGET	= libmist.a

# which modules (subdirectories) of the project to include in compiling
MODULES		= wish_app_deps wish_app_port_deps/unix wish_app wish_rpc mist apps/mist-api apps/mist-standalone deps/mbedtls-2.1.2/library deps/cBSON deps/ed25519/src ed25519/src deps/bson 
EXTRA_INCDIR    = wish_app_deps wish_rpc deps/libuv/include deps/mbedtls-2.1.2/include deps/cBSON deps/bson deps/ed25519/src deps/uthash/include

# libraries used in this project, mainly provided by the SDK
LIBS		= 

# Mist Modbus changes by AK 2016-09-20
CFLAGS		=  -g -Wall -O2 -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-pointer-sign -Werror -Wno-unused-function -Wno-unused-variable -pthread -MD -DSTDC_HEADERS -DHAVE_STDLIB_H -DENABLE_PTHREAD

# ASM flags
ASFLAGS     = -MD 

# linker flags used to generate the main object file
LDFLAGS		= -pthread
LDLIBS		= -lpthread -lrt

# select which tools to use as compiler, librarian and linker
CC=arm-linux-gnueabihf-gcc-4.8
CXX=arm-linux-gnueabihf-g++-4.8
#CC		:= gcc
#CC		:= clang
AR		:= ar
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
	$(AR) rcs $@ $^

checkdirs: $(BUILD_DIR) 

$(BUILD_DIR):
	$(Q) mkdir -p $@

clean:
	$(Q) rm -rf $(FW_BASE) $(BUILD_BASE)

$(foreach bdir,$(BUILD_DIR),$(eval $(call compile-objects,$(bdir))))

ifeq (,$(findstring bash,$(SHELL)))
	SHELL := '/bin/bash'
endif

CONFIG_DEBUG_INFO = y
KERNEL_MODULE_NAME := snap
KERNEL_MODULE_OBJECT_FILE_LIST := kern_mod.o kprobe_utils.o socket_utils.o engine.o
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

INCLUDES = -I.

ccflags-y += $(INCLUDES) -ggdb -O0 -Wall

obj-m += snap.o

$(KERNEL_MODULE_NAME)-y += $(KERNEL_MODULE_OBJECT_FILE_LIST)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

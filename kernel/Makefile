ifneq ($(KERNELRELEASE),)

obj-m += xt_MARKMPLS.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
MKDIR_P = mkdir -p
OUT_DIR := /lib/modules/$(shell uname -r)/kernel/net/ipt_markmpls/kernel/

all:	modules

modules:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

directories: ${OUT_DIR}

${OUT_DIR}:
	${MKDIR_P} ${OUT_DIR}

install: directories
	cp *.ko ${OUT_DIR}
	depmod -a
endif

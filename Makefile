# SPDX-License-Identifier: GPL-2.0-only
# builds the kprobes example kernel modules;
# then to use one (as root):  insmod <module_name.ko>
MODULE_NAME		:= fileops-kprobe
PWD			:= $(shell pwd)
KERNEL_HEAD		:= $(shell uname -r)
KERNEL_DIR		:= /lib/modules/$(KERNEL_HEAD)/build
obj-m			:= $(MODULE_NAME).o
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

install:
	sudo insmod $(MODULE_NAME).ko

remove:
	sudo rmmod $(MODULE_NAME)
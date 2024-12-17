obj-m += syscalltracer.o

PWD := $(CURDIR) 

BUILD_DIR=build

HEADERS := $(shell uname -r)

CONFIG_PROFILING := n 
CONFIG_RETHUNK := n 
CONFIG_RETPOLINE := n
CONFIG_KALLSYMS_ALL := y
ccflags-y := -mindirect-branch=keep -mfunction-return=keep
syscalltracer-objs := main.o utils.o syscallhook.o root.o

all: 
	$(MAKE) -C /lib/modules/$(HEADERS)/build M=$(PWD) modules
	@rm -rf ${BUILD_DIR}
	@mkdir ${BUILD_DIR}
	@mv -f Module.symvers modules.order *.o *.ko *.mod *.mod.c .*.cmd ${BUILD_DIR}
 
clean: 
	@rm -rf ${BUILD_DIR}
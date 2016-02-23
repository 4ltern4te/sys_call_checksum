obj-m+=sys_call_checksum.o


KERNEL_VERSION = $(shell echo ${KERNEL})
#$(warning $(KERNEL_VERSION))

ifeq ($(KERNEL_VERSION),"")
    ALL = make -C /lib/modules/$(KERNEL_VERSION)/build/ M=$(PWD) modules
    CLEAN = make -C /lib/modules/$(KERNEL_VERSION)/build/ M=$(PWD) modules
else
    ALL = make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
    CLEAN = make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
endif

all:
	$(ALL)
clean:
	$(CLEAN)

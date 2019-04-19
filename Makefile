obj-m += sys_cpenc.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xhw1 cpenc

xhw1: xhw1.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw1.c -o xcpenc -lcrypto -lssl 

cpenc:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -lcrypto -lssl

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcpenc

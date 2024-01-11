
obj-m += zfw_module.o #把文件test.o作为"模块"进行编译，不会编译到内核，但是会生成一个独立的 "test.ko" 文件

#remake: uninstall clean install
remake: clean install

uninstall:
	rmmod zfw_module.ko

install: oall ins
	mknod zfw_file c 100 0


oall:	zfw zfwmod

zfw:	zfw.c zfw.h
	gcc -Wall -o zfw zfw.c

zfwmod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f zfw zfw_file
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:
	insmod zfw_module.ko

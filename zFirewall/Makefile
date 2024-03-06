
obj-m += zfw_module.o 
# obj-m指定要编译成模块的源文件test.o，不会编译到内核，会生成一个独立的 "test.ko" 文件

remake: clean install

uninstall:# 卸载内核模块
	rmmod zfw_module.ko

install: oall ins	# 使用 mknod 命令创建设备节点，设备节点名称为 "zfw_file"，主设备号为 100，次设备号为 0
	mknod zfw_file c 100 0


oall:	zfw zfwmod

zfw:	zfw.c zfw.h	# 编译 -Wall 选项表示显示所有警告信息
	gcc -Wall -o zfw zfw.c

# uname -r 获取当前运行的 Linux 内核的版本号
# 使用 make 命令在内核源代码目录下编译内核模块，-C 表示指定目录，M=$(PWD) 表示指定模块源代码所在的当前目录，modules 表示编译内核模块
zfwmod:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:	# 清理编译过程中生成的中间文件和目标文件
	rm -f zfw zfw_file
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

ins:	# 安装内核模块
	insmod zfw_module.ko

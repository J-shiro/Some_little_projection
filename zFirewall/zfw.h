#ifndef _ZFW_H_
#define _ZFW_H_

#include<linux/types.h>

//字符设备名，字符设备的主设备号
#define DEVICE_INTF_NAME "zfw_file"
#define DEVICE_MAJOR_NUM 100


//enum枚举类型 指令的模式
enum zfw_mode {
	Z_NONE = 0,
	Z_ADD = 1,
	Z_REMOVE =2,
	Z_VIEW = 3
};

//过滤规则 结构体
//32:无符号整型 4字节
//16:无符号短整型 2字节
//8:1字节
struct zfw_rule {	
	uint32_t in;	
	uint32_t s_ip;		//源IP地址
	uint32_t s_mask; 	//子网掩码
	uint16_t s_port; 	//源端口
	uint32_t d_ip;		//目标IP地址
	uint32_t d_mask; 	//目标子网掩码
	uint16_t d_port; 	//目标端口
	uint8_t proto; 		//协议
};

//控制命令结构体
struct zfw_ctl {
	enum zfw_mode mode;
	struct zfw_rule rule;
};

#endif

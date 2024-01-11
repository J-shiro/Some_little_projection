#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>
#include<getopt.h>
#include<limits.h>
#include<stdlib.h>
#include "zfw.h"
#include<netinet/in.h>
#include<unistd.h>
#define no_argument 0
#define required_argument 1


//打印使用方法和参数
static void print_usage(void){
	printf("Usage: zfw RULE_OPTION xx\n"
		"--------------------------\n"
		"-i --in			input\n"
		"-o --out		output\n"
		"-s --s_ip IPADDR	source ip address\n"
		"-m --s_mask MASK	source mask\n"
		"-p --s_port PORT	source port\n"
		"-d --d_ip IPADDR	destination ip address\n"
		"-k --d_mask MASK	destination mask\n"
		"-q --d_port PORT	destination port\n"
		"-c --proto PROTOCOL	protocol(TCP:6, UDP:17, ICMP:1)\n"
		"-a --add		add a rule\n"
		"-r -remove		remove a rule\n"
		"-v --view		view rules\n"
		"-h --help		usage\n");
}

//该函数解析一个字符串，检查范围
static int64_t parse_number(const char *str, uint32_t min_val,uint32_t max_val){
	uint32_t num;
	char *end;

	num = strtol(str, &end, 10);//把str指向的字符串根据给定的base:10转换为一个长整数[例:str:"123this" num=123,end="this"]
	if(end == str || (num > max_val) || (num<min_val))
		return -1;//有字符or数字超出范围
	return num;
}

//经过一个设备文件将命令发送到防火墙内核模块
static void send_instruction(struct zfw_ctl *ctl){
	FILE *fp;
	int byte_count;

	fp = fopen(DEVICE_INTF_NAME,"w");
	if(fp == NULL){
		//打开失败
		printf("An device file (%s) can't be opened.\n",DEVICE_INTF_NAME);
		return ;
	}
	//ctl:要写出数据的内存首地址,1:写出数据的基本单元的字节大小(单位)
	//sizeof(*ctl):写出数据的基本单元的个数,fp:打开的文件指针
	//ctl->fp,byte_count:返回实际写出到文件的基本单元个数
	byte_count = fwrite(ctl, 1, sizeof(*ctl), fp);
	if(byte_count!=sizeof(*ctl)){
		printf("Write process is incomplete. Please try again.\n");
	}
	fclose(fp);
}

//函数实现展示所有已经存在的规则
static void view_rules(void){
	FILE *fp;
	char *buffer;
	int byte_count;
	struct in_addr addr;
	struct zfw_rule *rule;

	fp = fopen(DEVICE_INTF_NAME,"r");
	if(fp==NULL){
		printf("An device file (%s) can't be opened.\n",DEVICE_INTF_NAME);
		return ;
	}

	buffer = (char *)malloc(sizeof(*rule));
	//没有内存空间了
	if(buffer == NULL){
		printf("Rule can't be printed due to insufficient memory\n");
		return ;
	}

	//一行一行打印规则
	printf("I/O	"
		"S_Addr		S_Mask		S_Port	"
		"D_Addr		D_Mask		D_Port		Proto\n");
	//从fp文件流读取数据到buffer指向的数组中,1读取每个元素的大小,size:元素的个数
	while((byte_count = fread(buffer, 1, sizeof(struct zfw_rule), fp)) > 0){
		rule = (struct zfw_rule *)buffer;
		printf("%-3s	", rule->in ? "In" : "Out");
		addr.s_addr = rule->s_ip;
		//有-:左对齐,无-:右对齐,  15:占15个位置
		printf("%-15s	",inet_ntoa(addr));
		//inet_ntoa():将地址-->a.b.c.d, 返回一个字符指针否则返回NULL
		addr.s_addr = rule->s_mask;
		printf("%-15s	",inet_ntoa(addr));
		printf("%-5d	",rule->s_port);
		addr.s_addr = rule->d_ip;
		printf("%-15s	",inet_ntoa(addr));
		addr.s_addr = rule->d_mask;
		printf("%-15s	",inet_ntoa(addr));
		printf("%-5d		",rule->d_port);
		printf("%-3d\n",rule->proto);
	}
	free(buffer);
	fclose(fp);
}


static int parse_arguments(int argc, char **argv,struct zfw_ctl *ret_ctl){
	int opt;
	int64_t lnum; //返回一个数值
	int opt_index;
	struct zfw_ctl ctl = {};
	struct in_addr addr; //地址 包含一个in_addr_t s_addr

	static struct option long_options[] = {
		//指明了一个“长参数”
		//类似于命令行 ls -a --xxx
		//长参数名,参数个数(0,1,2),
		{"in", no_argument, 0, 'i'},
		{"out", no_argument, 0, 'o'},
		{"s_ip", required_argument, 0, 's'},
		{"s_mask",required_argument, 0, 'm'},
		{"s_port", required_argument, 0, 'p'},
		{"d_ip", required_argument, 0, 'd'},
		{"d_mask",required_argument, 0, 'k'},
		{"d_port",required_argument, 0, 'q'},
		{"proto", required_argument, 0, 'c'},
		{"add", no_argument, 0, 'a'},
		{"remove", no_argument, 0, 'r'},
		{"view", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0,0,0,0}
	};

	if(argc == 1) {
		print_usage();
		return 0;
	}

	ctl.mode = Z_NONE; //初始化为0
	ctl.rule.in = -1; //初始化为-1
	while(1){
		opt_index = 0;
		//命令行解析参数
		//a 只有选项-a
		//b: 带一个参数 -b xx
		//c:: 带可选参数可有可无 -c200
		opt = getopt_long(argc, argv, "ios:m:p:d:k:q:c:arvh", long_options, &opt_index);//optarg应是参数后的具体值:-a 20
		//若解析完所有字符未找到，返回（-1）
		if(opt==-1){
			break;
		}

		//若短选项找到，返回短选项对应的字符
		switch(opt) {
		case 'i'://入站规则
			if(ctl.rule.in == 0) {//只能选一个
				printf("Only choose In or Out!\n");
				return -1;
			}
			ctl.rule.in = 1;
			break;
		case 'o'://出站规则
			if(ctl.rule.in == 1) {
				printf("Only choose In or Out!\n");
				return -1;
			}
			ctl.rule.in = 0;
			break;
		case 's'://源IP地址
			//将一个字符串表示的点分十进制IP地址转换为网络字节序存储在addr中，返回0表示失败
			if(inet_aton(optarg,&addr) == 0) {
				printf("Invalid source ip address\n");
				return -1;
			}
			ctl.rule.s_ip = addr.s_addr;
			break;
		case 'm'://源子网掩码
			if(inet_aton(optarg,&addr) == 0) {
				printf("Invalid source subnet mask\n");
				return -1;
			}
			ctl.rule.s_mask = addr.s_addr;
			break;
		case 'p'://源端口号
			lnum = parse_number(optarg, 0, USHRT_MAX);
			//返回长整型数字lnum,范围0-USHRT_MAX:(65535)
			if(lnum<0){
				printf("Invalid source port number\n");
				return -1;
			}
			ctl.rule.s_port = (uint16_t)lnum;
			break;
		case 'd'://目标IP地址
			if(inet_aton(optarg,&addr)==0){
				printf("Invalid destination ip address\n");
				return -1;
			}
			ctl.rule.d_ip = addr.s_addr;
			break;
		case 'k'://目标子网掩码
			if(inet_aton(optarg, &addr) == 0){
				printf("Invalid destination subnet mask\n");
				return -1;
			}
			ctl.rule.d_mask = addr.s_addr;
			break;
		case 'q'://目标端口号
			lnum = parse_number(optarg,0,USHRT_MAX);
			if(lnum < 0){
				printf("Invalid destination port number\n");
				return -1;
			}
			ctl.rule.d_port = (uint16_t)lnum;
			break;
		case 'c'://协议号
			lnum = parse_number(optarg, 0, UCHAR_MAX);
			//UCHAR_MAX:255
			if(!(lnum==0||lnum==IPPROTO_TCP||lnum==IPPROTO_UDP||lnum==IPPROTO_ICMP)){
				//如果不是tcp,udp,icmp协议
				printf("Invalid protocol number %d, there're (tcp)%d,(udp)%d,(icmp)%d.\n",(uint8_t)lnum,IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP);
				return -1;
			}
			ctl.rule.proto = (uint8_t)lnum;
			break;
		case 'a'://添加规则
			if(ctl.mode != Z_NONE){
				printf("Only one mode can be selected.\n");
				return -1;
			}
			//初始化得为ZFW_NONE，否则说明选择了多个
			ctl.mode = Z_ADD;
			break;
		case 'r'://删除规则
			if(ctl.mode !=Z_NONE){
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = Z_REMOVE;
			break;
		case 'v'://查看规则
			if(ctl.mode!=Z_NONE){
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mode = Z_VIEW;
			break;
		case 'h':
		//若遇到一个选项不在短字符长字符中,或在长字符里有二义性,返回"?"	
		case '?':
		default:
			print_usage();
			return -1;
		}
	}
	if(ctl.mode == Z_NONE){
		printf("Please specify mode -- (add | remove | view)\n");
		return -1;
	}
	if(ctl.mode != Z_VIEW && ctl.rule.in == -1){
		printf("Please specify either In or Out\n");
		return -1;
	}

	*ret_ctl = ctl;//返回给引用的控制结构体
	return 0;
}

int main(int argc, char *argv[]){
	//argc参数个数 argv[]确定某个参数
	struct zfw_ctl ctl = {}; //控制结构体
	int ret; 

	ret = parse_arguments(argc, argv, &ctl);
	//ctl 引用返回类似于初始化
	if(ret < 0) return ret;

	switch(ctl.mode) {
		case Z_ADD:
			//printf("add");
			//break;
		case Z_REMOVE:
			//printf("remove");
			send_instruction(&ctl);
			break;
		case Z_VIEW:
			//printf("view");
			view_rules();
			break;
		default:
			//printf("default");
			return 0;
	}
	//return 0;
}

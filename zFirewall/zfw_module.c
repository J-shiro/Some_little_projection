#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/fs.h>
#include<linux/slab.h>
#include<asm/uaccess.h>
#include<linux/list.h>
#include<linux/types.h>
#include<linux/netfilter_ipv4.h>
#include<linux/in.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>

#include "zfw.h"
#include "linux/gfp.h"

#define EQUAL_NET_ADDR(ip1,ip2,mask) (((ip1 ^ ip2 ) & mask) == 0) //^异或同0异1  &与
#define IGNORE(x) (x==0)

MODULE_LICENSE("GPL");

//list node containing a filter rule
struct rule_node {
	struct zfw_rule rule;
	struct list_head list;//linux内核经典双向链表
};

struct list_head In_lhead;//入站规则链表头
struct list_head Out_lhead;//出站规则链表头

static int Device_open;	//设备文件的打开计数器
static char *Buffer;	//从用户空间接收数据的缓冲区


//过滤器
static unsigned int zfw_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct list_head *rule_list_head){
	struct list_head *listh;
	struct rule_node *node;
	struct zfw_rule *r;
	struct iphdr *iph;	//ip头
	struct tcphdr *tcph;	//tcp头
	struct udphdr *udph;	//udp头
	
	uint32_t s_ip;
	uint32_t d_ip;
	uint16_t s_port;
	uint16_t d_port;
	unsigned char proto;

	if(!skb || rule_list_head->next == rule_list_head)//信息为空
		return NF_ACCEPT;//通过,接受数据包
	
	iph = ip_hdr(skb);//获取ip头
	if(iph==NULL)
		return NF_ACCEPT;
	
	proto = iph->protocol;
	s_ip = iph->saddr;
	d_ip = iph->daddr;
	if(proto == IPPROTO_UDP){
		udph = udp_hdr(skb);
		s_port = ntohs(udph->source);
		d_port = ntohs(udph->dest);
		//ntohs: 16位数由网络字节顺序转换为主机字节顺序
	}
	else if(proto == IPPROTO_TCP){
		tcph = tcp_hdr(skb);
		s_port = ntohs(tcph->source);
		d_port = ntohs(tcph->dest);
	}
	else if(proto == IPPROTO_ICMP){
		s_port = 0;
		d_port = 0;
	}
	else return NF_ACCEPT;

	//循环规则链表,执行匹配
	listh = rule_list_head;
	list_for_each_entry(node, listh, list){//从listh开始循环遍历node的每一个list
		r = &(node->rule);
		if(!IGNORE(r->proto) && (r->proto != iph->protocol))
			continue;
		if(!IGNORE(r->s_ip) && !EQUAL_NET_ADDR(r->s_ip, s_ip,r->s_mask))
			continue;
		if(!IGNORE(r->s_port) && (r->s_port != s_port))
			continue;
		if(!IGNORE(r->d_ip) && !EQUAL_NET_ADDR(r->d_ip, d_ip, r->d_mask))
			continue;
		if(!IGNORE(r->d_port) && (r->d_port != d_port))
			continue;
		printk(KERN_INFO "%pI4 %pI4 %d %d\n",&(r->d_ip), &(r->d_mask), r->d_port, r->proto);
		printk(KERN_INFO "zFirewall: Drop packet src %pI4:%d	dst %pI4:%d	proto %d\n",&(s_ip), s_port, &(d_ip), d_port, iph->protocol);

		return NF_DROP;//阻断
	}
	return NF_ACCEPT;
}

static unsigned int zfw_in_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	return zfw_filter(priv,skb,state,&In_lhead);
}

 
static unsigned int zfw_out_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	return zfw_filter(priv,skb,state,&Out_lhead);
}

static void zfw_rule_add(struct zfw_rule *rule){
	struct list_head *lheadp;
	struct rule_node *nodep;
	nodep = (struct rule_node*)kmalloc(sizeof(struct rule_node), GFP_ATOMIC);
	if(nodep == NULL){
		printk(KERN_ALERT "zFirewall: Cannot add a new rule due to insufficient memory\n");
		return ;
	}
	nodep->rule = *rule;

	if(rule->in == 1) {
		lheadp = &In_lhead;
		printk(KERN_INFO "zFirewall: Add rule to the inbound list ");
	}else{
		lheadp = &Out_lhead;
		printk(KERN_INFO "zFirewall: Add rule to the outbound list ");
	}
	list_add_tail(&nodep->list, lheadp);//new, head
	// == __list_add(new, head->prev, head)
	// __list_add(new, prev, next)
	//  将new插入到prev和next中间,则add_tail函数:将new插入到head前
	printk(KERN_INFO "src %pI4：%d	dst %pI4:%d	proto %d\n", &(rule->s_ip), rule->s_port, &(rule->d_ip),rule->d_port, rule->proto);
}//%p打印地址(指针地址)的,十六进制的形式

//该函数从规则链表删除一个规则
static void zfw_rule_del(struct zfw_rule *rule){
	struct rule_node *node;
	struct list_head *lheadp;
	struct list_head *lp;

	if(rule->in == 1){
		lheadp = &In_lhead;
	}else{
		lheadp = &Out_lhead;
	}
	
	for(lp = lheadp;lp->next!=lheadp;lp=lp->next){
		node = list_entry(lp->next, struct rule_node, list);//指向lp的下一个首节点
		if(node->rule.in == rule->in &&
		node->rule.s_ip == rule->s_ip &&
		node->rule.s_mask == rule->s_mask &&
		node->rule.s_port == rule->s_port &&
		node->rule.d_ip == rule->d_ip &&
		node->rule.d_mask == rule->d_mask &&
		node->rule.d_port == rule->d_port &&
		node->rule.proto == rule->proto){
			list_del(lp->next);
			kfree(node);
			printk(KERN_INFO "zFirewall: Remove rule: src %pI4:%d	dst %pI4:%d	proto %d\n",&(rule->s_ip),rule->s_port, &(rule->d_ip), rule->d_port, rule->proto);
			break;
		}
	}
}




//该函数用于用户空间view操作，查看所有模块中的规则
static ssize_t zfw_dev_read(struct file *file,char *buffer, size_t length, loff_t *offset){
	//读取file,buffer对应放置信息的缓冲区,length读取长度,offset相对文件开头的偏移
	
	int byte_read = 0;
	static struct list_head *inlp = &In_lhead;
	static struct list_head *outlp = &Out_lhead;
	struct rule_node *node;
	char *readptr;

	//遍历规则链表(入站)
	if(inlp->next != &In_lhead){
		//找出inlp->next指针指向的链表节点所在的struct rule_node类型的结构体首地址,list是该结构体里的成员
		node = list_entry(inlp->next, struct rule_node, list);
		readptr = (char*)&node->rule;
		inlp = inlp->next;
	}
	else if(outlp->next != &Out_lhead){
		node = list_entry(outlp->next, struct rule_node, list);
		readptr = (char*)&node->rule;
		outlp = outlp->next;
	}
	else{
		inlp = &In_lhead;//重置两个指向链表头的指针
		outlp = &Out_lhead;
		return 0;
	}

	//写入用户空间缓冲区
	while(length && (byte_read < sizeof(struct zfw_rule))){
		put_user(readptr[byte_read],&(buffer[byte_read]));//1:内核空间数据,2:用户空间指针
		byte_read++;
		length--;
	}
	return byte_read;
}

//处理用户空间写操作,添加规则和删除规则
static ssize_t zfw_dev_write(struct file *file, const char *buffer, size_t length, loff_t *offset){
	struct zfw_ctl *ctlp;
	int byte_write = 0;

	if(length < sizeof(*ctlp)){
		printk(KERN_ALERT "zFirewall: Receives incomplete instruction\n");
		return byte_write;
	}
	
	while(length && (byte_write < sizeof(*ctlp))) {//从用户空间数据到内核空间缓冲区
		get_user(Buffer[byte_write], buffer + byte_write);
		byte_write++;
		length--;
	}
	ctlp = (struct zfw_ctl *)Buffer;
	switch(ctlp->mode){
		case Z_ADD:
			zfw_rule_add(&ctlp->rule);
			break;
		case Z_REMOVE:
			zfw_rule_del(&ctlp->rule);
			break;
		default:
			printk(KERN_ALERT "zFirewall: Received an unknown command\n");
	}

	return byte_write;
}

//该函数解决打开一个设备文件
static int zfw_dev_open(struct inode *inode, struct file *file){
	if(Device_open)
		return -EBUSY;//EBUSY是errno中的定义为16的错误码，表示被占用而无法进行操作,正忙
	Device_open++;
	if(!try_module_get(THIS_MODULE)){//判断module模块是否处于活动状态,宏:当前模块
		printk(KERN_ALERT "zFirewall: Module is not available\n");
		return -ESRCH;//3指定的进程不存在
	}
	return 0;
}

//该函数释放一个设备文件
static int zfw_dev_release(struct inode *inode, struct file *file){
	module_put(THIS_MODULE);//使指定的模块使用量减一
	Device_open--;
	return 0;
}


//给netfilter配置"入站"hook	nf_hook_ops:存储钩子的数据结构
struct nf_hook_ops zfw_in_hook = {
	.hook = zfw_in_filter,//挂钩上的函数名
	.pf = PF_INET,	//协议簇,IPv4:PF_INET
	.hooknum = NF_INET_PRE_ROUTING, //hook类型 在完整性校验之后,选路确定之前 链路层->传输层
	.priority = NF_IP_PRI_FIRST
};

//给netfilter配置"出站"hook
struct nf_hook_ops zfw_out_hook = {
	.hook = zfw_out_filter,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT, //来自本机进程的数据包在其离开本地主机的过程中
	.priority = NF_IP_PRI_FIRST
};

//给设备文件的文件操作配置
struct file_operations zfw_dev_fop = {
	.read = zfw_dev_read,
	.write = zfw_dev_write,
	.open = zfw_dev_open,
	.release = zfw_dev_release
};//每个成员对应一个系统调用

//防火墙内核模块初始化
//__init是告知编译器，将变量或函数放在一个特殊的区域,__init将函数放在代码段的一个子段".init.text"(初始化代码段)中,
//__initdata将数据放在数据段的子段".init.data"(初始化数据段)中,表明该函数在使用一次后就会被丢掉,将占用的内存释放
static int __init zfw_mod_init(void){
	int ret;

	//初始化静态全局变量
	Device_open = 0;
	Buffer = (char *)kmalloc(sizeof(struct zfw_ctl), GFP_ATOMIC);//分配过程是一个原子过程，过程不会被打断
	//kmalloc与vmalloc分配内核内存,malloc分配用户内存
	if(Buffer == NULL){
		printk(KERN_ALERT "zFirewall:Fails to start due to out of memory\n");//printk:日志级别, KERN_ALERT: action must be taken immediately
		return -1;
	}

	INIT_LIST_HEAD(&In_lhead);
	INIT_LIST_HEAD(&Out_lhead);//该函数需要先定义出链表实体即In_lhead和Out_lhead,然后将其地址传递给初始化函数，完成链表初始化
	
	//注册字符设备(通过把驱动程序以字符设备形式注册到内核，并且自动生成设备节点，使得用户可以访问到我们的驱动
	ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &zfw_dev_fop);
	//arg1:动态申请字符设备的主设备号
	//arg2:代表申请设备的设备名
	//arg3:struct file_operations结构体类型的指针,代表申请设备的操作函数
	if(ret<0){// =0success =-ENOMEM即-12fail
		printk(KERN_ALERT "zFirewall: Fails to start due to device register\n");
		return ret;
	}
	printk(KERN_INFO "zFirewall: Character device %s is registered with major number %d\n",DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);
	printk(KERN_INFO "zFirewall: To communicate to the device, use: mknod %s c %d 0\n", DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);


	//注册钩子
	nf_register_net_hook(&init_net, &zfw_in_hook);
	nf_register_net_hook(&init_net, &zfw_out_hook);
	return 0;
}

//将初始化函数加入到模块中
module_init(zfw_mod_init);

//结束将防火墙模块清除
static void __exit zfw_mod_cleanup(void){

	struct rule_node *nodep;
	struct rule_node *ntmp;

	kfree(Buffer);

	list_for_each_entry_safe(nodep, ntmp,&In_lhead, list) {	//nodep当前指针, ntmp下一个指针
		list_del(&(nodep->list));
		kfree(nodep);
		printk(KERN_INFO "zFirewall: Deleted inbound rule %p\n",nodep);
	}
	

	list_for_each_entry_safe(nodep, ntmp,&Out_lhead, list) {
		list_del(&(nodep->list));
		kfree(nodep);
		printk(KERN_INFO "zFirewall: Deleted outbound rule %p\n",nodep);
	}

	//清除hook和设备文件
	unregister_chrdev(DEVICE_MAJOR_NUM,DEVICE_INTF_NAME);
	printk(KERN_INFO "zFirewall: Device %s is unregistered\n", DEVICE_INTF_NAME);

	nf_unregister_net_hook(&init_net, &zfw_in_hook);
	nf_unregister_net_hook(&init_net, &zfw_out_hook);
}
//将清除函数添加到模块中
module_exit(zfw_mod_cleanup);



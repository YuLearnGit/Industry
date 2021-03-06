/*
 * xt_modbusTcp.c
 *
 *  Created on: 2015年6月15日
 *      Author: zwj, dl
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/in.h>

#include "modbus_decode.h"
#include "general_api.h"

#define  DEBUG

#define REQ_FOR_CONNECTION	1
#define RES_CONNECTION		1
#define ESTABLISHED			1

#define MODBUSTCP_PORT		502

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

static bool
modbusTcp_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{

	unsigned char *p_data;
	__be32 sip, dip;
	__u32 sport,dport;
	__u8 data_src_flag = 0;
	__u16 app_len = 0;//应用层数据长度
	char *data_start = 0;//应用层数据起始位置
	__u16 total_len = 0;

	const struct xt_modbusTcp_mtinfo *info = par->matchinfo;

	if(!skb)
		return false;

	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);
	//判断数据包是否为TCP数据包
	if( !IsTcpPacket(skb))
		return false;

	//判断TCP数据包端口是否为502
	sport = GetSrcPort(skb);
	dport = GetDstPort(skb);
	if(sport != htons(MODBUSTCP_PORT) && dport != htons(MODBUSTCP_PORT))
		return false;

	//这里需要修改，需要实现 判断状态位，如果为请求包以及应答包则直接通过，如果为数据包则需要进行深度包过滤
	//判断TCP数据包状态；
	//如果为PSH被置位，则进行深度包过滤;
	if( !IsTcpFlagPshSet(skb) )
		return true;

	//判断数据是客户端数据还是服务器端数据
	if(sport == htons(MODBUSTCP_PORT))
		data_src_flag = FROM_SERVER_FLAG;
	else if(dport == htons(MODBUSTCP_PORT))
		data_src_flag = FROM_CLIENT_FLAG;
		
		

	//获取应用层数据长度
	app_len = GetAppDataLength(skb);

	//获取应用层起始位置
	data_start = GetAppData(data_start, skb);

	//获取数据总长度
	total_len = (skb->len - skb->data_len);

	#ifdef DEBUG
		printk("\n\n===============start==============\n");


	//打印应用层数据
	printk("app_data_len=%d,total_data_len=%d\n",app_len,total_len);
	printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(sip), NIPQUAD(dip));
	printk("app_data: ");

	for( p_data = data_start; p_data < (skb->tail);p_data++)
	{
		printk("%02x ", (__u8) *p_data);
	}
    #endif

	#ifdef DEBUG
		printk("\n\n");
		printk("*********modbus dpi********\n");
	#endif

	if ( ModbusDecode(data_start, app_len, data_src_flag, info) == MODBUS_FAIL)
	{
		#ifdef DEBUG
			printk("modbus decode: not modbus tcp proto !!! Failed!!! \n");
			printk("================end==============\n");
		#endif

		return false;
	}
    else
    {
		#ifdef DEBUG
    		printk("modbus decode: modbus tcp proto !!! Success!!! \n");
    	    printk("================end==============\n");
		#endif

    	return true;
    }



}

static struct xt_match modbusTcp_mt_reg __read_mostly = {
		.name      = "modbusTcp",
		.revision  = 1,
		.family    = NFPROTO_IPV4,
		.match     = modbusTcp_mt4,
		.matchsize = sizeof(struct xt_modbusTcp_mtinfo),
		.me        = THIS_MODULE,
};

static int __init modbusTcp_mt_init(void)
{
	#ifdef DEBUG
		printk("register match successed\n");
	#endif
	return xt_register_match(&modbusTcp_mt_reg);
}

static void __exit modbusTcp_mt_exit(void)
{
	#ifdef DEBUG
		printk("unregister match successed\n");
	#endif
	xt_unregister_match(&modbusTcp_mt_reg);
}

module_init(modbusTcp_mt_init);
module_exit(modbusTcp_mt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZWJ <zwj9214@163.com>");
MODULE_DESCRIPTION("iptables:modubus tcp detection");
MODULE_ALIAS("ipt_modbusTcp");
MODULE_ALIAS("ip6t_modbusTcp");
